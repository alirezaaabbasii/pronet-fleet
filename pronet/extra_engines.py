"""Additional pinned adapters: authenticated Noise and verified TLS WS/HTTP2."""
from __future__ import annotations

import base64
import pathlib
import re

from .common import PronetError, atomic_write, command, read_json, write_json
from .model import PROFILES


def noise_key(directory, binary):
    path = pathlib.Path(directory) / "noise-key.json"
    saved = read_json(path, {})
    if not saved:
        result = command([binary, "--genkey"])
        private = re.search(r"Private Key:\s*([A-Za-z0-9+/]{43}=)", result.stdout)
        public = re.search(r"Public Key:\s*([A-Za-z0-9+/]{43}=)", result.stdout)
        if not private or not public:
            raise PronetError("Noise key generation did not produce a valid keypair")
        saved = {"private": private.group(1), "public": public.group(1)}
        write_json(path, saved)
    for key in ("private", "public"):
        try:
            if len(base64.b64decode(saved[key], validate=True)) != 32: raise ValueError()
        except (KeyError, ValueError): raise PronetError("Invalid stored Noise key")
    return saved["public"]


def render_extra(plan, directory, binaries):
    from .engines import toml_table
    directory = pathlib.Path(directory)
    engine = PROFILES[plan["profile"]]["engine"]
    iran = plan["role"] == "iran"
    mappings = [(plan["health_port"], plan["bridge_health_port"]), (plan["data_port"], plan["bridge_data_port"])]
    name = "pn-" + plan["pair_id"] + ".invalid"
    if engine == "rathole":
        role = "server" if iran else "client"
        values = {"default_token": plan["token"]}
        if iran:
            values.update(bind_addr=f"{plan['bind_ip']}:{plan['control_port']}", heartbeat_interval=15)
            noise_key(directory, binaries[engine])
            noise = {"local_private_key": read_json(directory / "noise-key.json")["private"]}
        else:
            values.update(remote_addr=f"{plan['iran_ip']}:{plan['control_port']}", heartbeat_timeout=45, retry_interval=3)
            public = plan.get("server_noise_public_key", "")
            if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", public): raise PronetError("Noise server identity missing")
            noise = {"remote_public_key": public}
        text = toml_table(role, values)
        text += toml_table(role + ".transport", {"type": "noise"})
        text += toml_table(role + ".transport.tcp", {"nodelay": True, "keepalive_secs": 20, "keepalive_interval": 8})
        text += toml_table(role + ".transport.noise", dict(pattern="Noise_NK_25519_ChaChaPoly_BLAKE2s", **noise))
        for index, (source, target) in enumerate(mappings):
            key = "bind_addr" if iran else "local_addr"
            value = source if iran else target
            text += toml_table(role + ".services.pn" + str(index), {"type": "tcp", key: f"127.0.0.1:{value}"})
        path = directory / "engine.toml"
        atomic_write(path, text)
        return {"command": [binaries[engine], "--" + role, str(path)], "validate": None, "environment": {"RUST_LOG": "warn"}}
    if engine == "wstunnel":
        binary = binaries[engine]
        if iran:
            policy = directory / "restrictions.yaml"
            text = ('restrictions:\n  - name: "pronet-pair"\n    match:\n      - !PathPrefix "^' + plan["token"] + '$"\n'
                    '    allow:\n      - !ReverseTunnel\n        protocol: [Tcp]\n        port: [' +
                    ', '.join(str(source) for source, _ in mappings) + ']\n        cidr: ["127.0.0.1/32"]\n')
            atomic_write(policy, text)
            args = [binary, "server", "--restrict-config", str(policy), "--tls-certificate", str(directory / "server.crt"),
                    "--tls-private-key", str(directory / "server.key"), f"wss://{plan['bind_ip']}:{plan['control_port']}"]
            environment = {"RUST_LOG": "warn", "TOKIO_WORKER_THREADS": "2"}
        else:
            scheme = "wss" if PROFILES[plan["profile"]]["carrier"] == "websocket" else "https"
            args = [binary, "client", "--tls-verify-certificate", "--tls-sni-override", name,
                    "--connection-retry-max-backoff", "15s", "--reverse-tunnel-connection-retry-max-backoff", "10s"]
            for source, target in mappings:
                args += ["-R", f"tcp://127.0.0.1:{source}:127.0.0.1:{target}"]
            args += [f"{scheme}://{plan['iran_ip']}:{plan['control_port']}"]
            empty_ca = directory / "empty-ca"
            empty_ca.mkdir(exist_ok=True, mode=0o700)
            environment = {"SSL_CERT_FILE": str(directory / "peer.crt"), "SSL_CERT_DIR": str(empty_ca),
                           "WSTUNNEL_HTTP_UPGRADE_PATH_PREFIX": plan["token"], "RUST_LOG": "warn", "TOKIO_WORKER_THREADS": "2"}
        return {"command": args, "validate": None, "environment": environment}
    raise PronetError("No adapter for engine")
