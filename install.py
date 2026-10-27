#!/usr/bin/env python3
"""Offline, versioned installer. Does not configure or alter existing tunnels."""
import argparse
import hashlib
import os
import pathlib
import platform
import shutil
import sys

SOURCE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))
from pronet import __version__
from pronet.common import PronetError, atomic_write, read_json


def verify():
    manifest = read_json(SOURCE / "SHA256-MANIFEST.json")
    for name, expected in manifest.items():
        path = SOURCE / name
        if (path.is_symlink() or not path.resolve().is_relative_to(SOURCE) or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            raise PronetError("Package checksum mismatch: " + name)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--activate-services", action="store_true", help="Validate and update owned service references to this management version")
    args = parser.parse_args()
    manifest = verify()
    if args.verify_only:
        print("Package checksums verified:", len(manifest), "files")
        return
    if platform.system() != "Linux" or os.geteuid() != 0 or sys.version_info < (3, 10):
        raise PronetError("Requires Linux, root and Python 3.10+; run sudo python3 install.py")
    if platform.machine() not in ("x86_64", "aarch64", "arm64"):
        raise PronetError("Supported architectures: amd64, arm64")
    destination = pathlib.Path("/opt/pronet-fleet") / __version__
    if destination.is_symlink():
        raise PronetError("Installation path is a symlink")
    destination.mkdir(parents=True, exist_ok=True, mode=0o755)
    # A root shell may use umask 077. Code must remain readable/traversable by
    # the unprivileged hub; credentials are stored separately under /etc.
    destination.parent.chmod(0o755)
    destination.chmod(0o755)
    wrapper = pathlib.Path("/usr/local/bin/pronet")
    marker = "#!/bin/sh\n# Managed by Pronet Fleet\n"
    if wrapper.exists() and (wrapper.is_symlink() or not wrapper.read_text().startswith(marker)):
        raise PronetError("/usr/local/bin/pronet already belongs to another installation")
    previous_wrapper = wrapper.read_bytes() if wrapper.exists() else None
    for name in manifest:
        if not (name.startswith(("pronet/", "vendor/", "licenses/", "sources/")) or name in ("main.py", "assets.lock.json", "engine-catalog.json", "OPERATOR.fa.md", "README.md", "SUPPORT.md", "NOTICE.md")):
            continue
        target = destination / name
        if target.exists() and target.read_bytes() != (SOURCE / name).read_bytes():
            raise PronetError("Existing version was locally modified; refusing to overwrite: " + name)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        parent = target.parent
        while parent != destination:
            if parent.is_symlink(): raise PronetError("Refusing installation directory symlink")
            parent.chmod(0o755)
            parent = parent.parent
        if target.is_symlink():
            raise PronetError("Refusing installation symlink")
        atomic_write(target, (SOURCE / name).read_bytes(), 0o644)
    for directory in (pathlib.Path("/etc/pronet-fleet"), pathlib.Path("/var/lib/pronet-fleet")):
        if directory.is_symlink():
            raise PronetError("State directory is a symlink")
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = marker + 'exec /usr/bin/python3 "' + str(destination / "main.py") + '" "$@"\n'
    atomic_write(wrapper, body, 0o755)
    if args.activate_services:
        from pronet.upgrades import activate
        import json
        try:
            print(json.dumps(activate(destination / "main.py", previous_wrapper, wrapper), indent=2))
        except BaseException:
            if previous_wrapper: atomic_write(wrapper, previous_wrapper, 0o755)
            raise
    elif previous_wrapper and previous_wrapper != body.encode() and any(pathlib.Path('/etc/systemd/system').glob('pronetf-*.service')):
        atomic_write(wrapper, previous_wrapper, 0o755)
        print("New version staged. Activate owned service references with: sudo sh install.sh --activate-services")
    print("Pronet Fleet", __version__, "installed. Run: sudo pronet")
    print("No existing tunnel, default route, firewall policy or panel configuration was changed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, PronetError) as error:
        print("Pronet installer:", error, file=sys.stderr)
        sys.exit(1)
