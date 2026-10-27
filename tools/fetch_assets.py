#!/usr/bin/env python3
"""Fetch only pinned, checksum-locked official archives; execute nothing."""
import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import ssl
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=["amd64", "arm64"], required=True)
    args = parser.parse_args()
    manifest = json.loads((ROOT / "assets.lock.json").read_text())
    destination = ROOT / "vendor"
    destination.mkdir(exist_ok=True)
    context = ssl.create_default_context()
    def fetch(item):
        name, row = item
        asset = row["assets"][args.arch]
        path = destination / asset["name"]
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == asset["sha256"]:
            return name + ": verified existing archive"
        request = urllib.request.Request(asset["url"], headers={"User-Agent": "Pronet-offline-bundle"})
        with urllib.request.urlopen(request, context=context, timeout=45) as reply:
            raw = reply.read(100 * 1024 * 1024 + 1)
        if len(raw) > 100 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != asset["sha256"]:
            raise ValueError("Archive failed pinned checksum: " + name)
        temporary = path.with_suffix(path.suffix + ".partial")
        temporary.write_bytes(raw)
        temporary.replace(path)
        return name + ": downloaded and verified"
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        for result in pool.map(fetch, manifest.items()): print(result, flush=True)


if __name__ == "__main__":
    main()
