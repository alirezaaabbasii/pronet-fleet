#!/bin/sh
set -eu
pronet_bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$pronet_bundle_dir/install.py" "$@"
