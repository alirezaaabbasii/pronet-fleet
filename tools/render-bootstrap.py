"""Render the small, verified bootstrap and immutable installer snapshots."""
import hashlib
from pathlib import Path
import re

repo=Path(__file__).resolve().parents[1]
installer=(repo/'get.sh').read_bytes()
version=re.search(rb'^VERSION="([^"]+)"',installer,re.M).group(1).decode()
digest=hashlib.sha256(installer).hexdigest()
shared=(repo/'tools/download.sh').read_text()
bootstrap='''#!/usr/bin/env bash
# The group must parse in full before a streamed bootstrap executes.
{
set -euo pipefail
umask 077
OWNER_REPO="alirezaaabbasii/pronet-fleet"
REPO_REF="main"
VERSION="VERSION_VALUE"
INSTALLER_SHA256="DIGEST_VALUE"
say() { printf '[pronet] %s\\n' "$*"; }
fail() { printf '[pronet] error: %s\\n' "$*" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || fail 'curl is required.'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum (coreutils) is required.'
# BEGIN VERIFIED DOWNLOAD FUNCTIONS
'''.replace('VERSION_VALUE',version).replace('DIGEST_VALUE',digest)+shared+'''# END VERIFIED DOWNLOAD FUNCTIONS
DOWNLOAD_PREFERRED_SOURCE=${PRONET_PREFERRED_SOURCE:-cdn}
bootstrap_work=$(mktemp -d "${TMPDIR:-/tmp}/pronet-bootstrap.XXXXXX")
trap 'rm -rf "$bootstrap_work"' EXIT
repo_fetch "installers/${VERSION}/get.sh" "$INSTALLER_SHA256" "$bootstrap_work/get.sh"
export PRONET_PREFERRED_SOURCE="$DOWNLOAD_PREFERRED_SOURCE"
bash "$bootstrap_work/get.sh" "$@"
}
'''
(repo/'install.sh').write_text(bootstrap)
archive=repo/'installers'/version
archive.mkdir(parents=True,exist_ok=True)
(archive/'install.sh').write_text(bootstrap)
(archive/'get.sh').write_bytes(installer)
(archive/'iran-apt-mirrors.py').write_bytes((repo/'tools/iran-apt-mirrors.py').read_bytes())
print('Bootstrap rendered for',version,'installer SHA256',digest)
