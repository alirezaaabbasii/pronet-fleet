#!/usr/bin/env bash
# Pronet Fleet installer and launcher.
#
#   Iran server:     curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh | sudo bash
#   Foreign server:  the exact command printed by the Iran server, e.g.
#                    curl -fsSL .../get.sh | sudo bash -s -- join PNF1-...
#
# Downloads the pinned release, verifies its SHA256 BEFORE installing, installs
# or upgrades it, then runs `pronet` with the given arguments (menu if none).
# Existing tunnels, routes, firewall policy and panel configuration are untouched.
#
# Optional:
#   PRONET_ZIP=/root/pronet-fleet-0.3.9.zip   use a file already copied to the server
#   PRONET_URL=https://mirror/...zip          use a mirror if GitHub is slow/blocked
#   PRONET_NO_MENU=1                          install only
set -euo pipefail

VERSION="0.3.9"
OWNER_REPO="alirezaaabbasii/pronet-fleet"
SHA256="2ad3088506171abb0926cebbf2221838aac882516262e6c154fd7973f954f1e5"
URL="${PRONET_URL:-https://raw.githubusercontent.com/${OWNER_REPO}/main/dist/pronet-fleet-${VERSION}.zip}"

say()  { printf '\033[1;36m[pronet]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[pronet] error:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run as root:  curl -fsSL ... | sudo bash"
[ "$(uname -s)" = "Linux" ] || fail "Linux is required."
case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) fail "unsupported CPU $(uname -m) (amd64/arm64 only)." ;; esac
[ -d /run/systemd/system ] || fail "systemd is required."

run_pronet() {
  [ -n "${PRONET_NO_MENU:-}" ] && [ "$#" -eq 0 ] && return 0
  if (exec </dev/tty) 2>/dev/null; then
    # stdin is the piped script; give prompts the real terminal.
    exec /usr/local/bin/pronet "$@" < /dev/tty
  fi
  exec /usr/local/bin/pronet "$@"
}

installed="$(/usr/local/bin/pronet --version 2>/dev/null || true)"
if [ "$installed" = "$VERSION" ] && [ -z "${PRONET_ZIP:-}" ]; then
  say "Pronet Fleet $VERSION is already installed."
  run_pronet "$@"
  exit 0
fi

need=""
for pair in python3:python3 unzip:unzip ip:iproute2 ss:iproute2 iptables:iptables openssl:openssl ssh-keygen:openssh-client nft:nftables sha256sum:coreutils curl:curl; do
  cmd="${pair%%:*}"; pkg="${pair##*:}"
  command -v "$cmd" >/dev/null 2>&1 || case " $need " in *" $pkg "*) ;; *) need="$need $pkg" ;; esac
done
if [ -n "$need" ]; then
  command -v apt-get >/dev/null 2>&1 || fail "missing tools:$need"
  say "Installing prerequisites:$need"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $need >/dev/null
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || fail "Python 3.10+ is required."

work="$(mktemp -d /tmp/pronet-get.XXXXXX)"
trap 'rm -rf "$work"' EXIT
zip="$work/pronet-fleet-${VERSION}.zip"

if [ -n "${PRONET_ZIP:-}" ]; then
  [ -f "$PRONET_ZIP" ] || fail "file not found: $PRONET_ZIP"
  cp "$PRONET_ZIP" "$zip"
else
  say "Downloading Pronet Fleet $VERSION ..."
  curl -fL --retry 5 --retry-delay 3 --connect-timeout 15 -o "$zip" "$URL" \
    || fail "download failed. If GitHub is blocked here, copy the zip with scp and run: PRONET_ZIP=/path/file.zip bash get.sh"
fi

say "Verifying SHA256 ..."
echo "${SHA256}  ${zip}" | sha256sum -c --status || fail "checksum mismatch: the file is damaged or modified. Nothing was installed."

unzip -q "$zip" -d "$work"
src="$work/pronet-fleet-${VERSION}"
[ -f "$src/install.sh" ] || fail "unexpected package layout."
sh "$src/install.sh" --verify-only >/dev/null

if ls /etc/systemd/system/pronetf-*.service >/dev/null 2>&1; then
  say "Upgrading the existing installation (running tunnels are kept) ..."
  sh "$src/install.sh" --activate-services >/dev/null
  say "Upgraded to $VERSION."
else
  sh "$src/install.sh" >/dev/null
  say "Installed Pronet Fleet $VERSION."
fi

# Keep installed versions: running helpers and pinned engine plans can still
# depend on their code or binaries even after unit references are migrated.
# Removing an unreferenced-by-unit directory here can break a later reconnect.

run_pronet "$@"
