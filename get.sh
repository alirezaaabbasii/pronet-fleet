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
#   PRONET_ZIP=/root/pronet-fleet-0.3.22.zip   use a file already copied to the server
#   PRONET_URL=https://mirror/...zip          use a mirror if GitHub is slow/blocked
#   PRONET_NO_MENU=1                          install only
#   bash get.sh --iran-mirrors               temporary Ubuntu mirror test for Iran installation
set -euo pipefail

VERSION="0.3.22"
OWNER_REPO="alirezaaabbasii/pronet-fleet"
SHA256="a65941cb76cc5cf865b324b94cf3ade9af52cbb16aee4aeb0473603e8ad66aa3"
BASE_VERSION="0.3.12"
BASE_SHA256="3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37"
UPDATE_SHA256="c27aba51c4d88b64234dc51cf7837c9c11b1b5e7025689c80c73cbaee6cf04b0"
BASE_URL="https://raw.githubusercontent.com/${OWNER_REPO}/main/dist/pronet-fleet-${BASE_VERSION}.zip"
UPDATE_URL="https://raw.githubusercontent.com/${OWNER_REPO}/main/dist/pronet-fleet-${VERSION}-update.zip"

say()  { printf '\033[1;36m[pronet]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[pronet] error:\033[0m %s\n' "$*" >&2; exit 1; }

iran_mirrors=0
if [ "${1:-}" = "--iran-mirrors" ]; then
  iran_mirrors=1
  shift
  [ "${1:-}" != "join" ] || fail "--iran-mirrors is for Iran installation; run the foreign join command without it."
fi

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

if [ "$iran_mirrors" -eq 0 ] && [ "${1:-}" != "join" ] && [ "${PRONET_NO_MENU:-}" != "1" ]; then
  foreign_node=0
  if [ -f /etc/pronet-fleet/node.json ] && command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import json,sys; sys.exit(0 if json.load(open("/etc/pronet-fleet/node.json")).get("role")=="foreign" else 1)' 2>/dev/null; then
      foreign_node=1
    fi
  fi
  if [ "$foreign_node" -eq 0 ] && (exec </dev/tty) 2>/dev/null; then
    printf '\n  IRAN INSTALLATION - UBUNTU MIRRORS\n'
    printf '  On an Iran server, test mirrors to speed up prerequisite downloads?\n'
    printf '   1) Yes - test mirrors temporarily and suggest DNS (no DNS change)\n'
    printf '   2) No - use the current server mirror\n'
    printf '  Original APT sources and DNS are kept; temporary mirror files are removed.\n'
    while true; do
      printf 'Select [2]: '
      IFS= read -r mirror_choice </dev/tty || mirror_choice=2
      case "${mirror_choice:-2}" in
        1) iran_mirrors=1; break ;;
        2) break ;;
        *) printf 'Choose 1 or 2.\n' ;;
      esac
    done
  fi
fi

need=""
for pair in python3:python3 unzip:unzip ip:iproute2 ss:iproute2 iptables:iptables openssl:openssl ssh-keygen:openssh-client nft:nftables sha256sum:coreutils curl:curl wg:wireguard-tools gpgv:gpgv; do
  cmd="${pair%%:*}"; pkg="${pair##*:}"
  command -v "$cmd" >/dev/null 2>&1 || case " $need " in *" $pkg "*) ;; *) need="$need $pkg" ;; esac
done
if [ "$iran_mirrors" -eq 1 ]; then
  mirror_work="$(mktemp -d /tmp/pronet-apt.XXXXXX)"
  trap 'rm -rf "$mirror_work"' EXIT
  bootstrap_need=""
  for pair in python3:python3 curl:curl sha256sum:coreutils gpgv:gpgv; do
    command -v "${pair%%:*}" >/dev/null 2>&1 || bootstrap_need="$bootstrap_need ${pair##*:}"
  done
  if [ -n "$bootstrap_need" ]; then
    command -v apt-get >/dev/null 2>&1 || fail "APT is required to prepare the mirror tester."
    # The signed APT path itself can bootstrap the optional Python tester.
    # Only this private Ubuntu source file is used; live sources stay intact.
    . /etc/os-release
    [ "${ID:-}" = "ubuntu" ] || fail "Iran mirror testing needs Ubuntu."
    [ -f /usr/share/keyrings/ubuntu-archive-keyring.gpg ] || fail "Ubuntu archive keyring is missing."
    case "${VERSION_CODENAME:-}" in ""|*[!a-z]*) fail "Unknown Ubuntu release." ;; esac
    boot="$mirror_work/bootstrap"
    mkdir -p "$boot/parts" "$boot/lists/partial" "$boot/archives/partial"
    boot_apt=(apt-get -o "Dir::Etc::sourcelist=$boot/sources.list"
              -o "Dir::Etc::sourceparts=$boot/parts" -o "Dir::State::lists=$boot/lists"
              -o "Dir::Cache::archives=$boot/archives" -o Acquire::Retries=0
              -o Acquire::http::Timeout=8 -o Acquire::https::Timeout=8)
    case "$(dpkg --print-architecture)" in
      amd64) bootstrap_mirrors="https://ubuntu.pishgaman.net/ubuntu https://archive.ubuntu.com/ubuntu https://mirror.leaseweb.com/ubuntu https://ftp.fau.de/ubuntu" ;;
      arm64) bootstrap_mirrors="https://ports.ubuntu.com/ubuntu-ports" ;;
      *) fail "Unsupported Ubuntu architecture." ;;
    esac
    bootstrap_ok=0
    for mirror in $bootstrap_mirrors; do
      say "Preparing mirror tester with authenticated Ubuntu packages: $mirror"
      printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s %s main universe\n' "$mirror" "$VERSION_CODENAME" > "$boot/sources.list"
      printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s %s-updates main universe\n' "$mirror" "$VERSION_CODENAME" >> "$boot/sources.list"
      printf 'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] %s %s-security main universe\n' "$mirror" "$VERSION_CODENAME" >> "$boot/sources.list"
      # APT keeps its normal signature checks; never use trusted=yes.
      # shellcheck disable=SC2086
      if "${boot_apt[@]}" -o APT::Update::Error-Mode=any update -qq &&
         DEBIAN_FRONTEND=noninteractive "${boot_apt[@]}" --download-only -y -qq install $bootstrap_need; then
        # shellcheck disable=SC2086
        DEBIAN_FRONTEND=noninteractive "${boot_apt[@]}" --no-download -y -qq install $bootstrap_need
        bootstrap_ok=1
        break
      fi
    done
    [ "$bootstrap_ok" -eq 1 ] || fail "Could not prepare mirror tester; original APT sources are unchanged."
  fi
  mirror_tool="$mirror_work/iran-apt-mirrors.py"
  curl -fsSL --connect-timeout 5 --max-time 30 \
    "https://raw.githubusercontent.com/${OWNER_REPO}/main/tools/iran-apt-mirrors.py" -o "$mirror_tool"
  echo "675fef7103573865c03d3eef6fd791f19ed40f1108b9dc2471639d8ea5675e7f  $mirror_tool" | sha256sum -c --status \
    || fail "mirror selector checksum mismatch; nothing was changed."
fi
if [ -z "$need" ] && [ "$iran_mirrors" -eq 1 ]; then
  say "Prerequisites are already installed; checking DNS only, without changing system settings."
  python3 "$mirror_tool" --directory "$mirror_work/apt" --dns-only
  rm -rf "$mirror_work"
  trap - EXIT
fi
if [ -n "$need" ]; then
  command -v apt-get >/dev/null 2>&1 || fail "missing tools:$need"
  apt_command=(apt-get)
  if [ "$iran_mirrors" -eq 1 ]; then
    # Package names come only from the fixed prerequisite list above.
    # shellcheck disable=SC2086
    python3 "$mirror_tool" --directory "$mirror_work/apt" --packages $need
    apt_command=(apt-get -o "Dir::Etc::sourcelist=$mirror_work/apt/sources.list"
                 -o "Dir::Etc::sourceparts=$mirror_work/apt/sources.list.d"
                 -o "Dir::State::lists=$mirror_work/apt/lists"
                 -o "Dir::Cache::archives=$mirror_work/apt/archives")
  else
    say "Updating prerequisite package indexes using the current mirror ..."
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
  fi
  say "Installing prerequisites:$need"
  # shellcheck disable=SC2086
  DEBIAN_FRONTEND=noninteractive "${apt_command[@]}" install -y -qq $need >/dev/null
  if [ "$iran_mirrors" -eq 1 ]; then
    rm -rf "$mirror_work"
    trap - EXIT
    say "Temporary mirror settings, indexes and downloads removed; original APT sources are unchanged."
  fi
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || fail "Python 3.10+ is required."

work="$(mktemp -d /tmp/pronet-get.XXXXXX)"
trap 'rm -rf "$work"' EXIT
zip="$work/pronet-fleet-${VERSION}.zip"

src="$work/pronet-fleet-${VERSION}"
fetch() {
  curl -fL --retry 5 --retry-delay 3 --connect-timeout 15 -o "$2" "$1" \
    || fail "download failed. Copy the complete release ZIP and use PRONET_ZIP=/path/file.zip bash get.sh"
}
verify_zip() {
  echo "$1  $2" | sha256sum -c --status || fail "checksum mismatch: nothing was installed."
}
if [ -n "${PRONET_ZIP:-}" ] || [ -n "${PRONET_URL:-}" ]; then
  if [ -n "${PRONET_ZIP:-}" ]; then
    [ -f "$PRONET_ZIP" ] || fail "file not found: $PRONET_ZIP"
    cp "$PRONET_ZIP" "$zip"
  else
    say "Downloading complete Pronet Fleet $VERSION ..."
    fetch "$PRONET_URL" "$zip"
  fi
  verify_zip "$SHA256" "$zip"
  unzip -q "$zip" -d "$work"
else
  # Reuse the immutable engine bundle instead of adding 70 MB of identical
  # binaries to Git history for every source-only update. Both ZIPs are pinned.
  say "Downloading verified engine bundle and Pronet Fleet $VERSION update ..."
  base_zip="$work/base.zip"
  update_zip="$work/update.zip"
  fetch "$BASE_URL" "$base_zip"
  verify_zip "$BASE_SHA256" "$base_zip"
  fetch "$UPDATE_URL" "$update_zip"
  verify_zip "$UPDATE_SHA256" "$update_zip"
  unzip -q "$base_zip" -d "$work"
  mv "$work/pronet-fleet-${BASE_VERSION}" "$src"
  unzip -oq "$update_zip" -d "$work"
  # Additional independent engines are mirrored under their original digest.
  # Keep every download on the same raw host as this installer: some routes
  # allow raw.githubusercontent.com but cannot reach github.com Releases.
  # Fetch both architectures to preserve the complete offline bundle manifest.
  python3 - "$src" > "$work/extra-assets.tsv" <<'PY'
import json,pathlib,sys
bundle=pathlib.Path(sys.argv[1])
locked=json.loads((bundle/'assets.lock.json').read_text())
for engine in ('paqet','backhaul','parsa-spoof'):
    for asset in locked[engine]['assets'].values():
        print(asset['name'],asset['sha256'],sep='\t')
PY
  while IFS="$(printf '\t')" read -r asset_name asset_sha; do
    say "Downloading verified engine: $asset_name"
    fetch "https://raw.githubusercontent.com/${OWNER_REPO}/main/dist/engines/${asset_sha}/${asset_name}" "$src/vendor/$asset_name"
    verify_zip "$asset_sha" "$src/vendor/$asset_name"
  done < "$work/extra-assets.tsv"
fi

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
