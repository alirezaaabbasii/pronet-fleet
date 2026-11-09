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
#   PRONET_ZIP=/root/pronet-fleet-0.3.26.zip   use a file already copied to the server
#   PRONET_URL=https://mirror/...zip          use a mirror if GitHub is slow/blocked
#   PRONET_NO_MENU=1                          install only
#   bash get.sh --iran-mirrors               temporary Ubuntu mirror test for Iran installation
set -euo pipefail
umask 077

VERSION="0.3.26"
OWNER_REPO="alirezaaabbasii/pronet-fleet"
REPO_REF="main"
SHA256="563b8f1eeca91fe3ff3592733fbbc16f8579c5925cbd36792ecaffe22810db3e"
BASE_VERSION="0.3.12"
BASE_SHA256="3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37"
UPDATE_SHA256="395942e480da8c8b5b30838625cef5f4f602e725b7a621067074f11aa1b07090"
BASE_URL="https://raw.githubusercontent.com/${OWNER_REPO}/main/dist/pronet-fleet-${BASE_VERSION}.zip"
UPDATE_URL="https://raw.githubusercontent.com/${OWNER_REPO}/main/dist/pronet-fleet-${VERSION}-update.zip"

say()  { printf '\033[1;36m[pronet]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[pronet] error:\033[0m %s\n' "$*" >&2; exit 1; }

# BEGIN VERIFIED DOWNLOAD FUNCTIONS
# Embedded verbatim in install.sh and get.sh; no helper download is required.
DOWNLOAD_CONNECT_TIMEOUT=${DOWNLOAD_CONNECT_TIMEOUT:-7}
DOWNLOAD_IDLE_SECONDS=${DOWNLOAD_IDLE_SECONDS:-20}
DOWNLOAD_MAX_SECONDS=${DOWNLOAD_MAX_SECONDS:-600}
DOWNLOAD_PREFERRED_SOURCE=${PRONET_PREFERRED_SOURCE:-}

# A successful HTTP response is insufficient: only the expected digest is accepted.
download_attempt() {
  local expected="$1" destination="$2" url="$3" label="$4"
  local partial="${destination}.part"
  say "Downloading via $label ..."
  rm -f -- "$partial"
  if curl -fL --connect-timeout "$DOWNLOAD_CONNECT_TIMEOUT" \
      --speed-limit 1024 --speed-time "$DOWNLOAD_IDLE_SECONDS" \
      --max-time "$DOWNLOAD_MAX_SECONDS" \
      -H 'Accept: application/vnd.github.raw+json' -o "$partial" "$url"; then
    if printf '%s  %s\n' "$expected" "$partial" | sha256sum -c >/dev/null 2>&1; then
      if mv -f -- "$partial" "$destination"; then return 0; fi
      rm -f -- "$partial"
      return 1
    fi
    say "Checksum mismatch from $label; trying another source."
  fi
  rm -f -- "$partial"
  return 1
}

repo_fetch() {
  local path="$1" expected="$2" destination="$3" upstream="${4:-}" size="${5:-small}"
  local source url tried=" "
  for source in "$DOWNLOAD_PREFERRED_SOURCE" raw upstream cdn api; do
    [ -n "$source" ] || continue
    case "$tried" in *" $source "*) continue ;; esac
    tried="$tried$source "
    case "$source" in
      raw) url="https://raw.githubusercontent.com/${OWNER_REPO}/${REPO_REF}/${path}" ;;
      upstream) [ -n "$upstream" ] || continue; url="$upstream" ;;
      cdn) [ "$size" != large ] || continue
           url="https://cdn.jsdelivr.net/gh/${OWNER_REPO}@${REPO_REF}/${path}" ;;
      api) [ "$size" != part ] || continue
           url="https://api.github.com/repos/${OWNER_REPO}/contents/${path}?ref=${REPO_REF}" ;;
      *) continue ;;
    esac
    if download_attempt "$expected" "$destination" "$url" "$source"; then
      DOWNLOAD_PREFERRED_SOURCE="$source"
      return 0
    fi
  done
  printf '%s\n' "All download sources failed (network error or checksum mismatch). Use the complete offline ZIP with PRONET_ZIP=/path/file.zip." >&2
  return 1
}

# Each part is separately pinned; the concatenated archive is checked again.
repo_fetch_parts() {
  local expected="$1" destination="$2"
  shift 2
  local directory spec path digest part assembled
  directory=$(mktemp -d "${destination}.chunks.XXXXXX") || return 1
  part="$directory/part"
  assembled="$directory/assembled"
  : > "$assembled" || { rm -rf -- "$directory"; return 1; }
  for spec in "$@"; do
    path="${spec%:*}"; digest="${spec##*:}"
    if ! repo_fetch "$path" "$digest" "$part" "" part; then
      rm -rf -- "$directory"
      return 1
    fi
    cat "$part" >> "$assembled" || { rm -rf -- "$directory"; return 1; }
  done
  if ! printf '%s  %s\n' "$expected" "$assembled" | sha256sum -c >/dev/null 2>&1; then
    say 'Assembled archive checksum mismatch; nothing was installed.'
    rm -rf -- "$directory"
    return 1
  fi
  if ! mv -f -- "$assembled" "$destination"; then
    rm -rf -- "$directory"
    return 1
  fi
  rm -rf -- "$directory"
}

repo_fetch_archive() {
  local path="$1" expected="$2" destination="$3"
  shift 3
  if download_attempt "$expected" "$destination" \
      "https://raw.githubusercontent.com/${OWNER_REPO}/${REPO_REF}/${path}" raw; then
    DOWNLOAD_PREFERRED_SOURCE=raw
    return 0
  fi
  say 'Trying the verified small-part archive mirror ...'
  DOWNLOAD_PREFERRED_SOURCE=cdn
  if repo_fetch_parts "$expected" "$destination" "$@"; then
    return 0
  fi
  if download_attempt "$expected" "$destination" \
      "https://api.github.com/repos/${OWNER_REPO}/contents/${path}?ref=${REPO_REF}" api; then
    DOWNLOAD_PREFERRED_SOURCE=api
    return 0
  fi
  fail 'Archive download failed on every source. Use the complete offline ZIP.'
}
# END VERIFIED DOWNLOAD FUNCTIONS

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
  repo_fetch "installers/${VERSION}/iran-apt-mirrors.py" \
    675fef7103573865c03d3eef6fd791f19ed40f1108b9dc2471639d8ea5675e7f "$mirror_tool"
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
verify_zip() {
  echo "$1  $2" | sha256sum -c --status || fail "checksum mismatch: nothing was installed."
}
if [ -n "${PRONET_ZIP:-}" ] || [ -n "${PRONET_URL:-}" ]; then
  if [ -n "${PRONET_ZIP:-}" ]; then
    [ -f "$PRONET_ZIP" ] || fail "file not found: $PRONET_ZIP"
    cp "$PRONET_ZIP" "$zip"
  else
    say "Downloading complete Pronet Fleet $VERSION ..."
    download_attempt "$SHA256" "$zip" "$PRONET_URL" custom \
      || fail "Custom download failed or checksum mismatch."
  fi
  verify_zip "$SHA256" "$zip"
  unzip -q "$zip" -d "$work"
else
  # Reuse the immutable engine bundle instead of adding 70 MB of identical
  # binaries to Git history for every source-only update. Both ZIPs are pinned.
  say "Downloading verified engine bundle and Pronet Fleet $VERSION update ..."
  base_zip="$work/base.zip"
  update_zip="$work/update.zip"
  repo_fetch_archive "dist/pronet-fleet-${BASE_VERSION}.zip" "$BASE_SHA256" "$base_zip" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-000:24dfc32d23e14e9e481f36f74352f48378b38b18583ac7f771154233ccf61f10" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-001:6a9b6ec7c1cd59ba408e6bfb7c2b51cb647276d400a79376192c5eebee9efe08" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-002:08f646bf43b9ac5879985a1e384f9d5beeca45739c4eb8e1ee23220d8ca2824c" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-003:44ebc6f501a5c687c3274e14f81168486a1dbddb47eca108857b5e1948b1ceac" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-004:ac46cafd2602b7bc02eaa90f58c8797ea016657df88326337338f17489cc363d" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-005:58a4b4c56fc6efb5916d98e770599fd0e237ffa4b98c176caa1e394721311ad5" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-006:94a7b09aa37bc6e4e1f805df0fe0c4a1beccfbb10edc3312579f95148007da2a" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-007:43f76056648a1d0b903bb10a780a3d03482ffb6a7a5b9d7c9a774a917b7e7977" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-008:46d7afdd82192dd2985937fbb00f9b61f4f9129fefb17dea1568b841c052213d" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-009:eae0b4bb59a2ece50ef106611d2b693ef4ffb73992f00e5032ddacffaff5b57c" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-010:baaf05930c8c414f3b3ea67d7882286b95df444f4369161ee9b57c0f091acd59" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-011:ff71a79e5cd1098b47469adafea780b5fc2173b91d852910ab459928bc1807af" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-012:0541948aafe9cb3dffe681018aef67de2c75d8a594de52d808bcbe8dc3104c11" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-013:43acab86e9e32d0eeb3ca8675eab356eb80a4bf28c4af987d2717d8be85c0904" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-014:eac9e321bb1dbe4fa69f7ecd40dd25a152edf13c2675a2457ddd0c096bfaa0ee" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-015:b886b1579830b7f3a6856786100783a4d7bfa95ef8caf3fe37736fb908875f42" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-016:8b4ce709f4bd455b9522c6d09fbad4c34142ba3c86b8fea2514457bb3dc7bb5a" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-017:7154b09fc6be39451e1d07d414592af35e9a01f29fc1ef696dab6b66542bf4e0" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-018:75eb52fdfe8b3df04754235a8df8845654d7437a86dc064675b955d2e8ef816e" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-019:626a97016c3652ecc161592ce8b75952ea1028cf546793383f1bf327f29d53c1" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-020:d126bcb6330fae44fdd3308ddf63b80977085e2f615501354be6423ec9be2a91" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-021:f3916aec60b42d36d5bb82ebcf053bb9901d23bde6962e824eeb2a42ea280eac" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-022:d54164dac12ba1135f4fb035254f684e9e0fbf6ca0a9e43ce9c0344675c01ec8" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-023:c8aa15ca7190b771115e977afdb84b0eec60bcfbeac9eafb96aacbe2492e4c5d" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-024:044fde2d11a9d95e0ea3af11a892f716369a3e9f351ef3bea1788e5be9342ea6" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-025:e71000ca56c84a077a717f3073e4bd7339474674e7b8c0e3547e967c5d3fb845" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-026:9712b4e775140e16ef0279413c066dee4efa3083850dcf29cde1228dcafeb6e2" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-027:8508ccc1d224b6ae30a364749f29a9f887eb0e16e0fe0fba072eb8c1011de9a9" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-028:41bbee9af95a87181b9048733d319f2b1d78798394099394d0f3b242fae4a1ea" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-029:ce276ac80d8a1285331757e3baee24ca85194c548b80ac5f3abafcc43637f46f" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-030:c43ddb33af4364f8252d640111af05d2f475aacd5217f865a8e5f6f180b1e47e" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-031:4b527327f0519ea1f04b0adc673863d9acfcb94529c17af96ce61c065a135c14" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-032:86f8ab6bc57299ec338f958e0891317e864a13244eab5afd3b184434bd82f2ff" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-033:a5ccd558c5ae5443a7073c41cc5c1539e4fd5eb53968a13298662d1075f8f225" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-034:c82689ebadc6b188d4f2a3ec4da451759c0b391e90ca92babb9922fb5ac092ce" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-035:3e2960cd791ca7352294e67d98e48c60329a0ad76c2ff1098b3aa938628f3ff1" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-036:7eb5a27c39102718f0c9caca62db44261d1ce0854409d36f16dd1d9f8f330908" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-037:c7543753db714182029f4d3eeaa5b247f6fe524b24bb63ae0d2b3eae09440eab" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-038:ef7aa644ad9c157a9226ff0394dd492fa16aab1411c44da0a14e3d5e1a5eed95" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-039:2fa3de8de168eb4b079886fd8d58848891bce87079a9004368bca77afd9cd965" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-040:38a9ae1922623e79f7b8366287245ac83489c010f5b7c6cf6c3e5c4c07b0f927" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-041:1506838b101bc13b82ff0b297497daa2775dbe5fd2d596ebb679edeaabde124f" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-042:913ec9e9ba1469f77cb79a961bb04a0e0beb7a6c122d421f0d819465c15a57fc" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-043:d0e1c4f45206a551a8fa711c9ff4b3f1195d5a2a898771aaf56430c4a5e3f53d" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-044:d999dbfd0695889143117cfffb618a0fcccb01be15f3dbad623cc316354be264" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-045:f7684cbe57ef2a2112ece8a86059e77c509605541cfa5318639a294bc8b63f99" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-046:664bdae1f1549ac35d1b9f1c217db6ce6abe7982a1bcbb517529f0a178e5ec2c" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-047:1623f78f0f609329978e25d8bc104f7e1a7cc254e52af40c8a5c34d475eeb63e" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-048:3b0cec53f0bff47d9ba674bcdd6e0443f29e60fae036a49ad9ad435ae48ce127" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-049:cb8c5f4cfe38e64a44aead86f1fac423761410a843e58cb2a317a9959a4a596f" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-050:22a69e4f89cb677b1437cb5d645cc0930153424dccc2db8b057f65077a67a236" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-051:a017cbe44a79dc6698021b571b0464a95b241945cd56b7d42fc78ef27083b829" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-052:91536be1dfb5593752db56c2cbd662d1ca29926a93e9d4b1425148bf58702e39" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-053:74af64648681ce76e1625d7ba6352341510d6532f237b1d30ea8ffc73b3d21f5" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-054:ada5d1b3e2d410abceec7d4c31e3d5b9ec6636e7121cb88379722b9887ab5fb4" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-055:cb27a2fe24aee4d633ec61faa145ac4a855fb797cedb2dda6a226aea9c209617" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-056:9a084c9077d30781d3dc05673cb59d94daceaccb19d73fedd9d0179dbaede862" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-057:8dda2687b46ba110ca947fc3043d041af61a2015a1167e2a99bf76ae0eeafa8a" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-058:dcec4edd84150eaac662136f15920cb8e2707b7e2eb83e318ccf1dcd9a6b0748" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-059:7e1e9a3373aeb0fc9314ed276743d47f340bab847525208493bfbf6f24f89a47" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-060:fbcfa029df99bef01e5af1515e4e02ce80a48e3375e03c697b938cc13f0937fc" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-061:0b67f9b3993fab386428cf2fa19aef886db7db63aef296bc4148a8a9a9206d59" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-062:9689b820635e9f162f10218e27beb6592752bf5c4dbd06a756544e1719e723af" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-063:89fa8af3ddade6ba5b25ae8800a34d4924b2305e5f338be4a738398f0254f953" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-064:d3d3d6035fe127be4626dd51dc80d4f5e86c754dad75305f82cab8d9ec8a66ab" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-065:1c188a94ae358b2de2b48c733eb78120fb29a42713a2b476edbb36a958ca6fcd" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-066:a33c1c31a97c5e56d370ecb4cd48dbb6c2f145ed42025ceade07e1df7028153a" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-067:67b64cf98aaaa4319932180bee0b4618fe84e207f6175dc0fa9bfcfd07dd2d0f" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-068:7ba19a948a4ea23f970b3e5a18362abf024275d816a90cbdb36d6a09d0dc75e0" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-069:71d04e14122e933a978182d5937686209136ac2d3b343ecb009cbe1f82183461" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-070:ef8d7a068d49f63fd8ddee740488aa50f13d815251548ff063722d3cc74b278b" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-071:e0cc20945b22ded9962572684b3f41b49b10c266800eed8c5a219ec49bf46518" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-072:b048014b8a1b678fd72a04297442735a6931c87dd49709468208d455414b92a9" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-073:6c12ece2c9be8ef712efde9ed368735e658f550bf0cdf2c9570a05dd8abd36eb" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-074:37c01f0a1be911d6b03b29af509ea2a1e5e1f0c5ab9a22f2a2a1982266c60e00" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-075:5e5fc42a807da5677314348cdedcab9c92846b2bb3e8120994e57f3e78596171" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-076:3e290b4bff049605b952f4bc7bc5949c5e432c58be9dd56a35992fcb43f8e8c1" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-077:2e1a0638dd56d05a131ae5ccbf74b993d7b46c58448bc8a075594009c211016b" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-078:1181983f6b47aa7a2a8297cdd1f3a851fa74881249ed947a3c1e07726acaf01f" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-079:43c1d0c0eb2b07dad069d1e35abeb6108b262835c7410e4ca743820588b51f2a" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-080:7591bf56ff4883aa87b70228d655a04a7f4b2530e13e7057fb47e29ac9519c8e" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-081:64b3f1117be1f5a1ed8f8d330e7508a17ab74f3e4240a3f4e7cdb6d961c4b195" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-082:7b5697437c1272bfd4845bf4eec8fdb32e4f58a2fb56ee5078d0527a2d278def" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-083:4b7cbde528e8e284fb7942225930a84c71528cd6a64542cd36f1b76af354bb71" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-084:4153e5417cc4da8ecefc42c0c3132acc4c128a6f10ccff3ab584e8e5170161b5" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-085:44072c72e866df69f097c38ec323ae02500c3f32c43541e5ccfa23ceb59dbe04" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-086:988b4a8c2b7570c6a2668c61c977b734ec449c0c03a4d1ef15e41088e8232419" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-087:4bab79ad67067fa415ab3d9e3dcaed93f5e942837fdc6d5682cf619b8f5a8533" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-088:b84d3c761510346bbf8fbd682ba4065da6656ed5c7924da6c80f4552f725b99e" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-089:6eb6151151e56e0f0af401bbecd8ff3962a818a51a71fb02e73d38750ac13492" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-090:537c32f9c10aa92d9204fc59a9a8d0333cc6c47d794c9d6492de3ff4f79d73dc" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-091:cda3b6af59fd7e1561835eccdb890ce79f0e822f0823aef9937f912a5a35408e" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-092:2e0debde1c9360474a4958cedc3b8681826467c84be9423483e1d36762d63501" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-093:d341ce7ac4a8a4cee8459ef82479008bc70cf179d4b0a94a870a4e474894d8d3" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-094:8ad68ade1943b230df80cdae0cfdc677fd985c779192097c99f9d63a5d8ab8f5" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-095:954d909f5908ef259a1533bf5fb5155f5663ad7375e55e38e6fdb5ca1160aec0" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-096:1f4f316e10bce333a32b369fceddba12249714cb67b3fc10977471888579017d" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-097:ae06ddd13dbab7d9470d3fcafdf9159e2cf6904d78dfdbefb5a92652ca6a1f5f" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-098:7741f7b7f8a2fb33e32c5d6d5c280f964c019406457fcf751759cee24bbc0aab" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-099:a7660c9221f5a109cf1f5e9aac37a6ecfb2c3cac81697d40ced8a070ca57fc3b" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-100:0da3f1a000f09fc40eda214271a76b0eceb058b03214d7db660944df4a518f59" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-101:f124e444371cc731d5e7937af5878c26a9fc0f3a900c00dbdba745b8aacdcf7a" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-102:55156e0cb9b74596aa543afd2c64c28a1f4aca43716e0dc0215797d04f790e62" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-103:30dbf0f382ada6969b3dd04cf4f5fa2948a3983958720cb98c74e79282ac83a2" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-104:ca4dc471e4db95e1141250418ec545d990fd176906abf463768ce87c840dbc9d" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-105:73e256485f96b2b2103e626a06149306d6c06d0d2fe6202accf920632ab502a5" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-106:6b68c1e1c2648c9ee35ef5b2085909cab224353577f033270f48a52e8888e484" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-107:56cc32e45faff8e0fb895e270a08f55cfcc43ad34aea7bf8aa8f51a44381bac7" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-108:cc8630085c897813163029b5bddc8efa40c4f6c832d4e487b582afbac4fcea14" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-109:efe5d61a56b520a464bf0775cf96963414dd4ac7fc91f91f32bd6ce7f17fd62f" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-110:80f813ee94a76fbe501416ab094f1dd0574a1af36cc7b6b3bbb94a5b3a113353" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-111:5b08b35b140eae85a36c12b829fca41b5d682b5a053e294a2f778c7dc9c39eb9" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-112:fa06ae994c707f43f6c5b6ddd9c468322474735166ed7f03235d186018519669" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-113:755fe84d798742982295a53ac10cb9c49739175412f5736e5a5bcd94143adf72" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-114:d003bcb79155fb5cecc88b0e3de69402e86d4d36789d790d7191c5f8fc259b05" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-115:fe86209b50c6b3da77e415d0305e701e2d58f975322dae62027e2e25f7c25d80" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-116:ec138cd8df8fad334db48b29d85fffb9e71028f16cbcc18f56cd18c26739346e" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-117:b4530798d51465eea9089d01973561068a881090b7942a8942bce9b0b6deb7b5" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-118:d2f8803b63a94864c840e9f34974d3afa8ddd2cd684a8d3fe9b8f66f6d0360c6" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-119:47915340c161acdc1e402d02af6c3dc2e8404e2f1f6c8e342f256a85ceaa14d0" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-120:0ef2fd821c3f06f1a14f77a7f16780b9eeade830681975e85757b3b54a02f4cd" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-121:e9d726bbf520c20902f8b0427ef638b094b0cdd42e310ce1d07c38fa2c522f91" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-122:7801b9aa1193b51a651f3f8ed1def1a0423ed99121e3c65185e124253823a190" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-123:917d943a208650cb4fe806f9764ff2dca9c6d35e0a60feb400a08e47e2f21111" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-124:fcee2e4c11e6f92dbdd4471d9dcf256e9511886f0612502ab496f3e746fdd5bd" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-125:542ccce4d0e545eac3b7abc4cdbcc3396e3a0d314ce8358e230cc887678a384e" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-126:713eabc4c5fbbf560186dba982b2c51aca28791f120c5e19a20e5203203892b9" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-127:6fa4c3f96091c9552bd2025a5739d5787654e01a2bc8d8558bb1c41820a12db4" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-128:ea9e7dbc1e11f1dc446f9ef15216a86f801546e978159e3f15639fb3b5110996" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-129:f50dfe6a47bb4585f06c97ae4b4c0c4b170dcc0c14f260cda2cefbb68a52cdb3" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-130:f580b4edf59323b08c18f567fb61a6eb03c3c63242694db93f45861125a97223" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-131:d1c56704981ab2f11bca573161f9fd3151344ef883ac6b64aed0b8333baf8244" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-132:ca2502fbdbddc3f2a1e071fa15a9250c971fdfd88deda9ab11e272ec817eff7a" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-133:138c5f2c8684bde4e0ee42de9e49d71eb068fb75b7649abb4b2f3115090475df" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-134:c7b75498df38487922b678f7ca76cd77ca4ac39f621119d0d74fdd82a33c28b6" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-135:385186273792100517bc949bfb83fc5182581e774f96c2ea73fedbebc3ee2876" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-136:62dee2ec77b4db18b473e1b434b962bbc77c472d53029f2d7f684abbb7690c58" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-137:297552bbe917c56615103d7d277d054e540b7165a72d98e80f9b243b51832432" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-138:1753c8114b0c1568633424fbb266f816d15c7b6cb58042d88421f3f4d4532d94" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-139:8169c0d4f77083385d4b9b0d6cc762a28b3a34474cc7083110eb0c10ce281728" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-140:5e399892adc413628d17a91c9fa1ba8625d45660371836d94856416c4f7a4feb" \
    "dist/chunks/3f1c4483c41c1f288281dabb789289888e043a9132e1d99f814929e55ba2fb37/part-141:bf266e98441809d2574d9dd22440749fe91f3d6463637ac3df51637cf7c9d483"
  repo_fetch "dist/pronet-fleet-${VERSION}-update.zip" "$UPDATE_SHA256" "$update_zip"
  unzip -q "$base_zip" -d "$work"
  mv "$work/pronet-fleet-${BASE_VERSION}" "$src"
  unzip -oq "$update_zip" -d "$work"
  # Additional independent engines are mirrored under their original digest.
  # Try independent HTTPS delivery paths and the locked upstream Releases.
  # A blocked Raw host must not prevent downloading the remaining engines.
  # Fetch both architectures to preserve the complete offline bundle manifest.
  python3 - "$src" > "$work/extra-assets.tsv" <<'PY'
import json,pathlib,sys
bundle=pathlib.Path(sys.argv[1])
locked=json.loads((bundle/'assets.lock.json').read_text())
for engine in ('paqet','backhaul','parsa-spoof'):
    for asset in locked[engine]['assets'].values():
        print(asset['name'],asset['sha256'],asset['url'],sep='\t')
PY
  while IFS="$(printf '\t')" read -r asset_name asset_sha asset_url; do
    say "Downloading verified engine: $asset_name"
    repo_fetch "dist/engines/${asset_sha}/${asset_name}" "$asset_sha" \
      "$src/vendor/$asset_name" "$asset_url"
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
