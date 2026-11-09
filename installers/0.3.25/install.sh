#!/usr/bin/env bash
# The group must parse in full before a streamed bootstrap executes.
{
set -euo pipefail
umask 077
OWNER_REPO="alirezaaabbasii/pronet-fleet"
REPO_REF="main"
VERSION="0.3.25"
INSTALLER_SHA256="65dacf60b1934f65de1864102b0880f3246642e3915c722ba8b68aaefa9b102d"
say() { printf '[pronet] %s\n' "$*"; }
fail() { printf '[pronet] error: %s\n' "$*" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || fail 'curl is required.'
command -v sha256sum >/dev/null 2>&1 || fail 'sha256sum (coreutils) is required.'
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
DOWNLOAD_PREFERRED_SOURCE=${PRONET_PREFERRED_SOURCE:-cdn}
bootstrap_work=$(mktemp -d "${TMPDIR:-/tmp}/pronet-bootstrap.XXXXXX")
trap 'rm -rf "$bootstrap_work"' EXIT
repo_fetch "installers/${VERSION}/get.sh" "$INSTALLER_SHA256" "$bootstrap_work/get.sh"
export PRONET_PREFERRED_SOURCE="$DOWNLOAD_PREFERRED_SOURCE"
bash "$bootstrap_work/get.sh" "$@"
}
