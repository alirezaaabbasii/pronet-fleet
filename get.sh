#!/usr/bin/env bash
# Pronet Fleet one-line installer.
#   curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh | sudo bash
#
# Downloads the pinned release, verifies SHA256 BEFORE anything is installed,
# installs (or upgrades) and opens the menu. It never touches existing tunnels,
# firewall policy or panel configuration.
#
# Overrides (optional):
#   PRONET_URL=https://mirror/pronet-fleet-0.2.4.zip   use a mirror if GitHub is slow/blocked
#   PRONET_ZIP=/root/pronet-fleet-0.2.4.zip            use a file already copied to the server
#   PRONET_NO_MENU=1                                   install only, do not open the menu
set -euo pipefail

VERSION="0.2.4"
OWNER_REPO="alirezaaabbasii/pronet-fleet" 
SHA256="9a4a335882081335ab141e4a45fefbd1dcabdcc066a51e4823ca012ba1b816ee"
URL="${PRONET_URL:-https://github.com/${OWNER_REPO}/releases/download/v${VERSION}/pronet-fleet-${VERSION}.zip}"

say()  { printf '\033[1;36m[pronet]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[pronet] خطا:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "با sudo اجرا کن:  curl -fsSL ... | sudo bash"
[ "$(uname -s)" = "Linux" ] || fail "فقط Linux پشتیبانی می‌شود."
case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) fail "معماری $(uname -m) پشتیبانی نمی‌شود (فقط amd64/arm64)." ;; esac
[ -d /run/systemd/system ] || fail "systemd لازم است."

# System tools the agent needs. Installed only when missing.
need=""
for pair in python3:python3 unzip:unzip ip:iproute2 ss:iproute2 iptables:iptables openssl:openssl ssh-keygen:openssh-client nft:nftables sha256sum:coreutils curl:curl; do
  cmd="${pair%%:*}"; pkg="${pair##*:}"
  command -v "$cmd" >/dev/null 2>&1 || case " $need " in *" $pkg "*) ;; *) need="$need $pkg" ;; esac
done
if [ -n "$need" ]; then
  if command -v apt-get >/dev/null 2>&1; then
    say "نصب پیش‌نیازها:$need"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq $need >/dev/null
  else
    fail "این ابزارها نصب نیستند:$need"
  fi
fi
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || fail "Python 3.10 یا جدیدتر لازم است."

work="$(mktemp -d /tmp/pronet-get.XXXXXX)"
trap 'rm -rf "$work"' EXIT
zip="$work/pronet-fleet-${VERSION}.zip"

if [ -n "${PRONET_ZIP:-}" ]; then
  [ -f "$PRONET_ZIP" ] || fail "فایل $PRONET_ZIP پیدا نشد."
  cp "$PRONET_ZIP" "$zip"
else
  say "دانلود نسخهٔ $VERSION ..."
  curl -fL --retry 5 --retry-delay 3 --connect-timeout 15 -o "$zip" "$URL" \
    || fail "دانلود نشد. اگر GitHub از این سرور در دسترس نیست، فایل را با scp بیاور و با PRONET_ZIP=/مسیر/فایل اجرا کن."
fi

say "بررسی SHA256 ..."
echo "${SHA256}  ${zip}" | sha256sum -c --status || fail "هش فایل مطابقت ندارد؛ فایل خراب یا دست‌کاری‌شده است. چیزی نصب نشد."

unzip -q "$zip" -d "$work"
src="$work/pronet-fleet-${VERSION}"
[ -f "$src/install.sh" ] || fail "ساختار بسته نامعتبر است."
sh "$src/install.sh" --verify-only

if ls /etc/systemd/system/pronetf-*.service >/dev/null 2>&1; then
  say "نسخهٔ قبلی پیدا شد؛ ارتقا با حفظ تونل‌های فعال ..."
  sh "$src/install.sh" --activate-services
  say "برای فعال شدن Gateway جدید، روی ایران در ساعت کم‌ترافیک اجرا کن:"
  say "  sudo systemctl restart pronetf-<PAIR_ID>-gateway.service"
else
  sh "$src/install.sh"
fi

say "نصب تمام شد. منو:  sudo pronet"
if [ -z "${PRONET_NO_MENU:-}" ] && [ -r /dev/tty ]; then
  # stdin is the piped script; give the interactive menu the real terminal.
  exec /usr/local/bin/pronet < /dev/tty
fi
