# Pronet Fleet 0.3.6

Default recovery is now `stable`: keep the selected primary and warm standby, with confirmed failover and a persistent switch budget. Transport timeouts now close failed sessions instead of entering a CPU/RAM runaway loop; failed stream cleanup also releases socket buffers promptly. See `CHANGES-0.3.6.fa.md` and `STABILITY-VALIDATION.json` inside the release ZIP for validation and limits.

Updating management preserves live sessions; existing data helpers load the memory fix on their next restart. Schedule that one-time restart using the release notes. Old installed versions are retained because live engine plans may still pin them.

Iran <-> foreign tunnel manager: automatic carrier testing, best-route selection, warm standby with automatic failover.

## Install (2 steps)

**1. Iran server (always start here)**
```bash
curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh | sudo bash
```
Choose `1` (Iran), then press Enter twice (detected public IP, client port 2053).
The Iran server sets up the coordinator itself and prints ONE command for the foreign server.

**2. Foreign server** - copy the whole line shown on Iran and run it, e.g.
```bash
curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh | sudo bash -s -- join PNF1-...
```

The Iran screen shows live progress and a final report (chosen carrier, standby, why, and what failed).
Finally create your panel inbound on the foreign server (listen `0.0.0.0`, same port) and give clients `IRAN_IP:PORT`.

## Useful commands
```bash
sudo pronet            # menu (new tunnel, live status, report)
sudo pronet watch      # live status
sudo pronet report     # last setup report
sudo pronet logs ID    # logs of one tunnel
sudo pronet dashboard  # web dashboard link (Iran)
```

## If GitHub is blocked on a server
Copy `dist/pronet-fleet-0.3.6.zip` and `get.sh` with scp, then:
```bash
sudo PRONET_ZIP=/root/pronet-fleet-0.3.6.zip bash get.sh                 # Iran
sudo PRONET_ZIP=/root/pronet-fleet-0.3.6.zip bash get.sh join PNF1-...   # foreign
```

---

### راهنمای فارسی خلاصه
۱. همیشه از سرور **ایران** شروع کن: دستور اول را بزن، گزینهٔ `1` و دو بار Enter.
۲. خطی که ایران در آخر چاپ می‌کند را کامل کپی کن و روی سرور **خارج** بزن.
۴. صفحهٔ وب وضعیت: روی ایران `sudo pronet dashboard` را بزن تا لینک صفحه را ببینی.
۳. بعد از پیام `TUNNEL READY`، روی سرور خارج در پنل اینباند را روی `0.0.0.0` و همان پورت بساز و به کاربر آدرس `IP-ایران:پورت` بده.
