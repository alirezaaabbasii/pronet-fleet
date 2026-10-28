<div align="center">

# Pronet Fleet

**Iran ⇄ foreign tunnel manager: it tests every carrier on your real route, picks the best one, keeps warm standbys and fails over by itself.**

![version](https://img.shields.io/badge/version-0.3.16-blue)
![platform](https://img.shields.io/badge/platform-Linux%20amd64%20%7C%20arm64-lightgrey)
![python](https://img.shields.io/badge/python-3.10%2B-green)
![carriers](https://img.shields.io/badge/carriers-20%2B-orange)

**English** · [فارسی](README.fa.md)

</div>

---

## Why Pronet Fleet

Most tunnel scripts make you pick a protocol, hope it survives the filtering on *your* route, and fix it by hand when it dies at 3 a.m.
Pronet Fleet does the opposite:

1. It **starts 20+ carriers** (BackPack, FRP, Chisel, Rathole, wstunnel, over TCP, raw TCP, UDP, QUIC, KCP, ICMP, WebSocket and HTTP/2) between your two servers.
2. It **measures them on the real route**: latency, jitter, upload and download, idle survival, half-close, data integrity.
3. It **keeps the best one as primary plus two warm standbys** from *different* protocol families, so one filtering rule can't take out all three.
4. It **watches them every minute** and switches users to a standby on its own when the primary dies.

Your clients always use the same `IRAN_IP:PORT`. Carrier changes happen behind that address.

## Features

| | |
|---|---|
| 🔍 **Real-route carrier testing** | Every carrier is measured end-to-end between your two servers before anything is chosen. |
| ⚡ **Fast setup** | Carriers are tested in smart groups. Host changes on both servers stay outside measurements. Probes and idle waits overlap within a group; retired services stop together with one manager reload. |
| 🏆 **Best-route selection** | A stability-weighted score: a fast but flaky carrier loses to a slightly slower, steady one. |
| 🛟 **Primary + 2 warm standbys** | Standbys run and are probed all the time, so failover takes seconds. Only one standby is kept on servers with less than 1.4 GB RAM. |
| 🔁 **Automatic failover, only for real outages** | A health check fails only if 3 echo attempts all fail **and** no user data came through the carrier in the last 30 s, so a busy or slightly lossy tunnel is never treated as down. The primary has to fail 3 checks in a row (about 3 minutes) before users move to the standby with the best record over the last hour. Dead sessions are closed so clients reconnect immediately. |
| 📉 **Flap detection** | A standby with 3+ separate outages in an hour is marked *unstable* and replaced automatically, which never touches users. A working primary is left only after 4+ outages in an hour, never within 2 hours of a switch, and never within 24 hours of your own manual choice. |
| 🔧 **Self-repair** | An unstable standby is swapped for the next carrier that passed setup; the primary is never touched. If **every** path is down for 5 minutes while both servers are online, carriers are re-tested and the best are installed, with the same client address. |
| 🧯 **Switch budget** | At most 3 automatic switches per 30 minutes, so a bad route can't make it thrash. |
| 🌙 **Quiet during long outages** | If one server is off for hours, everything backs off to about one attempt a minute, logs once, and waits. Nothing spins. |
| 📨 **Telegram alerts** | Optional. Covers down/restored, failover, unstable carrier, standby replaced, re-test, and a server that stops reporting. Sent from the foreign server, because Telegram is filtered in Iran. English or Persian. |
| 🖥️ **Clear terminal UI** | Live per-carrier progress bars, a "Now:" line showing the current step, and a final report that says what was chosen and why. |
| 🌐 **Web dashboard** | A private status page served from the Iran server at an unguessable link, with a **Return to main carrier** button when a tunnel is on a standby. |
| 🔀 **Manual return** | After a failover Pronet stays on the standby. You choose when to return: `sudo pronet switch` or the dashboard button. Only new connections move. |
| 🔌 **Multiple client ports** | One tunnel can carry several ports, e.g. `2053,2083,8443`. |
| 🔒 **Safe by design** | SHA256-pinned release archives. Each tunnel gets its own credentials and certificates. Firewall rules and services are tagged and owned, and nothing else on the server is touched. |
| 🧹 **Clean uninstall** | `sudo pronet uninstall` removes only what Pronet created. |

## How it works

```
 clients ──► IRAN_IP:PORT ──► [ gateway ] ══ primary carrier ══► [ foreign ] ──► your panel inbound
                               (Iran)      ── standby 1 ──────►   server        (same port, 0.0.0.0)
                                           ── standby 2 ──────►
```

- **Iran server**: runs the coordinator (job queue, health decisions, dashboard), an agent and the client-facing gateway.
- **Foreign server**: runs an agent and the far end of each carrier. Your panel (Xray / V2Ray / PasarGuard / Marzban…) inbound listens there.
- The **gateway** keeps the client port fixed. On a switch, new connections go to the new carrier at once. Connections on a dead carrier are closed so clients reconnect.
- The **watchdog** (on Iran) sends one tiny probe to each carrier per minute. It handles failover, flap detection and outage tracking.

## Requirements

- Two Linux servers (amd64 or arm64) with systemd, one in Iran and one abroad.
- Root access, Python 3.10+ (Ubuntu 22.04+ / Debian 12+ ship it).
- Standard tools: `ip`, `ss`, `iptables`, `openssl`, `ssh-keygen`.
- Both servers must run **the same Pronet version**.

## Quick start

**1. Iran server (always start here)**

```bash
curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh | sudo bash
```

Choose `1` (Iran), then press Enter to accept the detected public IP and client port `2053`.
Iran sets up the coordinator and prints **one command** for the foreign server. That command stays on screen until the foreign server joins.

**2. Foreign server**: paste the whole line printed on Iran, for example:

```bash
curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh | sudo bash -s -- join PNF1-...
```

> The join line contains a one-time secret. Don't post it anywhere.

**3. Watch the test on the Iran screen.** You get live progress bars for each carrier, then a final report: primary, standbys, measured numbers, and why each rejected carrier failed.

**4. Point your panel and clients**
- On the foreign server, create the panel inbound on `0.0.0.0` with the **same port** (2053 by default).
- Give clients `IRAN_IP:2053`.

## Commands

| Command | Where | What it does |
|---|---|---|
| `sudo pronet` | both | Menu: new tunnel, live status, report, dashboard, Telegram alerts |
| `sudo pronet watch` | both | Live status of every tunnel |
| `sudo pronet status` / `json` | both | One-shot status (text / JSON) |
| `sudo pronet report [ID] [--details]` | Iran | Last setup report; `--details` lists every carrier |
| `sudo pronet pair [options]` | Iran | Create another tunnel (see options below) |
| `sudo pronet logs ID` | both | Events and engine logs of one tunnel |
| `sudo pronet dashboard [on\|off\|new-link]` | Iran | Web dashboard link |
| `sudo pronet switch [ID] [CARRIER]` | Iran | Move new connections back to the main carrier (or to CARRIER); never automatic |
| `sudo pronet notify [telegram\|test\|on\|off\|status]` | foreign | Telegram alerts |
| `sudo pronet probe-interval [SECONDS]` | Iran | Seconds between health probes (default 60, 5–300) |
| `sudo pronet failover-delay [SECONDS]` | Iran | Total primary outage before switching (default 180, 10–1800) |
| `sudo pronet recovery-policy [stable\|explore]` | Iran | `stable` (default) or opt-in exploration of new carriers |
| `sudo pronet repair ID` / `restart ID` | both | Re-apply / restart one tunnel's services |
| `sudo pronet remove ID` | Iran | Stop and remove one tunnel on both servers |
| `sudo pronet doctor` | both | Inventory and checks of this server (JSON) |
| `sudo pronet profiles` | both | List all carriers |
| `sudo pronet uninstall [--yes]` | both | Remove Pronet Fleet completely from this server |

### `pronet pair` / `setup-iran` options

| Option | Default | Meaning |
|---|---|---|
| `--port 2053` or `--port 2053,2083,8443` | `2053` | Client port(s) on Iran. The same ports are used for the panel inbound on the foreign server. |
| `--name NAME` | auto | Tunnel name (shown in reports and alerts) |
| `--quality quick\|balanced\|thorough` | `balanced` | How long each carrier is measured |
| `--profiles a,b,c` or `all` | all non-experimental | Limit or extend the carriers tested |
| `--direction iran-dials\|foreign-dials` | `iran-dials` | Which side opens the connection, for carriers that support both |
| `--sni host` | none | SNI for SNI-shaped carriers |
| `--no-standby` | off | Primary only, no warm standbys |
| `--no-wait` | off | Return immediately; follow with `sudo pronet watch` |

## Carriers

| Name | Engine | Transport |
|---|---|---|
| `gre` | Linux kernel GRE | Native GRE over IPv4 (IP protocol 47), independent of BackPack |
| `bp-l3-pck`, `bp-l3-pck-reverse`, `bp-l3-pck-fec` | BackPack L3 | raw TCP (PCK); reverse = foreign dials; FEC variant |
| `bp-l3-udp`, `bp-l3-udp-reverse`, `bp-l3-udp-fec` | BackPack L3 | UDP |
| `bp-l3-quic`, `bp-l3-quic-reverse` | BackPack L3 | QUIC |
| `bp-l3-sni` | BackPack L3 | SNI-shaped TCP |
| `bp-l3-xdi` | BackPack L3 | ICMP (experimental, not in the default set) |
| `bp-stealth`, `bp-pck`, `bp-quic`, `bp-kcp` | BackPack reverse | stealth TCP / raw TCP / QUIC / KCP |
| `bp-direct-stealth` | BackPack direct | stealth TCP |
| `frp-tls`, `frp-quic` | FRP | TLS over TCP / QUIC |
| `chisel` | Chisel | SSH over HTTP |
| `rathole-noise` | Rathole | Noise-encrypted TCP |
| `wstunnel-wss`, `wstunnel-h2` | wstunnel | WebSocket over TLS / HTTP/2 |

**GRE is included in the default tests.** It uses protocol 47, not TCP/UDP port 47. It requires kernel GRE support and a route that permits GRE; it does not require `/dev/net/tun`. GRE itself does not encrypt or authenticate traffic. Its key separates managed tunnels, and the panel protocol must provide the application security you need.

The active adapter list above is the supported set; research/catalog entries are not additional working adapters.

Engines are unchanged upstream releases, pinned by SHA256 and run as separate systemd services with memory and task limits.

## Failover and recovery

| Situation | What Pronet does |
|---|---|
| Primary fails 3 checks in a row (each check = 3 attempts, no user data flowing) | Moves users to the standby with the best record over the last hour and closes sessions stuck on the dead path |
| Primary keeps dropping briefly (4+ outages / hour) | Moves **new** connections to a fully stable standby, but only if no switch happened in the last 2 h (24 h after a manual switch); established ones are left alone |
| A standby keeps dropping | Marks it unstable and replaces it with the next carrier that passed setup (at most once per 30 min) |
| Every path down for 5 min, both servers online | Re-tests carriers and installs the best ones; retries after 1 h, 2 h, 4 h, then every 6 h if nothing works |
| One server off or unreachable for hours | Waits quietly (about one attempt a minute). When it returns, carriers get 3 minutes to reconnect on their own before any repair starts |
| Primary healthy again after a failover | Stays on the standby (no automatic return). Return with `sudo pronet switch` or the dashboard button: only new connections move, and the switch doesn't count toward the budget |
| More than 3 switches in 30 min | Pauses automatic switching for the rest of the window; probes continue |

## Telegram alerts (optional)

Telegram is filtered in Iran, so alerts are sent **from the foreign server**:

```bash
sudo pronet notify telegram     # on the FOREIGN server: asks for bot token, chat id, language (en/fa)
sudo pronet notify test         # send a test message
sudo pronet notify off | on     # pause / resume
```

1. In Telegram, open **@BotFather**, send `/newbot`, copy the token.
2. Send any message to your bot, or add it as an admin to a channel.
3. Chat id: your numeric id (ask **@userinfobot**) or `@yourchannel`.

The token is typed hidden and stored only on the foreign server (mode 600). It is never sent to Iran.

You get alerts for:
- tunnel down / restored
- carrier switched
- unstable primary or standby
- standby replaced
- re-test started / finished
- a server silent for 2+ minutes, and its return
- the Iran server unreachable from the foreign server for 5+ minutes

## Resource usage

After setup, the steady state is deliberately small:

- **Health:** one tiny echo per carrier per minute. The raw probe history stays on the Iran server; only a summary goes into heartbeats.
- **Control traffic:** one heartbeat every 15 s, plus one held job request roughly every 20 s per server. There is no busy polling, and the coordinator wakes on events instead of querying its database in a loop.
- **Long outage of one side:** all retries back off to about once a minute and the outage is logged once, with a reminder every 15 minutes. An engine that keeps exiting is restarted with growing delays (5 s → 60 s). Engine logs are rate-limited by journald.
- **Memory:** about 30 MB per running carrier per server; the second standby is skipped on small servers.
- Measurement lanes, live progress and long tests only run during setup or a repair.

## Uninstall

```bash
sudo pronet uninstall
```

This removes Pronet's services, tagged firewall rules, nftables tables, state, configuration and the `pronet` command. It touches nothing else. Run it on each server.

## Offline install (GitHub blocked on a server)

The online installer verifies the 0.3.12 base ZIP and the small 0.3.16 update ZIP before assembling the new version. For offline installation, use the complete `pronet-fleet-0.3.16.zip` with `get.sh`, then:

```bash
sudo PRONET_ZIP=/root/pronet-fleet-0.3.16.zip bash get.sh                  # Iran
sudo PRONET_ZIP=/root/pronet-fleet-0.3.16.zip bash get.sh join PNF1-...    # foreign
```

`get.sh` checks the ZIP's SHA256 before installing. You can also use a mirror with `PRONET_URL=https://…/pronet-fleet-0.3.16.zip`.

## FAQ

**Do I have to choose a protocol?** No. Pronet tests them all on your route and chooses. Use `--profiles` only if you want to limit the list.

**Will clients disconnect on failover?** Only those on the dead path, and they reconnect immediately through the new one. Everyone else keeps their connection.

**Can I run several tunnels?** Yes. Use `sudo pronet pair` on Iran for each additional tunnel or port set.

**The foreign server was off for hours. Do I need to do anything?** No. When it returns, carriers reconnect by themselves. A repair runs only if they still fail after a few minutes.

**Where are the logs?** `sudo pronet logs ID` shows tunnel events and engine logs. `sudo pronet watch` shows live status.

## Credits and licenses

Pronet Fleet runs unchanged upstream engines as separate processes:
- [BackPack](https://github.com/AminMGMT/BackPack) (AGPL-3.0)
- [FRP](https://github.com/fatedier/frp) (Apache-2.0)
- [Chisel](https://github.com/jpillora/chisel) (MIT)
- [Rathole](https://github.com/rathole-org/rathole)
- [wstunnel](https://github.com/erebe/wstunnel)

Licenses, notices and the BackPack source are included in the release ZIP (`licenses/`, `sources/`, `NOTICE.md`). Inclusion does not imply endorsement by the upstream authors.

## Changelog

Release notes (Persian) are inside each release ZIP as `CHANGES-<version>.fa.md`.

- **0.3.16**
  - Independent native Linux GRE in the default carrier tests, with bidirectional integrity, half-close, idle and throughput qualification.
  - Owned interface cleanup, peer-restricted protocol-47 firewall rules and independent GRE family ranking.
- **0.3.13**
  - Serialize group startup against measurements on both servers; batch retirement avoids repeated stop waits and manager reloads.
  - Confirm service shutdown with process IDs, continue partial cleanup, and expose failed setup/cleanup accurately.
  - 217 tests pass on macOS/Python 3.12; real Linux/systemd route validation is still required.
- **0.3.12**
  - Far fewer switches: 3-attempt checks, user traffic counts as proof of life, failover after 3 failed checks.
  - Stricter flap rules, a 2 h calm period after a switch, and a 24 h hold on manual choices.
  - Last-hour uptime per carrier.
- **0.3.11**
  - Manual return to the main carrier: `sudo pronet switch` and a dashboard button.
  - Fix: a stale drain list could cut a healthy carrier on a later switch.
- **0.3.10**
  - Long outages stay quiet: shared backoff to one attempt a minute, a single log line, restart backoff for engines, journald rate limits.
  - Lighter steady state: event-driven job waits, fewer controller passes, one `systemctl` call per heartbeat.
  - A server returning from an outage gets 3 minutes before any repair.
  - Telegram alerts.
- **0.3.9**
  - Flap detection.
  - Second warm standby.
  - Automatic standby replacement and re-test when every path is down.
  - "Now:" line and dashboard link in the final report.
- **0.3.8**
  - Faster grouped carrier testing.
  - Live per-carrier progress.
  - Cleaner reports.
- **0.3.7**
  - The join command stays on screen until the foreign server joins.
  - `pronet uninstall`.
- **0.3.6**
  - Stable recovery policy by default.
  - Fix for the gateway CPU/RAM runaway.


## Independent carriers added in 0.3.16

Paqet (`paqet`, pinned v1.0.0-alpha.21) is an independent engine, not a BackPack mode.
Backhaul v0.7.2 provides `backhaul-tcp` and `backhaul-tcpmux`. Both use Pronet's
authenticated FIN/ACK bridge, preserving application half-close despite upstream's
full-close behaviour. These TCP modes do not encrypt payload; use authenticated
application encryption. Upstream WSS is deliberately excluded because its client
skips certificate validation. No upstream installation script or global tuning runs.

`parsa-spoof` uses the Parsa v3.1.0-beta.0 raw TCP carrier with **WireGuard** inside.
WireGuard supplies encryption, peer authentication and replay protection. Both servers
need `wireguard-tools` and kernel WireGuard support, plus permitted spoofed egress.
The source addresses must be explicitly chosen by the operator; Pronet does not
invent addresses or scan public ranges. On Iran, configure the address that each
sender will put in its outgoing packets:

```sh
sudo pronet spoof-sources IRAN_SENDER_SOURCE_IP FOREIGN_SENDER_SOURCE_IP
sudo pronet
```

This applies to new tunnels. Alternatively use `pronet pair --spoof-iran IP
--spoof-foreign IP`. Without source addresses the profile fails preflight immediately
with a clear reason and emits no spoof traffic. An answering authenticated test over
WireGuard, integrity, bidirectional throughput, half-close and idle survival are still
required before selection. A lab test cannot establish compatibility with a public
Iran/foreign route. ICMP and XDP modes are excluded to avoid global sysctl changes
and attachment to a shared physical interface. Existing tunnels keep their committed
carriers until an explicit new setup or retest. GFK remains unimplemented and is not
in automatic tests.

All six new Linux amd64/arm64 assets are checksum-pinned and bundled for offline
installation. Upstream source and licences are in `assets.lock.json` and `licenses/`.


## Emergency tunnels (manual only, 0.3.16)

Spoof is excluded from ordinary setup, `pair --profiles all`, automatic recovery,
standby replacement and automatic retesting, including old 0.3.15 histories.
Paqet and Backhaul remain normal carriers. Open `sudo pronet` -> **7) Emergency
tunnels**, or run `sudo pronet emergency`. Emergency and normal carriers cannot
be mixed in one pairing.

The emergency section offers **Test only, then clean up** and **Test and activate**.
The test-only option runs reachability, integrity, speed, idle and half-close
qualification on both nodes, cleans up, and saves an emergency report without
committing a carrier or opening a client gateway. Tests use a separate pairing
with free endpoints/nodes; no existing active tunnel is stopped or replaced.
The ordinary foreign join command still completes that separate pairing.

Noninteractive entry points (both sender source addresses are required unless
saved using `spoof-sources`):

```sh
sudo pronet emergency --test-only --spoof-iran IP1 --spoof-foreign IP2
sudo pronet emergency --activate --spoof-iran IP1 --spoof-foreign IP2
```

Manual emergency setup may keep monitoring the established tunnel's health;
it never automatically starts another emergency qualification scan.
