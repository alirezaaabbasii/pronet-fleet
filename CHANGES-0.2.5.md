# Pronet Fleet 0.2.5 - faster, simpler setup

## Setup: two steps instead of eight
1. **Iran:** `curl -fsSL https://raw.githubusercontent.com/alirezaaabbasii/pronet-fleet/main/get.sh | sudo bash`, choose `1`, press Enter twice (public IP and client port are detected/defaulted).
   The coordinator is created on the Iran server automatically (first free port of 9443/8443/7443/10443/20443; an active ufw/firewalld gets the port opened).
2. **Foreign:** paste the single command the Iran server prints:
   `curl -fsSL .../get.sh | sudo bash -s -- join PNF1-...`
   It installs, registers and pairs in one go. No bootstrap file to copy, no paths to type, no separate 4-digit prompt.

The join token carries the coordinator URL, the enrollment secret, the client port, the pairing code and the
**SHA-256 pin of the coordinator certificate**. The foreign server accepts the coordinator only if the certificate
matches the pin (no trust-on-first-use). Pairing codes are valid for 10 minutes (was 5).

The Iran agent talks to a local coordinator over 127.0.0.1 when the certificate covers it (new coordinators),
so a host that cannot hairpin its own public IP still works.

## Carrier testing: roughly half the time or less
- Carriers are prepared and started in batches of 6 (2 round trips per batch instead of 2 per carrier, one host inventory per batch).
- Reachability of a whole batch is awaited **in parallel** for at most 20 s; a carrier whose engine exits is failed immediately.
- Unreachable carriers no longer run a full benchmark (previously ~60 s of timeouts each); throughput is still measured one carrier at a time.
- Agent job polling 2 s -> 0.5 s, coordinator result polling 0.5 s -> 0.2 s.
- Both servers must run the same version; a mismatch stops setup in preflight with a clear message.

## Output
- All terminal text is English (Persian did not render correctly in terminals). The web dashboard is unchanged.
- Live progress view (redraws in place) and a final report: primary and standby carriers with the reason each was chosen,
  failed carriers grouped by cause, total test time, route latency, and the exact next action (e.g. foreign inbound not listening).
- New: `sudo pronet report`.

## Upgrade
Run the same installer command on both servers. Running tunnels are kept; the coordinator and agents restart.

## 0.2.6
- The first menu asks where the server is (1 Iran, 2 Foreign). Choosing Foreign without the command from Iran stops with:
  "Start on your IRAN server first ... it prints one command; copy it and run it on this foreign server."
- The Iran server's final instruction is explicit: copy the whole line and run it on the foreign server.

## 0.2.7
- Idle agents poll the coordinator every 5 s instead of every 0.5 s (fast polling only for 3 minutes around setup work).
- The installer keeps the current and one previous management version under /opt/pronet-fleet and removes older unreferenced ones.

## 0.2.8
- Automatic failover re-arms itself after the primary has been healthy for about one minute (for example after a
  server's traffic quota is recharged). Previously it stayed paused until `sudo pronet repair`.
- `sudo pronet failover-delay [SECONDS]` on Iran shows or sets how long the primary must be completely down before
  switching to the standby (10-600 s, default 15 s).

## 0.2.9
- Health probes of the primary and standby run once per minute (was every 5 s).
- Default failover: the primary must miss 2 probes in a row (fully down for about 1-2 minutes) AND the standby must
  answer a fresh probe. If the standby is down too, nothing is switched: traffic stays on the primary and resumes
  there as soon as it comes back.
- Failover re-arms after the primary has been healthy for about 2 minutes.
- `sudo pronet probe-interval [5-300]` and `sudo pronet failover-delay [10-1800]` show or change these values.

## 0.3.0
- Clean terminal status (`sudo pronet status` / `watch`): servers with online state and load; per tunnel: client
  address, active carrier, standby health, panel inbound state, traffic totals and current rate, active connections,
  failover settings, last switch, recent events and plain-language problems.
- Redesigned read-only web dashboard on the coordinator (same port as before, e.g. https://IRAN_IP:9443/),
  mobile friendly, no JavaScript. `sudo pronet dashboard` prints the address and login; the setup report prints the address.
- Rendering costs about 0.05 ms per page; the page is built from data the coordinator already has and adds no work to tunnels.

## 0.3.1
- Dashboard moved to a secret link (https://IRAN_IP:PORT/<32 hex>/); `sudo pronet dashboard` prints it,
  `sudo pronet dashboard off|on|new-link` disables it or rotates the link. The old password page is removed.
- Every other non-API path on the coordinator port answers a plain 404: no Server header, no product name,
  no login prompt, so port scanners cannot identify the software.
- Dashboard polish: summary tiles (tunnels up/down, servers online, warnings) and status-colored cards. ~6 KB, ~0.04 ms to render.

## 0.3.2
- Dashboard is always dark.

## 0.3.3
- Several client ports on one tunnel. At the "Client port(s)" question enter one port (2053) or several separated by
  commas (2053,2083,8443); a range such as 2080-2083 also works (at most 16 ports). The same works with
  `--port 2053,2083` for `setup-iran` and `pair`.
- Every port listens on the Iran server and goes to the SAME port on the foreign server, through the same carriers,
  the same standby and the same failover. Create one panel inbound per port on the foreign node (listen 0.0.0.0).
- A single port behaves exactly as before; tunnels created by earlier versions keep working unchanged after the upgrade.
- Status and the final report list every port; a port whose foreign inbound is not listening is named.
