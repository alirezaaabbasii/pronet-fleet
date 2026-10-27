# Support and validation — 0.2.3

Observed on 2026-10-24. The owner authorized two dedicated test servers: Iran 79.143.87.142 and Sweden 82.115.8.74, Ubuntu 24.04 amd64. Existing production tunnels were not used as test targets. See FINAL-REPORT.fa.md for WAN selection and application results.

| Component | Evidence | Limits |
|---|---|---|
| HTTPS hub, enrolled agents, four-digit one-use pairing, leases and cancellation | Local HTTPS workflow tests; actual distributed enrollment/pairing/removal and version activation on both VPSs | No HA hub or node-revocation UI |
| Native FRP TLS/QUIC, Chisel, Rathole Noise, Wstunnel WSS/H2 | Six Linux loopback profiles passed real health/data, integrity, half-close, idle, 32 echoes/8 workers, wrong-server-identity rejection and client restart. native-linux-report.json | Loopback throughput is not WAN capacity; arm64 Linux not executed |
| Full Linux service lifecycle | Initial eight-profile and final seven-profile isolated namespace runs passed; standalone Stealth crash recovery also passed; gateway datapath, SIGKILL recovery, warm standby failover and data with hub stopped. linux-systemd-report.json, linux-final-systemd-report.json, linux-stealth-crash-report.json | One amd64 Ubuntu host, no full-host reboot or multi-day run |
| Real Iran–Sweden WAN | See wan-final-report.json; 21 configured candidates including experimental XDI were requested | Failed candidates remain failures; no claim of universal reachability |
| Monitoring and nft counters | Kernel counters installed on both nodes; own counter-only netdev table; persistence/parser unit tests | Observed byte counters, not billing records; scale not benchmarked |
| Installer/update | Actual old-to-new management activation on both servers; permission and systemd path defects found and corrected; update/rollback unit tests | Offline bundle activation; no automatic upstream engine updates |

57 unit tests passed before deployment; the final unit-test-report.txt is authoritative if later fixes change the count. The three macOS native profiles also passed and are preserved in native-test-report.json.

21 profiles: 15 BackPack, two FRP, one Chisel, one Rathole, two Wstunnel. 20 default candidates exclude experimental XDI. Five executable engines; the other research entries are not deployed adapters.

The forwarded workload is TCP only, one inbound port per pair. UDP/QUIC carriers do not imply UDP client forwarding. Multiple foreign nodes need distinct Iran IP:port endpoints; each foreign identity joins one live pair. The current wizard uses the port authorized at node enrollment; additional ports require local configuration and a matching foreign inbound.

No SNI multiplexer, load balancer, IPv6 server identity, DNS-tunnel adapter, domain provisioner, external relay, ACME renewal, HA coordinator, atomic distributed zero-downtime commit, node-revocation UI or unbounded automatic repair is implemented. The disposable Xray WS/TLS and XHTTP tester is an explicit validation harness, not an automatic importer of PasarGuard credentials. It never edits an existing panel.

Pinned official Linux amd64/arm64 archives are verified before allowlisted extraction. Bundle hashes detect corruption, not publisher identity; no signed release or reproducible-build attestation is claimed. Pair leaves and the default self-signed hub certificate have a one-year lifetime; automated renewal is not implemented. Hub renewal must coordinate agent trust. BackPack L3 carriers use the tagged upstream Noise session; the SNI-shaped carrier is not a trusted application certificate. Keep authenticated TLS enabled in WS/XHTTP applications.

Short qualification runs are seconds/minutes, not multi-day stability evidence. The selected carrier is the best accepted measured candidate for this route and test window. No protocol is guaranteed to be unfilterable or permanently best across Iran.

Actual authenticated WS/TLS and XHTTP/TLS transfers passed through the Iran public gateway, including 1 MiB upload integrity, downloads, 12 requests/four workers and 45 seconds idle. See ws-e2e-report.json and xhttp-e2e-report.json. Real WAN fault injection passed with the hub stopped, after primary SIGKILL, and after a 48-second observed switch to the UDP reverse standby. Final audit files confirm both selected carriers healthy, owned units enabled/active, SSH preserved, and existing foreign Nginx/Docker active. The disposable foreign inbound was removed; configure the real panel inbound on TCP 0.0.0.0:2053.

Version 0.2.3 adds a real standby health probe each watchdog cycle, separate backup state in the CLI/dashboard, and bounded transition logging without switching a healthy primary. Three regression tests cover healthy-primary backup probing, failure/recovery reporting and primary-failure switchover. Carrier binaries and rendered configurations are unchanged from the 0.2.2 application/fault tests. The final short observation is in standby-watch-report.json; it is not a multi-day soak.
