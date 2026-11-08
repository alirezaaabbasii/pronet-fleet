# Resilient installation downloads

Iran routes can fetch jsDelivr while GitHub Raw TLS times out. Downloading get.sh alone from CDN leaves the mirror helper, 70 MB base bundle and independent engines dependent on Raw. Some transfers also stall indefinitely.

Ship 0.3.24 with a small bootstrap install.sh served through CDN and GitHub. It obtains a pinned, versioned get.sh through Raw, CDN and GitHub API before execution. Every repository download tries HTTPS alternatives with SHA256 validation, bounded connect/idle/total time, private partial files, atomic acceptance and cleanup. Large archives skip jsDelivr's file-size limit: fall back to 142 pinned 512 KiB parts served through CDN/Raw, reserving API quota for whole-file fallback, verify their concatenation against the original archive digest; full GitHub API is a last fallback. Initial bootstrap is HTTPS-trusted; subsequent executable payloads are hash-pinned. Extra engines also use locked upstream Release URLs. Prefer a successful source for later files; never disable TLS/digest validation. An explicit PRONET_URL remains an exact user override. Existing offline installation stays available.

Alternatives: only replace the initial URL (rejected: leaves all other downloads broken); add an owned mirror (requires an operator-owned host, not supplied); use independent public delivery endpoints with pinned hashes (chosen). Availability on every network cannot be guaranteed. APT/DNS policy and running tunnel lifecycle remain unchanged. Foreign join commands use bootstrap, preserve arguments and omit the Iran mirror prompt as before.

Execution authorized by the user's request to repair the installation path globally and existing authorization to publish repo updates. No production-server actions are included.
