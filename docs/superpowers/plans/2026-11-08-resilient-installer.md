# Resilient installer implementation plan

Goal: install through a bounded, verified alternative when GitHub Raw is blocked.
Architecture: embedded shared Bash download functions in bootstrap and get.sh; immutable versioned installer payload; existing cumulative release packaging.
Tech: Bash, curl, sha256sum, Python unittest, existing GitHub Actions.
Spec: ../specs/2026-11-08-resilient-installer-design.md

- [ ] Write and observe failing real-download/fixture tests for blocked Raw, corrupt/JSON replies, stalled transfers, partial cleanup, and bootstrap argument preservation.
- [ ] Implement bounded, digest-checked Raw/CDN/API/upstream fallback and reuse successful transport; cover helper, base/update and extras; retain offline/explicit URL semantics.
- [ ] Add verified bootstrap; update generated joins, README, version, release and CI paths.
- [ ] Run downloader/installer/unit tests; verify complete archive and immutable manifest, live upgrade and WireGuard integrations.
- [ ] Independent review, publish PR, wait for CI, merge authorized update and verify published endpoints.

Review focus: no CDN attempt for 70 MB archive; HTTP 200 error JSON rejected; all sources failing never installs; checksum checks retained on every fallback; join token never logged during source selection.
Ruling: use a dedicated branch and separate assembled source directory, matching this repository's prior release workflow. Implement inline; user has already asked to proceed autonomously.
