# Self-Protection, Tamper Resistance, Performance, Compatibility, Recovery & Forensics

## Self-Protection & Tamper Resistance
- Driver is EV-signed, PPL-protected (Windows), locked by IMA (Linux), notarized + hardened runtime (macOS)
- Unload gate: TPM-signed token required to disable
- Watchdog: auto-restart broker; memory integrity (HVCI) compatible
- Update: dual-signed, staged rollout, rollback with attested state

## Performance & Compatibility
- ≤ 1 µs overhead per open (Ed25519) → ≥ 100k ops/s/core
- ≤ 1 ms overhead (Dilithium) → ≥ 1k ops/s/core
- Zero-copy token cache → O(1) lookup
- Compatible with: Office 365, VS Code, Adobe, Docker, SQL Server, Xcode, Lightroom (entropy-bypass + quota)
- Network shares: enforce on server side (SMB/NFS) with SID/UID mapping

## Recovery & Forensics
- Instant “revert to read-only” button → kills offending PIDs, network isolates host
- Forensic bundle export: policy snapshot, process tree, token log, key epoch, Merkle proofs
- Offline verify tool → proves folder never written without token

## Editions
- Personal: 1 PC, local broker, 1 dongle, Ed25519
- Business: unlimited endpoints, central broker HA, SIEM feed, hybrid PQC, MDM plug-in
- Server: cluster broker, CSV/SMB gateway, WORM-archive mode, API for backup software

## Roadmap
- Content-aware ML → advisory score to reduce prompts
- Honey-file trip-wire → early alert
- Decentralised broker (blockchain anchor) → no single CA
- Light-weight PQC (NIST round-2) → smaller sigs
