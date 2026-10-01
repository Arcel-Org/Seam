# Changelog

All notable changes to Seam are documented here.

## [1.1.0] - 2026-10-01

### Added
- **Real FUSE backend for `seam mount`** (read-only, `--features fuse`): whole-file reads via a `fuser`-based filesystem instead of a stub.
- **`seam cp --multipath-redundant`**: send on all paths simultaneously, receiver deduplicates — anti-jamming / packet-level redundancy for the multipath engine.
- Dockerfile for `seam serve` (`.dockerignore`, deployment docs).
- Crate metadata (description, repository, keywords, categories).

### Fixed
- **Critical crypto / transport correctness:**
  - Derive the hybrid X25519 component from real DH secret material (not a placeholder).
  - Don't commit the replay window before AEAD auth succeeds.
  - `seam share` had a full auth bypass; `seam cp` pull direction never worked — both fixed.
  - Degenerate Cauchy matrix entry could silently corrupt or panic (FEC).
  - Bound `AckRanges` memory on long-lived sessions; bound sync manifest entry count.
  - Two unbounded-resource DoS findings from the security audit.
- **Audit findings (CLI + transport):** 4 HIGH (TUI key leak, TUI push/pull footgun, `ls` alias resolution, russh MITM bypass) and 8 MEDIUM.
- `route.rs` UDP proxy socket/task leak; `known_hosts` TOCTOU race.
- PTY reap deadlock in `seam serve`/`shell` on abrupt disconnect.
- `tui.rs` `trunc()` panic on non-ASCII text at a UTF-8 char boundary.
- `doctor.rs` config-key allowlist drift; documented `send.rs --once` no-op.
- Bump russh 0.61.2 → 0.62.5 (resolves 4 Dependabot advisories); port to fuser 0.17.
- rustls → 0.23.45 (resolves RUSTSEC-2026-0285).
- CI: build/test/lint the fuse feature for real; clippy/format fixes for newer toolchains.

### Docs
- `SECURITY.md`, deployment docs, README correctness pass (documented 8 missing CLI subcommands, fixed stale crypto/multipath claims).
