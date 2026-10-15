# Changelog

All notable changes to Seam are documented here.

## [1.1.2] - 2026-10-14

### Security

- **Dependency security + currency update** (184 crates):
  - rustls 0.23.45 → 0.23.46 (RUSTSEC-2026-0346..0349: `Debug` leaks TLS
    secrets, ServerHello classical-key-exchange downgrade, Brotli
    pre-auth 1 GiB alloc, ECH rejection data leak)
  - anyhow 1.0.102 → 1.0.103 (RUSTSEC-2026-0190: `downcast_mut` unsoundness)
  - lru 0.18.0 → 0.18.2 (RUSTSEC-2026-0253: `LruCache::pop` use-after-free)
  - chacha20 0.10.1 → 0.10.2, der 0.8.0 → 0.8.2, wnaf 0.14.0 → 0.14.1 (yanked)
  - argon2 0.6.0-rc.8 → 0.6.0 stable, aws-lc-rs/aws-lc-sys bumps, and more
  - `cargo audit` now clean (0 vulnerabilities / 0 warnings).

### Changed

- **Multipath flags on single-session commands now fail loudly instead of
  being silently ignored.** `--multipath`/`--multipath-redundant` on
  `shell`, `forward`, `ping` and `serve` previously printed a warning and
  then transferred over a single path — implying anti-jamming redundancy
  the user wasn't getting. They now error out, because those commands
  establish a single session and cannot shard a stream across independent
  connections the way `seam cp` (connection-level multipath) does. True
  packet-level scheduling within a single session remains documented
  follow-up work (it requires the server to associate one session with
  several source addresses).

## [1.1.1] - 2026-10-01

### Security

- Upgrade russh 0.62.5 → 0.63.3 and pageant → 0.2.3, resolving six
  Dependabot advisories:
  - GHSA-35g8-35p8-c8fw (unbounded memory exhaustion via CHANNEL_OPEN flood)
  - GHSA-p8qx-h547-fjw9 (MAC-none block-cipher slice-index out-of-range panic)
  - GHSA-47hw-gvq5-r2gm (channel-scoped Handler callbacks for unopened channels)
  - GHSA-w3jg-pjxf-73p4 (missing X25519 zero-point validation in hybrid ML-KEM kex)
  - GHSA-g6xm-f9xp-qq35 (client auth-attempt cap not enforced)
  - GHSA-g4mp-vgx3-xrvm (pageant OOB read/oversized alloc on Windows)
- Adapt to russh 0.63 `check_server_key` signature (`&PublicKey` →
  `&PublicKeyOrCertificate`): Seam pins raw host keys only and rejects
  server host certificates.

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
