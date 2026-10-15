# Contributing to Seam

Thank you for your interest in contributing to Seam.

## Contributor License Agreement

Before your contribution can be accepted, you must sign the [**Arcel Contributor License Agreement (CLA)**](https://github.com/Arcel-Org/cla/blob/main/cla.md). This grants Arcel LLC the right to include your contribution in both the open-source (AGPL v3) and commercial releases of Seam.

Signing is automatic: every pull request runs the CLA bot, which posts a comment telling you exactly what to reply (the standard phrase is "I have read the CLA Document and I hereby sign the CLA"). Contributions cannot be merged until you've signed — or email `legal@arcel.org` to sign out of band.

**Why a CLA?** Seam is dual-licensed. Without a CLA, we cannot include your contribution in commercial releases, which would mean rejecting the PR. The CLA keeps contribution open while preserving our ability to sustain the project commercially.

## Development

```sh
git clone https://github.com/Arcel-Org/Seam
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## Guidelines

- All code must compile with `cargo clippy --all-targets -- -D warnings` (zero warnings)
- Add tests for new functionality in the relevant module
- Cryptographic changes require review from an Arcel maintainer before merge
- Keep commits focused; one logical change per PR

## Security

For security vulnerabilities, open a [private advisory](https://github.com/Arcel-Org/Seam/security/advisories/new) — not a public issue.

## License

By contributing, you agree that your contributions will be licensed under both AGPL v3 and Arcel's commercial license per the CLA.
