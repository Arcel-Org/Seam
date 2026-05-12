# Contributing to Seam

Thank you for your interest in contributing to Seam.

## Contributor License Agreement

Before your contribution can be accepted, you must sign the **North9 Contributor License Agreement (CLA)**. This grants North9 LLC the right to include your contribution in both the open-source (AGPL v3) and commercial releases of Seam.

The CLA is managed automatically via [CLA Assistant](https://cla-assistant.io/). When you open a pull request, a bot will check your CLA status and prompt you to sign if you haven't already.

**Why a CLA?** Seam is dual-licensed. Without a CLA, we cannot include your contribution in commercial releases, which would mean rejecting the PR. The CLA keeps contribution open while preserving our ability to sustain the project commercially.

## Development

```sh
git clone https://github.com/North9-Labs/Seam
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## Guidelines

- All code must compile with `cargo clippy --all-targets -- -D warnings` (zero warnings)
- Add tests for new functionality in the relevant module
- Cryptographic changes require review from a North9 maintainer before merge
- Keep commits focused; one logical change per PR

## Security

For security vulnerabilities, open a [private advisory](https://github.com/North9-Labs/Seam/security/advisories/new) — not a public issue.

## License

By contributing, you agree that your contributions will be licensed under both AGPL v3 and North9's commercial license per the CLA.
