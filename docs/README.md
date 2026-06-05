# Seam Documentation

**Seam** is a post-quantum UDP transport library and CLI tool written in Rust.
It replaces `scp`, `netcat`, and `ssh -L` with a single binary that is faster
on real-world links and safe against quantum computers.

Version: **0.1.32** — pre-1.0, no third-party security audit yet.

---

## Documentation Index

| Document | Description |
|---|---|
| [getting-started.md](getting-started.md) | Installation, first-time setup, and a quick walkthrough |
| [cli-reference.md](cli-reference.md) | Every subcommand with all flags and examples |
| [architecture.md](architecture.md) | Protocol stack, handshake sequence, packet format, session lifecycle |
| [security.md](security.md) | Cryptographic algorithm choices and their justifications |
| [fips-mode.md](fips-mode.md) | FIPS-140 compliant mode: what changes, how to enable it |
| [deployment.md](deployment.md) | Running `seam serve` in production, systemd, auth-keys, monitoring |
| [government-compliance.md](government-compliance.md) | CNSA 2.0 mapping, audit log compliance, FedRAMP notes |
| [threat-model.md](threat-model.md) | Formal threat model (adversary model, attack surface, security properties) |

---

## What Seam Does

Every seam command uses the same underlying connection model:

1. **SSH bootstrap** — seam uses your existing SSH config to reach the remote, starts a receiver process, and reads back UDP connection parameters over the SSH channel. No new inbound ports need to be opened on the server.
2. **Post-quantum handshake** — client and server perform a Noise_XX handshake augmented with ML-KEM-768 in approximately 247 µs. Each side contributes randomness; neither can force a weak key.
3. **Encrypted UDP transport** — all data flows over a direct UDP path with built-in loss recovery (ARQ + FEC), flow control, multiplexing, and header protection.

Alternatively, `seam serve` runs a standalone daemon that eliminates the SSH dependency entirely.

## Why UDP

TCP's head-of-line blocking means one lost packet stalls all subsequent data on the connection until the retransmit arrives. On a 100 ms RTT link with 0.1% loss, TCP's congestion window math caps usable bandwidth at roughly 30% of the nominal link rate. Seam's GF(2⁸) Reed-Solomon FEC recovers most lost packets without a retransmit round-trip; the adaptive FEC arbiter switches between pure ARQ, hybrid FEC+ARQ, and pure FEC based on observed loss rate and RTT.

## Quick Reference

```sh
# Installation
curl -fsSL https://install.north9.org/seam.sh | sh

# System readiness check
seam doctor

# File transfer (push)
seam cp ./report.pdf alice@server:/home/alice/report.pdf

# Directory sync
seam sync ./project/ alice@server:/srv/project

# Interactive shell
seam shell alice@server

# TCP port forward (local 8080 → remote localhost:3000)
seam forward 8080:localhost:3000 alice@server

# Throughput benchmark
seam bench alice@server

# Self-update
seam update
```

## License

Seam is dual-licensed:

- **Open source:** GNU Affero General Public License v3.0
- **Commercial / Government / SaaS:** contact [licensing@north9.org](mailto:licensing@north9.org)
