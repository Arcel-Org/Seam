<div align="center">

# Seam

**Post-quantum encrypted communications over UDP — written in Rust.**

[![CI](https://github.com/Arcel-Org/Seam/actions/workflows/ci.yml/badge.svg)](https://github.com/Arcel-Org/Seam/actions/workflows/ci.yml)
[![Dependency Audit](https://github.com/Arcel-Org/Seam/actions/workflows/security.yml/badge.svg)](https://github.com/Arcel-Org/Seam/actions/workflows/security.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88+-orange.svg)](#build-from-source)

</div>

```sh
curl -fsSL https://install.arcel.org/seam.sh | sh
```

Seam replaces `scp`, `netcat`, `ssh -L`, and `rsync` with a single tool that is faster on real-world links and safe against quantum computers. All traffic uses a hybrid Noise_XX + ML-KEM-768 handshake so session keys cannot be decrypted even if elliptic-curve cryptography is broken in the future.

---

## Why Seam

TCP was designed in 1974. SSH was bolted on top. The result is a stack that:

- **Stalls on packet loss** — one lost packet blocks all subsequent data until it is retransmitted (head-of-line blocking)
- **Caps out early on high-latency links** — the congestion window math means a 100 ms RTT link with 0.1% loss can only push ~30% of its nominal bandwidth over TCP
- **Is not quantum-safe** — session keys established today with classical ECDH can be decrypted later once a cryptographically-relevant quantum computer exists

Seam fixes all three.

### Speed comparison

> Measured on loopback (single core, x86_64). WAN advantage is larger — TCP degrades at high latency and loss where seam does not.

| | seam | scp (OpenSSH) | rsync over SSH | netcat (no encryption) |
|---|---:|---:|---:|---:|
| **Encrypted throughput** | **568 MiB/s** | ~400 MiB/s | ~380 MiB/s | n/a |
| **Handshake latency** | **247 µs** | ~10 ms | ~10 ms | ~1 ms |
| **Quantum-safe** | ✅ ML-KEM-768 | ❌ | ❌ | ❌ |
| **Head-of-line blocking** | none (UDP + FEC) | yes | yes | yes |
| **High-latency WAN** | ✅ approaches line rate | degrades | degrades | degrades |
| **Multi-stream mux** | ✅ | ❌ | ❌ | ❌ |

seam transfers the same data in about 30% less wall time than scp on a clean local link. On a WAN path with 100 ms RTT and 0.5% loss the gap widens to 2–4×, because seam's forward error correction absorbs most lost packets without a round-trip retransmit.

---

## How Seam compares

| Feature | Seam | WireGuard | SSH | QuSecure QuProtect |
|---|---|---|---|---|
| Post-quantum KEM | ✅ ML-KEM-768 (FIPS 203) | ❌ | ❌ | ✅ |
| PQ identity signing | ✅ ML-DSA-65 (FIPS 204) | ❌ | ❌ | Unknown |
| Transport protocol | UDP (custom) | UDP | TCP | Varies |
| Head-of-line blocking | None (FEC) | None | Yes | Unknown |
| Forward secrecy | ✅ Double ratchet | ✅ per-session | ✅ per-session | Unknown |
| Traffic analysis resistance | ✅ padding + chaff + jitter | ❌ | ❌ | ❌ |
| Multi-path anti-jamming | ✅ PathScheduler | ❌ | ❌ | ❌ |
| Session resumption | ✅ zero-RTT | ❌ | ❌ | Unknown |
| FIPS mode | ✅ --fips-mode | ❌ | Partial | ✅ |
| Audit logging (SP 800-53) | ✅ | ❌ | Partial | Unknown |
| Open source | ✅ AGPL-3.0 | ✅ MIT | ✅ | ❌ closed |
| Air-gap traversal | ✅ --via relay | ❌ | ❌ | ❌ |
| File transfer built-in | ✅ seam cp/sync/share | ❌ | ✅ scp | ❌ |
| Live directory sync | ✅ seam watch | ❌ | ❌ | ❌ |
| Multi-hop routing | ✅ seam route | ❌ | ❌ | ❌ |
| NAT hole punching | ✅ seam punch | ❌ | ❌ | ❌ |
| Port scanner built-in | ✅ seam scan | ❌ | ❌ | ❌ |
| Proxy (SOCKS5) built-in | ✅ seam proxy | ❌ | ✅ | ❌ |
| FUSE filesystem | ✅ seam mount | ❌ | ❌ | ❌ |
| Interactive TUI | ✅ | ❌ | ❌ | ❌ |

---

## Install

```sh
curl -fsSL https://install.arcel.org/seam.sh | sh
```

Installs to `~/.local/bin/seam`. Override:

```sh
SEAM_INSTALL_DIR=/usr/local/bin curl -fsSL https://install.arcel.org/seam.sh | sh
```

The installer verifies a SHA-256 checksum before placing the binary.

### Shell completions

```sh
seam completions bash > /etc/bash_completion.d/seam   # system-wide
seam completions zsh  > ~/.zsh/completions/_seam       # user
seam completions fish > ~/.config/fish/completions/seam.fish
```

### First-time setup

```sh
seam doctor          # check system readiness
```

Seam respects your `~/.ssh/config` (Host aliases, User, Port, IdentityFile) and stores a persistent identity key in `~/.config/seam/identity` so peers can recognise you across sessions.

---

## Interactive TUI

Run `seam` with no arguments to launch the interactive terminal UI:

```sh
seam
```

```
╭─ Seam ───────────────────────────── v1.0.1 ─╮  ╭─ Actions ──────────────────╮
│  Host  alice@server.example.com             │  │  1 ⬆  Copy file/dir        │
│                                             │  │  2 ⬇  Sync directory       │
╰─────────────────────────────────────────────╯  │  3 ⧎  Open tunnel          │
                                                  │  4 ↔  Pipe / remote shell  │
╭─ Param ─────────────────────────────────────╮  │  5 📊 Stats                │
│  ./report.pdf → :/home/alice/report.pdf     │  │  6 🔬 Bench                │
╰─────────────────────────────────────────────╯  │  7 📁 List remote          │
                                                  │  w 👁 Watch directory      │
╭─ Recent ────────────────────────────────────╮  │  p 🔌 Proxy (SOCKS5)      │
│  ✓ cp ./data.tar.gz → alice@server:/backups │  │  r 🛤  Route (multi-hop)   │
│  ✓ tunnel 5432 → db.internal:5432           │  │  m 🗻 Mount (FUSE)         │
│  ✗ cp ./large.iso → alice@server:/data      │  ╰────────────────────────────╯
╰─────────────────────────────────────────────╯
```

**Keyboard shortcuts:**

| Key | Action |
|---|---|
| `1`–`9`, `w`, `p`, `r`, `m` | Jump directly to an action |
| `Tab` / `Shift-Tab` | Cycle focus: Host → Actions → Param → Recent |
| `↑↓` / `j k` | Move in action/recent list |
| `Enter` | Run command or re-run a recent entry |
| `?` | Toggle help overlay |
| `Esc` / `q` | Quit |

---

## Commands

### `seam cp` — file transfer

```sh
# Send a file (zstd-compressed by default)
seam cp ./report.pdf alice@server:/home/alice/report.pdf

# Send a directory
seam cp ./dataset/ alice@server:/data/dataset

# Receive from remote (pull)
seam cp alice@server:/remote/logs ./local-backup/

# Resume an interrupted transfer
seam cp --resume ./large.iso alice@server:/data/

# Raw transfer, no compression (already-compressed files)
seam cp --no-compress ./archive.tar.gz alice@server:/backups/
```

seam bootstraps itself on the remote over SSH if it is not already installed — no manual setup on the server side. The bootstrap uses a pure-Rust SSH implementation with no dependency on a system `ssh` binary.

---

### `seam watch` — live directory sync

Watch a local directory for changes and sync them to a remote host in real time. Debounces rapid edits into batches with a 100 ms window.

```sh
seam watch ./src alice@server:/app/src

# Adjust debounce window
seam watch ./config alice@server:/etc/app --debounce-ms 250
```

Useful for live development against a remote machine — edit locally, code runs remotely.

---

### `seam share` — one-time encrypted file sharing

Start a local seam receiver, generate a one-time auth token, and print a ready-to-run `seam cp` command for the recipient. The server shuts down automatically after the download completes.

```sh
# Share a single file (auto-expires after 1 download)
seam share ./report.pdf

# Share a directory, allow 3 downloads, expire after 2 hours
seam share ./dataset/ --times 3 --expire 2h
```

Output:
```
  seam share  report.pdf  (1 download · expires never)
  ──────────────────────────────────────────────────────
  Recipient runs:
    seam cp --token abc123... 203.0.113.5:59241:/report.pdf ./

  Waiting for connection…
```

---

### `seam sync` — incremental directory sync

```sh
# Push local changes to remote (rsync-style)
seam sync ./dataset/ alice@server:/data/dataset

# Pull remote to local
seam sync alice@server:/data/dataset ./dataset/
```

---

### `seam pipe` — bidirectional pipe

Netcat, but post-quantum encrypted and fast.

```sh
# Open a remote shell
seam pipe alice@server -- bash

# Run a command, stream its output locally
seam pipe alice@server -- journalctl -f

# Pipe data between machines
tar cf - ./project | seam pipe alice@server -- tar xf - -C /dest
```

---

### `seam tunnel` — TCP port forward

SSH `-L`, but over seam's UDP transport. Multiple concurrent connections share one post-quantum session.

```sh
# Forward local:8080 → server:localhost:3000
seam tunnel 8080:alice@server:3000

# Access a private database through a jump host
seam tunnel 5432:alice@server:db.internal:5432

# Then connect normally — seam is invisible
psql -h localhost -p 5432 -U myuser mydb
```

---

### `seam fwd` — reverse port forward

Expose a port from a remote machine back to your local machine. Like `ssh -R` over seam's UDP transport — works through double-NAT.

```sh
# Remote server listens on :3000, forwards connections to local :8080
seam fwd alice@server:3000 8080

# Expose a local dev service to a remote machine
seam fwd alice@bastion:9090 8080 --local-host 0.0.0.0
```

---

### `seam route` — multi-hop routing

Build a chain of encrypted hops through intermediate seam relay nodes. Useful for reaching isolated networks or when direct connections are not possible.

```sh
# Two-hop: local → relay1 → dest
seam route --via relay1.example.com alice@dest cp ./file :/remote/path

# Three-hop: local → relay1 → relay2 → dest
seam route --via relay1.example.com --via relay2.example.com alice@dest shell "uptime"
```

Each intermediate node must have `seam serve` running. The connection is end-to-end post-quantum encrypted — intermediate hops see only ciphertext.

---

### `seam punch` — NAT hole punching

Discover your external address via STUN and optionally punch a UDP hole to a peer behind NAT so a direct seam connection can be established.

```sh
# Discover external address (STUN lookup only)
seam punch --stun stun.l.google.com:19302

# Punch a hole to a peer
seam punch --peer 203.0.113.5:4433 --stun stun.l.google.com:19302
```

Used as a building block for peer-to-peer seam connections through symmetric NAT.

---

### `seam mount` — FUSE filesystem

Mount a remote directory as a local filesystem. Requires FUSE to be available on the host.

```sh
seam mount alice@server:/data /mnt/remote
# Files appear at /mnt/remote, all I/O is post-quantum encrypted
fusermount -u /mnt/remote
```

---

### `seam daemon` — background daemon

Run a seam daemon process that manages persistent connections and listens on a local socket.

```sh
seam daemon start    # start daemon in background
seam daemon status   # check running state
seam daemon stop     # stop daemon
```

---

### `seam proxy` — SOCKS5 proxy

Turn any seam remote into a SOCKS5 proxy. Route browser or app traffic through a remote host over post-quantum encryption.

```sh
seam proxy alice@server --local-port 1080
# Configure applications to use SOCKS5 proxy at 127.0.0.1:1080
```

---

### `seam stats` — connection statistics

```sh
seam stats alice@server          # 5-second measurement window
seam stats alice@server --duration 10
```

```
  Seam connection stats  alice@server  (5s window)
  ─────────────────────────────────────────────────
  RTT           min 44ms  avg 51ms  max 79ms
  Throughput    recv 234 MiB/s
  Path MTU      1400 bytes
  cwnd          512 KiB
```

---

### `seam bench` — throughput test

```sh
seam bench alice@server          # 100 MiB test
seam bench alice@server --mib 1000
SEAM_CC=bbr seam bench alice@server   # test with BBR congestion control
```

---

### `seam scan` — port scanner

```sh
seam scan alice@server 10.0.0.0/24    # scan via remote pivot
seam scan alice@server --ports 22,80,443,8080
```

---

### `seam ls` — remote directory listing

```sh
seam ls alice@server:/var/log
```

---

### `seam config` — persistent settings

```sh
seam config init                  # create ~/.config/seam/config.toml
seam config list                  # show all settings
seam config set cc bbr            # switch default congestion control
seam config set compress false    # disable zstd by default
```

---

### `seam update` — self-update

```sh
seam update           # download and replace the binary
seam update --check   # just print available version
```

---

## How It Works

Every seam command follows the same pattern:

1. **SSH bootstrap** — seam uses your existing SSH config to reach the remote, starts a receiver process, and reads back connection parameters. No new ports need to be opened. A pure-Rust SSH implementation means no system `ssh` dependency is required.
2. **Post-quantum handshake** — client and server perform Noise_XX augmented with ML-KEM-768 in ~247 µs. Each side contributes randomness; neither can force a weak key.
3. **Encrypted UDP transport** — all data flows over a direct UDP path. The transport layer handles loss recovery, ordering, flow control, and multiplexing internally.

### Transport features

| Feature | What it does |
|---|---|
| **CUBIC congestion control** | Fills the pipe without overwhelming routers (switch to BBR with `SEAM_CC=bbr`) |
| **ARQ retransmission** | Resends dropped packets with exponential backoff |
| **GF(2⁸) Reed-Solomon FEC** | Recovers up to *r* losses per *k*-packet group without a round-trip; adapts overhead dynamically via EWMA loss tracking |
| **Adaptive FEC arbiter** | Pure ARQ on clean links, hybrid FEC+ARQ at moderate loss, pure FEC above 15% loss; automatically adds light FEC on high-latency paths (RTT > 100 ms) |
| **Buffer pool** | 256-slot RAII pool for 1400 B UDP payload buffers — eliminates per-packet heap allocation on the hot path |
| **Multi-stream mux** | Tunnel, bench, and pipe share one session; streams are independent |
| **DDoS-resistant handshake** | BLAKE3 cookie challenge before any per-client state is allocated |
| **Header protection** | Session ID and packet number encrypted in addition to payload |
| **Flow control** | Dynamic 16 MiB windows extended via MaxData frames |
| **Connection migration** | PathChallenge/PathResponse for IP/port change without session reset |
| **Keepalive** | Automatic Ping/Pong every 15 s; idle timeout after 60 s |
| **Pure-Rust SSH** | Bootstrap SSH with no system `ssh` dependency; falls back to system ssh on failure |

---

## Security

### What is protected

Every byte sent over seam is encrypted with **ChaCha20-Poly1305**, an AEAD cipher with a 256-bit key. The packet header — session ID, packet number, flags — is additionally encrypted so passive observers cannot correlate traffic to sessions.

### The handshake

Seam uses **Noise_XX** (mutual authentication with forward secrecy) combined with **ML-KEM-768** (CRYSTALS-Kyber, NIST FIPS 203 post-quantum standard). The hybrid construction means:

- A classical adversary cannot break the session (x25519 elliptic-curve hardness)
- A quantum adversary cannot break the session (ML-KEM-768 hardness)
- Traffic recorded today cannot be decrypted later even if one primitive is broken in the future

Identity keys are signed with **ML-DSA-65** (NIST FIPS 204). Forward secrecy is maintained through a **double ratchet** that rotates keys on every packet.

### Supply chain security

Seam runs `cargo audit` in CI on every push. As of v1.0.1, no unresolved `cargo audit` findings — one transitive dependency (`anyhow`, pulled in via the TUI's terminal backend) carries an allowed advisory with no fix released upstream yet.

### Anti-replay

Each packet carries a 64-bit sequence number. The receiver maintains a sliding bitmap window; duplicate or out-of-window packets are silently dropped.

### DDoS resistance

The server commits no per-client memory until the client echoes a valid BLAKE3 cookie that is tied to its source IP and expires after 30 seconds.

### Honest disclaimer

Seam is v1.0 software. The cryptographic design follows well-established patterns and uses audited primitives, but the protocol itself has not yet undergone an independent third-party security audit. Do not use it where your threat model requires independently audited software.

---

## Troubleshooting

### "handshake timed out"
- Seam automatically retries the handshake up to 3 times with exponential backoff.
- If it still fails, check that UDP is not blocked by a firewall.
- Increase kernel socket buffers:
  ```sh
  sudo sysctl -w net.core.rmem_max=8388608
  sudo sysctl -w net.core.wmem_max=8388608
  ```

### "seam not found on remote"
- seam bootstraps automatically, but if the remote has no internet access, copy the binary manually to `~/.local/bin/seam`.

### Slow throughput on LAN
- seam is optimised for lossy / high-latency paths. On pristine LAN, scp may be similar. Use `seam bench` to verify.

### Verbose logging
```sh
seam -v cp ./data user@host:/dest    # info
seam -vv cp ./data user@host:/dest   # debug
seam -vvv cp ./data user@host:/dest  # trace
```

---

## Build from Source

```sh
# Prerequisites: Rust 1.88+
git clone https://github.com/Arcel-Org/Seam
cd Seam
cargo build --release --bin seam
./target/release/seam --version
```

Test suite:

```sh
cargo test
```

Benchmarks (Criterion, single-core loopback):

```sh
cargo bench
```

Fuzz targets:

```sh
cargo install cargo-fuzz
cargo fuzz run packet_decode
```

FUSE support (Linux only):

```sh
cargo build --release --features fuse
```

---

## Library Usage

```toml
# Cargo.toml
seam-protocol = { git = "https://github.com/Arcel-Org/Seam" }
```

```rust
use seam_protocol::{api::{Client, Server}, handshake::IdentityKeypair};

// Server — bind and wait for a connection
let id = IdentityKeypair::generate();
let mut server = Server::bind("0.0.0.0:4433".parse()?, id).await?;
let conn = server.accept().await.unwrap();

// Client — connect to the server
let id = IdentityKeypair::generate();
let client = Client::bind("0.0.0.0:0".parse()?, id).await?;
let conn = client.connect(server_addr, &server_x25519, &server_kem_pk).await?;
```

Streams implement `AsyncRead + AsyncWrite + Unpin` and compose directly with tokio I/O utilities:

```rust
use seam_protocol::tunnel::SeamMux;

let mux = SeamMux::new(conn);
let mut stream = mux.open_stream().await;
tokio::io::copy_bidirectional(&mut stream, &mut tcp_socket).await?;
```

---

## Performance

> Single-core, loopback, x86_64. Numbers vary with hardware and kernel UDP buffer limits.

**568 MiB/s (~4.76 Gbps) encrypted throughput at 1400 B MTU. 247 µs full Noise_XX + ML-KEM-768 handshake.**

| Payload size | Encrypt + send | Throughput |
|---|---|---:|
| 64 B | 350 ns | ~303 MiB/s |
| 256 B | 644 ns | ~455 MiB/s |
| 512 B | 1.03 µs | ~519 MiB/s |
| 1400 B | 2.43 µs | **~568 MiB/s** |

| Operation | Time |
|---|---:|
| `IdentityKeypair::generate` | 17.8 µs |
| `PacketKeys::derive_from_secret` | 370 ns |
| Full handshake (Noise_XX + ML-KEM-768, 3 messages) | **247 µs** |

---

## Repository Layout

```
src/
├── api.rs              # Client, Server, SeamConn
├── bufpool.rs          # 256-slot RAII buffer pool (eliminates per-packet allocation)
├── tunnel.rs           # SeamMux + SeamStream (AsyncRead + AsyncWrite)
├── crypto/             # ChaCha20-Poly1305, header protection, anti-replay
├── handshake/          # Noise_XX + ML-KEM-768, DDoS-resistant cookie
├── session/            # Streams, ARQ, flow control, priority scheduling
├── fec/                # GF(2⁸) arithmetic, systematic RS codec, adaptive FEC/ARQ arbiter
└── transport/
    ├── connection.rs   # Connection state machine, path migration
    ├── endpoint.rs     # Multi-connection endpoint
    ├── nat.rs          # STUN client (RFC 5389), UDP hole punching
    └── ...             # CUBIC/BBR CC, pacer

src/bin/seam/
├── main.rs             # CLI entry point, interactive TUI launcher
├── tui.rs              # ratatui interactive TUI (keyboard-driven)
├── copy.rs             # seam cp (with pure-Rust SSH bootstrap)
├── watch.rs            # seam watch (filesystem event watcher, 100ms debounce)
├── share.rs            # seam share (one-time file sharing, token auth)
├── sync.rs             # seam sync (incremental directory sync)
├── pipe.rs             # seam pipe
├── tunnel.rs           # seam tunnel (local port forward)
├── fwd.rs              # seam fwd (reverse port forward)
├── route.rs            # seam route (multi-hop through relay nodes)
├── punch.rs            # seam punch (STUN + NAT hole punching)
├── mount.rs            # seam mount (FUSE filesystem, --features fuse)
├── daemon.rs           # seam daemon (background process, subprocess-based)
├── proxy.rs            # seam proxy (SOCKS5)
├── bench.rs            # seam bench (throughput test)
├── stats.rs            # seam stats (live connection metrics)
├── scan.rs             # seam scan (port scanner)
├── ls.rs               # seam ls (remote file listing)
├── russh_client.rs     # pure-Rust SSH (russh 0.61, no system ssh required)
└── config.rs           # seam config

benches/                # Criterion benchmarks
fuzz/                   # cargo-fuzz targets
```

---

## License

Seam is dual-licensed:

- **Open source:** [GNU Affero General Public License v3.0](LICENSE) — free for open source projects and personal use
- **Commercial:** contact [licensing@arcel.org](mailto:licensing@arcel.org) for proprietary, SaaS, government, or OEM use

See [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) for details.
