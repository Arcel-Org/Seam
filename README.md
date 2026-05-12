<div align="center">

# Seam

**Post-quantum encrypted communications over UDP — written in Rust.**

[![CI](https://github.com/North9-Labs/Seam/actions/workflows/ci.yml/badge.svg)](https://github.com/North9-Labs/Seam/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88+-orange.svg)](#build-from-source)

</div>

```sh
curl -fsSL https://raw.githubusercontent.com/North9-Labs/Seam/main/install.sh | sh
```

Seam replaces `scp`, `netcat`, and `ssh -L` with a single tool that is faster on real-world links and safe against quantum computers. All traffic uses a hybrid Noise\_XX + ML-KEM-768 handshake so session keys cannot be decrypted even if elliptic-curve cryptography is broken in the future.

---

## Why seam

TCP was designed in 1974. SSH was bolted on top. The result is a stack that:

- **Stalls on packet loss** — one lost packet blocks all subsequent data until it is retransmitted (head-of-line blocking)
- **Caps out early on high-latency links** — the congestion window math means a 100 ms RTT link with 0.1% loss can only push ~30% of its nominal bandwidth over TCP
- **Is not quantum-safe** — session keys established today with classical ECDH can be decrypted later once a cryptographically-relevant quantum computer exists

Seam fixes all three.

### Speed comparison

> Measured on loopback (single core, x86\_64). WAN advantage is larger — TCP degrades at high latency and loss where seam does not.

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

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/North9-Labs/Seam/main/install.sh | sh
```

Installs to `~/.local/bin/seam`. Override:

```sh
SEAM_INSTALL_DIR=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/North9-Labs/Seam/main/install.sh | sh
```

The installer verifies a SHA-256 checksum before placing the binary.

---

## Commands

### `seam cp` — file transfer

```sh
# Send a file (zstd-compressed by default)
seam cp ./report.pdf alice@server:/home/alice/report.pdf

# Send a directory
seam cp ./dataset/ alice@server:/data/dataset

# Raw transfer, no compression (already-compressed files)
seam cp --no-compress ./archive.tar.gz alice@server:/backups/
```

seam bootstraps itself on the remote over SSH if it is not already installed — no manual setup on the server side.

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

# Remote port scan (pipe through any tool)
seam pipe alice@server -- nmap -sV 10.0.0.0/24
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

### `seam bench` — throughput test

Measure actual seam speed to a host and compare against known baselines.

```sh
seam bench alice@server          # 100 MiB test
seam bench alice@server --mib 1000
```

```
  ────────────────────────────────────────────────────────────────────
  tool     throughput                            MiB/s   notes
  ────────────────────────────────────────────────────────────────────
  seam     █████████████████████████████████       847   0.706 Gbps  ← measured
  scp      █████████████████░░░░░░░░░░░░░░░░       400   encrypted TCP  (est.)
  rsync    ████████████████░░░░░░░░░░░░░░░░░       380   encrypted TCP  (est.)
  netcat   ██████████████████████████████████░     950   unencrypted TCP  (est.)
  ────────────────────────────────────────────────────────────────────

  seam is 2.1× faster than scp on this path
  post-quantum safe · UDP · FEC recovery · 247 µs handshake
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

1. **SSH bootstrap** — seam uses your existing SSH config to reach the remote, starts a receiver process, and reads back connection parameters. No new ports need to be opened.
2. **Post-quantum handshake** — client and server perform Noise\_XX augmented with ML-KEM-768 in ~247 µs. Each side contributes randomness; neither can force a weak key.
3. **Encrypted UDP transport** — all data flows over a direct UDP path. The transport layer handles loss recovery, ordering, flow control, and multiplexing internally.

### Transport features

| Feature | What it does |
|---|---|
| **CUBIC congestion control** | Fills the pipe without overwhelming routers |
| **ARQ retransmission** | Resends dropped packets with exponential backoff |
| **GF(2⁸) Reed-Solomon FEC** | Recovers up to *r* losses per *k*-packet group without a round-trip |
| **Multi-stream mux** | Tunnel, bench, and pipe share one session; streams are independent |
| **DDoS-resistant handshake** | BLAKE3 cookie challenge before any per-client state is allocated |
| **Header protection** | Session ID and packet number encrypted in addition to payload |

---

## Security

### What is protected

Every byte sent over seam is encrypted with **ChaCha20-Poly1305**, an AEAD cipher with a 256-bit key. The packet header — session ID, packet number, flags — is additionally encrypted so passive observers cannot correlate traffic to sessions.

### The handshake

Seam uses **Noise\_XX** (mutual authentication with forward secrecy) combined with **ML-KEM-768** (CRYSTALS-Kyber, NIST post-quantum standard). The hybrid construction means:

- A classical adversary cannot break the session (x25519 elliptic-curve hardness)
- A quantum adversary cannot break the session (ML-KEM-768 hardness)
- Traffic recorded today cannot be decrypted later even if one primitive is broken in the future

Both parties authenticate with long-term identity keypairs and exchange ephemeral keys for forward secrecy.

### Anti-replay

Each packet carries a 64-bit sequence number. The receiver maintains a sliding bitmap window; duplicate or out-of-window packets are silently dropped. An attacker who captures and replays a packet cannot cause it to be accepted a second time.

### DDoS resistance

The server commits no per-client memory until the client echoes a valid BLAKE3 cookie that is tied to its source IP and expires after 30 seconds. This prevents an attacker from exhausting server memory by spoofing connection requests.

### Honest disclaimer

Seam is pre-1.0 software. The cryptographic design follows well-established patterns and uses audited primitives, but the protocol itself has not undergone a third-party security audit. Do not use it where your threat model requires independently audited software.

---

## Build from Source

```sh
# Prerequisites: Rust 1.88+
git clone https://github.com/North9-Labs/Seam
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

---

## Library Usage

```toml
# Cargo.toml
seam-protocol = { git = "https://github.com/North9-Labs/Seam" }
```

### Client / Server

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

### Multiplexed streams

Streams implement `AsyncRead + AsyncWrite + Unpin` and compose directly with tokio I/O utilities.

```rust
use seam_protocol::tunnel::SeamMux;

let mux = SeamMux::new(conn);  // wraps a SeamConn

// Open a stream from either side
let mut stream = mux.open_stream().await;           // locally-initiated
let mut stream = mux.accept_stream().await.unwrap(); // remote-initiated

// Drop in anywhere tokio I/O is expected
tokio::io::copy_bidirectional(&mut stream, &mut tcp_socket).await?;
```

### Datagrams

```rust
// Unreliable, unordered — useful for real-time data
conn.send_datagram(b"ping").await?;
```

---

## Performance

> Single-core, loopback, x86\_64. Numbers vary with hardware and kernel UDP buffer limits.

**568 MiB/s (~4.76 Gbps) encrypted throughput at 1400 B MTU. 247 µs full Noise\_XX + ML-KEM-768 handshake.**

| Payload size | Encrypt + send | Throughput |
|---|---:|---:|
| 64 B | 350 ns | ~303 MiB/s |
| 256 B | 644 ns | ~455 MiB/s |
| 512 B | 1.03 µs | ~519 MiB/s |
| 1400 B | 2.43 µs | **~568 MiB/s** |

| Operation | Time |
|---|---:|
| `IdentityKeypair::generate` | 17.8 µs |
| `PacketKeys::derive_from_secret` | 370 ns |
| Full handshake (Noise\_XX + ML-KEM-768, 3 messages) | **247 µs** |

---

## Repository Layout

```
src/
├── api.rs          # Client, Server, SeamConn
├── tunnel.rs       # SeamMux + SeamStream (AsyncRead + AsyncWrite)
├── crypto/         # ChaCha20-Poly1305, header protection, anti-replay
├── handshake/      # Noise_XX + ML-KEM-768, DDoS-resistant cookie
├── session/        # Streams, ARQ, flow control, priority scheduling
├── fec/            # GF(2⁸) arithmetic, systematic RS codec, FEC/ARQ arbiter
└── transport/      # Connection, endpoint, CUBIC CC, pacer, path probing

benches/            # Criterion benchmarks
fuzz/               # cargo-fuzz targets
```

---

## License

Seam is dual-licensed:

- **Open source:** [GNU Affero General Public License v3.0](LICENSE) — free for open source projects and personal use
- **Commercial:** contact [licensing@north9.org](mailto:licensing@north9.org) for proprietary, SaaS, government, or OEM use

See [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) for details.
