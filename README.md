<div align="center">

# Seam

**Post-quantum encrypted transport protocol — written in Rust.**

UDP · Multi-stream · Built-in FEC · Noise_XX + ML-KEM-768

[![CI](https://github.com/North9-Labs/Seam/actions/workflows/ci.yml/badge.svg)](https://github.com/North9-Labs/Seam/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88+-orange.svg)](#getting-started)

</div>

---

Seam is a user-space transport protocol for applications where TCP or QUIC leave performance on the table. It delivers encrypted, paced UDP with multi-stream multiplexing, forward error correction, and a hybrid post-quantum handshake in a single library.

| Capability | Detail |
|---|---|
| Transport | UDP with CUBIC congestion control + token-bucket pacing |
| Encryption | ChaCha20-Poly1305 packet encryption + header protection |
| Handshake | Noise_XX + ML-KEM-768 (post-quantum hybrid, 247 µs) |
| Reliability | ARQ + GF(2⁸) forward error correction |
| Multiplexing | Priority-scheduled streams (0–7, 0 = highest) |

---

## Why Seam

- **No head-of-line blocking.** Streams are scheduled independently — a stalled bulk transfer never delays a control message.
- **Post-quantum by default.** ML-KEM-768 is baked into the handshake. Harvest-now-decrypt-later attacks can't reach session keys.
- **FEC at the transport layer.** Packet loss is recovered locally without a round-trip retransmit.
- **Paced, not bursty.** Token-bucket pacer at `cwnd/srtt` bytes/sec eliminates the burst-driven queue buildup that plagues raw UDP.
- **DDoS-resistant handshake.** Stateless cookie challenge — no heap allocation until the client proves it can receive at the claimed address.

---

## Performance

> Single-core, local measurements. Hardware and compiler dependent.

**568 MiB/s (~4.76 Gbps) encrypted throughput per core at 1400 B MTU. 247 µs full handshake including ML-KEM-768.**

### Packet encode — ChaCha20-Poly1305 + header protection

| Payload | Time | Throughput |
|---|---:|---:|
| 64 B | 350 ns | ~303 MiB/s |
| 256 B | 644 ns | ~455 MiB/s |
| 512 B | 1.03 µs | ~519 MiB/s |
| 1400 B | 2.43 µs | **~568 MiB/s** |

### FEC encode/recover — 1400 B symbols

| Config | Encode | Recover 1 loss |
|---|---:|---:|
| k=4, r=1 | ~5.5 µs | ~10.4 µs |
| k=8, r=2 | ~11 µs | ~21 µs |
| k=10, r=3 | ~16 µs | ~32 µs |

### Handshake — Noise_XX + ML-KEM-768

| Operation | Time |
|---|---:|
| `IdentityKeypair::generate` | 17.8 µs |
| `PacketKeys::derive_from_secret` | 370 ns |
| `CookieFactory::generate` | 91 ns |
| `CookieFactory::verify` | 88 ns |
| **Full handshake (3 messages)** | **247 µs** |

### Session flush throughput

| Payload | 1 stream | 4 streams (equal) | 4 streams (mixed priority) |
|---|---:|---:|---:|
| 256 B | 1.76 µs / 139 MiB/s | 3.27 µs | 3.35 µs |
| 4 KB | 8.4 µs / 462 MiB/s | 9.2 µs | 9.3 µs |
| 16 KB | 30.5 µs / 513 MiB/s | — | — |

Priority scheduling overhead: **~2.4%** vs equal-priority.

---

## Comparison

| | Seam | TCP + TLS 1.3 | QUIC | Raw UDP |
|---|:---:|:---:|:---:|:---:|
| HoL blocking | ✅ None | ❌ Full stream | ⚠️ Per-stream | ✅ None |
| Built-in FEC | ✅ | ❌ | ❌ | ❌ |
| Stream priorities | ✅ 0–7 native | ❌ | ⚠️ Higher-layer | ❌ |
| Burst control | ✅ Token-bucket | ⚠️ Kernel CC | ⚠️ Impl-dependent | ❌ |
| Post-quantum KEM | ✅ ML-KEM-768 | ❌ Varies | ❌ Varies | ❌ |
| DDoS-resistant HS | ✅ Cookie | ❌ | ✅ | — |

---

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/North9-Labs/Seam/main/install.sh | sh
```

Installs the `seam` CLI to `~/.local/bin`. Set `SEAM_INSTALL_DIR` to override.

### File Transfer

```sh
# Copy a file or directory to a remote host (bootstraps seam on remote if needed)
seam cp ./data user@host:/remote/path

# Keep seam up to date
seam update
```

---

## Getting Started (library)

```bash
# Add to Cargo.toml
# seam-protocol = { git = "https://github.com/North9-Labs/Seam" }

cargo build --all-targets
cargo test --all-targets
cargo bench
```

### Client / Server

```rust
use seam_protocol::{api::{Client, Server}, handshake::IdentityKeypair};

// Server
let id = IdentityKeypair::generate();
let mut server = Server::bind("0.0.0.0:4433".parse()?, id).await?;
let conn = server.accept().await.unwrap();

// Client
let id = IdentityKeypair::generate();
let mut client = Client::bind("0.0.0.0:0".parse()?, id).await?;
let conn = client.connect(server_addr, &server_x25519, &server_kem_pk).await?;
```

### Multiplexed streams

```rust
use seam_protocol::tunnel::SeamMux;

let mux = SeamMux::new(conn);

// Locally-initiated stream
let mut stream = mux.open_stream().await;

// Accept a remote-initiated stream
let mut stream = mux.accept_stream().await.unwrap();

// SeamStream implements AsyncRead + AsyncWrite + Unpin
tokio::io::copy_bidirectional(&mut stream, &mut other).await?;
```

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
- **Commercial:** contact [licensing@north9.org](mailto:licensing@north9.org) for proprietary, government, SaaS, or OEM use

See [LICENSE-COMMERCIAL](LICENSE-COMMERCIAL) for details.
