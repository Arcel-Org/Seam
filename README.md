<div align="center">

# Seam Protocol

**A high-performance, post-quantum encrypted transport stack written in Rust.**

UDP-based · Multi-stream · Built-in FEC · ML-KEM768 Post-Quantum Handshake

[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Language](https://img.shields.io/badge/language-Rust-orange)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](#)

</div>

---

## Overview

Seam is a user-space transport protocol designed for applications where standard TCP or QUIC leave performance on the table. It combines encrypted, paced UDP delivery with multi-stream session management, forward error correction, and a hybrid post-quantum handshake — all in a single cohesive stack.

| Capability | Detail |
|---|---|
| Transport | User-space UDP with CUBIC congestion control + token-bucket pacing |
| Encryption | ChaCha20-Poly1305 packet protection + header protection |
| Handshake | Noise_XX + ML-KEM768 (post-quantum hybrid) |
| Reliability | ARQ + GF(2^8) Forward Error Correction |
| Multiplexing | Priority-scheduled streams (0–7, 0 = highest) |

---

## Why Seam?

- **No head-of-line blocking** — streams are scheduled independently; a stalled bulk transfer never blocks a control message
- **Post-quantum by default** — ML-KEM768 KEM is baked into the handshake, not bolted on
- **FEC at the transport layer** — packet loss is recovered without a round-trip, not retransmitted
- **Paced, not bursty** — token-bucket pacer at `cwnd/srtt` bytes/sec eliminates burst-driven queue buildup that plagues raw UDP
- **Priority-aware** — a priority-0 control stream always drains before priority-7 bulk data, with ~2% scheduling overhead

---

## Performance

> Benchmarks are hardware and compiler dependent. Values below are representative of local runs on a single core.

**The headline numbers: ~568 MiB/s (~4.76 Gbps) encrypted throughput per core at 1400 B MTU, 247 µs full handshake including ML-KEM768.**

### Packet Encode — ChaCha20-Poly1305 + Header Protection

| Payload | Time | Throughput |
|---|---:|---:|
| 64 B | 350 ns | ~303 MiB/s |
| 256 B | 644 ns | ~455 MiB/s |
| 512 B | 1.03 µs | ~519 MiB/s |
| 1400 B | 2.43 µs | **~568 MiB/s** |

### GF(2^8) `mul_add_slice` — 8× Unrolled

| Slice | scalar=0x17 | scalar=1 (XOR) |
|---|---:|---:|
| 64 B | ~30 ns | ~21 ns |
| 256 B | ~117 ns | ~77 ns |
| 1 KB | ~467 ns | ~297 ns |
| 4 KB | ~1.9 µs | ~1.1 µs |

Throughput range: **~1.4–3.3 GiB/s** depending on scalar. The `scalar=1` XOR path auto-vectorizes.

### FEC Encode / Recover — 1400 B Symbols

| Config | Encode | Recover 1 Loss |
|---|---:|---:|
| k=4, r=1 | ~5.5 µs | ~10.4 µs |
| k=8, r=2 | ~11 µs | ~21 µs |
| k=10, r=3 | ~16 µs | ~32 µs |

### Handshake — Noise_XX + ML-KEM768

| Operation | Time |
|---|---:|
| `IdentityKeypair::generate` | 17.8 µs |
| `PacketKeys::derive_from_secret` | 370 ns |
| `CookieFactory::generate` | 91 ns |
| `CookieFactory::verify` | 88 ns |
| **Full handshake (3 messages)** | **247 µs** |

### Session Flush Throughput

| Payload | 1 Stream | 4 Streams (equal) | 4 Streams (mixed priority) |
|---|---:|---:|---:|
| 256 B | 1.76 µs / 139 MiB/s | 3.27 µs | 3.35 µs |
| 4 KB | 8.4 µs / 462 MiB/s | 9.2 µs | 9.3 µs |
| 16 KB | 30.5 µs / 513 MiB/s | — | — |

Priority scheduling adds only **~2.4% overhead** over equal-priority scheduling.

### Congestion Control + Pacer

| Operation | Time |
|---|---:|
| `Cubic::on_ack` | ~200 ns |
| `Pacer::available + consume` | ~10 ns |

---

## Comparison to TCP / QUIC / UDP

This is a directional capability comparison, not a same-host apples-to-apples benchmark.

| | Seam | TCP+TLS 1.3 | QUIC | Raw UDP |
|---|---|---|---|---|
| HOL blocking | ✅ None | ❌ Full stream | ⚠️ Per-stream | ✅ None |
| Built-in FEC | ✅ Yes | ❌ No | ❌ No | ❌ No |
| Stream priorities | ✅ 0–7 native | ❌ No | ⚠️ Higher-layer | ❌ No |
| Burst control | ✅ Token-bucket | ⚠️ Kernel CC | ⚠️ Impl-dependent | ❌ None |
| Post-quantum KEM | ✅ ML-KEM768 | ❌ Varies | ❌ Varies | ❌ No |
| Handshake cost | ~247 µs CPU | Minimal | ~300–600 µs | None |

---

## Repository Layout

```
src/
├── api.rs          # Client, Server, SeamConn, SeamConnWriter
├── crypto/         # Packet & header protection, anti-replay, key derivation
├── handshake/      # Noise_XX + ML-KEM768 handshake, cookies
├── session/        # Stream state, ARQ, flow control, priority scheduling
├── fec/            # GF(2^8) arithmetic, FEC codec, FEC/ARQ arbiter
├── transport/      # Connection, endpoint, CUBIC CC, pacer, probing, resumption
└── tunnel.rs       # SeamMux / SeamStream — AsyncRead + AsyncWrite adapters

benches/            # Criterion benchmarks
```

---

## Getting Started

```bash
# Build all targets
cargo build --all-targets

# Run tests
cargo test --all-targets

# Run benchmarks
cargo bench
```

### Basic usage

```rust
use seam_protocol::{api::{Client, Server}, handshake::IdentityKeypair};

// Server side
let id = IdentityKeypair::generate();
let mut server = Server::bind("0.0.0.0:4433".parse().unwrap(), id).await?;
let conn = server.accept().await.unwrap();

// Client side
let id = IdentityKeypair::generate();
let mut client = Client::bind("0.0.0.0:0".parse().unwrap(), id).await?;
// let conn = client.connect(server_addr, &x25519, &kem_pk).await?;
```

### Mux / stream usage

```rust
use seam_protocol::tunnel::SeamMux;

// After handshake:
let mux = SeamMux::new(conn);

// Open a stream (locally initiated)
let mut stream = mux.open_stream().await;

// Accept a stream from the remote peer
let mut stream = mux.accept_stream().await.unwrap();

// SeamStream implements AsyncRead + AsyncWrite
tokio::io::copy(&mut stream, &mut sink).await?;
```

### Error handling

```rust
use seam_protocol::SeamError;

match result {
    Err(SeamError::HandshakeFailed(msg)) => { /* ... */ }
    Err(SeamError::AuthFailed) => { /* ... */ }
    _ => {}
}
```

---

<div align="center">
Built with Rust
</div>
# Seam
