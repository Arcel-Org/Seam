# Apex Protocol

Apex is a Rust transport protocol stack focused on high-throughput encrypted data transfer with:

- **UDP-based transport** with custom congestion control and pacing
- **Reliable multi-stream sessions** with **priority scheduling**
- **Built-in FEC** (forward error correction) over GF(2^8)
- **Hybrid handshake** (`Noise_XX` + `ML-KEM768`) for post-quantum key exchange

## What was recently added

- **Token-bucket pacer** (`src/transport/pacer.rs`)
  - Sends at `cwnd/srtt` bytes/sec
  - Reduces burst-driven queue buildup
  - Work-conserving refill with one-burst token accumulation

- **Stream priority scheduling** (`src/session/stream.rs`)
  - Priority range `0..=7` (`0` highest, `7` lowest)
  - `Session::flush()` drains high-priority streams before bulk streams

- **8× unrolled GF `mul_add_slice` path** (`src/fec/gf.rs`)
  - Improves bulk FEC math throughput
  - `scalar=1` XOR path auto-vectorizes well

## Performance snapshot

> Benchmarks are hardware/compiler dependent. These values are representative from local runs.

### Packet encode (ChaCha20Poly1305 + header protection)

| Payload | Time   | Throughput |
|---|---:|---:|
| 64 B   | 350 ns  | ~303 MiB/s |
| 256 B  | 644 ns  | ~455 MiB/s |
| 512 B  | 1.03 µs | ~519 MiB/s |
| 1400 B | 2.43 µs | ~568 MiB/s |

### GF(2^8) `mul_add_slice` (unrolled)

| Slice | scalar=0x17 | scalar=1 (XOR) |
|---|---:|---:|
| 64 B  | ~30 ns  | ~21 ns |
| 256 B | ~117 ns | ~77 ns |
| 1 KB  | ~467 ns | ~297 ns |
| 4 KB  | ~1.9 µs | ~1.1 µs |

Throughput range: **~1.4–3.3 GiB/s** depending on scalar.

### FEC encode/recover (1400 B symbols)

| Config | Encode | Recover 1 loss |
|---|---:|---:|
| k=4 r=1  | ~5.5 µs | ~10.4 µs |
| k=8 r=2  | ~11 µs  | ~21 µs |
| k=10 r=3 | ~16 µs  | ~32 µs |

### Handshake

| Operation | Time |
|---|---:|
| `IdentityKeypair::generate` | 17.8 µs |
| `PacketKeys::derive_from_secret` | 370 ns |
| `CookieFactory::generate` | 91 ns |
| `CookieFactory::verify` | 88 ns |
| Full handshake (3 messages) | 247 µs |

### Session flush throughput

| Payload | 1 stream | 4 streams equal | 4 streams mixed priority |
|---|---:|---:|---:|
| 256 B  | 1.76 µs | 3.27 µs | 3.35 µs |
| 4 KB   | 8.4 µs  | 9.2 µs  | 9.3 µs  |
| 16 KB  | 30.5 µs | — | — |

### CC + pacer overhead

| Operation | Time |
|---|---:|
| `Cubic::on_ack` | ~200 ns |
| `Pacer::available + consume` | ~10 ns |

## What these speeds mean vs baseline TCP/UDP

At 1400 B MTU, **~568 MiB/s ≈ 4.76 Gbps per core** of encrypted+protected packet processing.

### Practical comparison (directional)

| Metric | Apex | TCP (plaintext) | TCP+TLS 1.3 | QUIC | Raw UDP |
|---|---|---|---|---|---|
| Transport | User-space UDP | Kernel TCP | Kernel TCP + TLS | User-space UDP + TLS | UDP only |
| Per-core encrypted throughput | ~4.76 Gbps (bench path) | N/A | workload/implementation dependent | workload/implementation dependent | N/A |
| Handshake CPU cost | ~247 µs (with ML-KEM768 path) | minimal (no crypto) | added TLS crypto cost | added QUIC+TLS crypto cost | none |
| Built-in FEC | **Yes** | No | No | No (app-level only) | No |
| Stream priorities | **Yes** | No native stream abstraction | No native stream abstraction | Yes (higher-layer scheduling) | No |
| HOL blocking across logical streams | **No** (independent stream scheduling avoids cross-stream HOL) | Yes (single byte stream) | Yes (inherits TCP stream HOL) | Reduced (per stream) | No |
| Burst control | **Token-bucket pacing** | Kernel CC pacing behavior | Kernel CC pacing behavior | CC + pacing in implementation | None by default |
| Post-quantum KEM | **Yes (ML-KEM768)** | No | adoption varies by deployment and policy | adoption varies by deployment and policy | No |

### Bottom line

- Compared to **raw UDP**, Apex adds congestion discipline, reliability features, and FEC while keeping low overhead.
- Compared to **TCP/TLS**, Apex targets lower head-of-line impact and richer transport-level controls (streams + priority + FEC).
- Compared to **QUIC**, Apex is in a similar design space; this table is a directional comparison of capability differences and rough performance order-of-magnitude, not a direct same-host apples-to-apples benchmark against a specific QUIC implementation.

## Build and benchmark

```bash
cargo build --all-targets
cargo test --all-targets
cargo bench
```

## Repository layout

- `src/crypto/` — packet protection, header protection, anti-replay, key derivation
- `src/handshake/` — Noise + ML-KEM768 handshake and cookies
- `src/session/` — stream state, ARQ, flow control, scheduling
- `src/fec/` — GF arithmetic, FEC codec, FEC/ARQ arbiter
- `src/transport/` — connection, endpoint, congestion control, pacer, probing, resumption
- `benches/` — criterion performance benchmarks
