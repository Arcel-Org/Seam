<div align="center">

# Seam

**Post-quantum encrypted file transfer and transport library — written in Rust.**

UDP · Multi-stream · Built-in FEC · Noise_XX + ML-KEM-768

[![CI](https://github.com/North9-Labs/Seam/actions/workflows/ci.yml/badge.svg)](https://github.com/North9-Labs/Seam/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL%20v3-blue.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88+-orange.svg)](#build-from-source)

</div>

---

```sh
curl -fsSL https://raw.githubusercontent.com/North9-Labs/Seam/main/install.sh | sh
```

`seam` is a command-line tool for securely copying files between machines over a post-quantum encrypted UDP transport. The handshake uses Noise_XX + ML-KEM-768 so session keys are safe against harvest-now-decrypt-later attacks.

---

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/North9-Labs/Seam/main/install.sh | sh
```

Installs to `~/.local/bin/seam`. Override the location with `SEAM_INSTALL_DIR`:

```sh
SEAM_INSTALL_DIR=/usr/local/bin curl -fsSL https://raw.githubusercontent.com/North9-Labs/Seam/main/install.sh | sh
```

Verify the install:

```sh
seam --version
```

---

## Quick Start

```sh
# Copy a local file to a remote host
seam cp ./report.pdf user@host:/home/user/report.pdf

# Copy a directory (compressed by default with zstd)
seam cp ./dataset/ user@host:/data/dataset

# Skip compression (already-compressed data)
seam cp --no-compress ./archive.tar.gz user@host:/backups/

# seam bootstraps itself on the remote if it isn't installed yet —
# no manual setup on the server side required.
```

`seam cp` does the full job: SSH to the remote, start the receiver, perform the post-quantum handshake, transfer the data, and verify delivery.

---

## Update

```sh
seam update
```

Downloads the latest release for your platform and replaces the current binary.

---

## How It Works

`seam cp` opens an SSH connection to your remote host, starts `seam recv` there, then connects back over UDP with a post-quantum encrypted channel. The file transfer runs over that direct UDP path — bypassing the SSH forwarding overhead for bulk data.

The transport layer provides:

- **Noise_XX + ML-KEM-768 handshake** — hybrid classical/post-quantum key exchange completes in ~247 µs
- **ChaCha20-Poly1305** packet encryption with header protection
- **ARQ + GF(2⁸) forward error correction** — packet loss recovered locally without a round-trip
- **Multi-stream multiplexing** — control and data streams are independent, no head-of-line blocking
- **DDoS-resistant handshake** — stateless cookie challenge before any server state is allocated

> **Honest status:** Transfers are currently rate-limited to ~10 MB/s while congestion control on_ack() feedback is being wired end-to-end. On high-latency WAN links the UDP transport already reduces round-trip overhead compared to TCP. The rate limit will be removed once CUBIC CC is fully integrated.

---

## Security

- All packets are encrypted with ChaCha20-Poly1305; the header (session ID, packet number) is additionally protected against traffic analysis.
- The handshake is Noise_XX augmented with ML-KEM-768 (NIST post-quantum standard). Even if classical elliptic-curve cryptography is broken in the future, recorded traffic cannot be decrypted.
- Anti-replay protection rejects duplicate or out-of-window packet numbers.
- The server allocates no per-client state until the client echoes a valid BLAKE3 cookie tied to its IP address, preventing amplification attacks.

Seam is pre-1.0 software. The cryptographic design is sound, but the protocol has not undergone a third-party audit. Do not use it where your threat model requires audited implementations.

---

## Build from Source

```sh
# Prerequisites: Rust 1.88+
git clone https://github.com/North9-Labs/Seam
cd Seam

cargo build --release --bin seam

# The binary is at:
./target/release/seam --version
```

Run the test suite:

```sh
cargo test
```

Run benchmarks:

```sh
cargo bench
```

---

## Library Usage

Add to `Cargo.toml`:

```toml
seam-protocol = { git = "https://github.com/North9-Labs/Seam" }
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

### Multiplexed streams (AsyncRead + AsyncWrite)

```rust
use seam_protocol::tunnel::SeamMux;

let mux = SeamMux::new(conn);

let mut stream = mux.open_stream().await;          // locally-initiated
let mut stream = mux.accept_stream().await.unwrap(); // remote-initiated

// SeamStream implements AsyncRead + AsyncWrite + Unpin
tokio::io::copy_bidirectional(&mut stream, &mut other).await?;
```

---

## Performance

> Single-core, loopback. Hardware and compiler dependent.

**568 MiB/s (~4.76 Gbps) encrypted throughput per core at 1400 B MTU. 247 µs full handshake including ML-KEM-768.**

| Payload | Time | Throughput |
|---|---:|---:|
| 64 B | 350 ns | ~303 MiB/s |
| 256 B | 644 ns | ~455 MiB/s |
| 512 B | 1.03 µs | ~519 MiB/s |
| 1400 B | 2.43 µs | **~568 MiB/s** |

| Handshake operation | Time |
|---|---:|
| `IdentityKeypair::generate` | 17.8 µs |
| `PacketKeys::derive_from_secret` | 370 ns |
| Full handshake (3 messages, Noise_XX + ML-KEM-768) | **247 µs** |

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
