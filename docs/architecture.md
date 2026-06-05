# Seam Architecture

This document describes the protocol stack, handshake sequence, packet format, session lifecycle, and transport features of Seam.

---

## Protocol Stack Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Application Layer                           │
│   cp / sync / shell / forward / proxy / pipe / bench / stats        │
├─────────────────────────────────────────────────────────────────────┤
│                       Multiplexing Layer (SeamMux)                  │
│   Bidirectional streams  │  Unreliable datagrams                    │
│   AsyncRead + AsyncWrite │  No ordering, no retransmit              │
├─────────────────────────────────────────────────────────────────────┤
│                         Session Layer                               │
│   ARQ retransmission  │  Flow control (16 MiB window + MaxData)     │
│   Priority scheduling │  Stream multiplexing                        │
│   Double ratchet      │  Out-of-order delivery                      │
├─────────────────────────────────────────────────────────────────────┤
│                    FEC / Loss Recovery Layer                        │
│   GF(2⁸) Reed-Solomon  │  Adaptive FEC arbiter (EWMA loss)         │
│   Systematic codec      │  Pure ARQ ↔ hybrid ↔ pure FEC            │
├─────────────────────────────────────────────────────────────────────┤
│                         Crypto Layer                                │
│   ChaCha20-Poly1305 / AES-256-GCM AEAD encryption                  │
│   Header protection (ChaCha20 keystream XOR)                       │
│   Anti-replay window (1024-slot sliding bitmap)                    │
│   Double ratchet key derivation (BLAKE3 KDF)                       │
├─────────────────────────────────────────────────────────────────────┤
│                      Handshake Layer                                │
│   Noise_XX_25519_ChaChaPoly_BLAKE2s                                 │
│   + ML-KEM-768 hybrid key encapsulation (FIPS 203)                  │
│   + ML-DSA-65 identity proof exchange (FIPS 204)                    │
│   + BLAKE3 cookie (DDoS resistance)                                 │
├─────────────────────────────────────────────────────────────────────┤
│                       Transport Layer                               │
│   CUBIC / BBR congestion control  │  Path MTU probing               │
│   Multi-path transport            │  Keepalive (Ping/Pong, 15s)     │
│   Token-bucket pacer              │  Idle timeout (60s)             │
├─────────────────────────────────────────────────────────────────────┤
│                            UDP / IP                                 │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Handshake Sequence

Seam uses a three-message Noise_XX handshake augmented with ML-KEM-768 post-quantum key encapsulation and ML-DSA-65 identity proofs. The sequence below shows the full flow from SSH bootstrap through to application data.

```
Client                                          Server
  │                                               │
  │  ── SSH ──────────────────────────────────►  │  (bootstrap)
  │  ssh user@host "seam _xxx-recv --port 0"     │
  │                                               │  binds UDP port
  │  ◄── SSH ─────────────────────────────────── │
  │  SEAM PORT=N X25519=<hex> KEM=<hex>           │
  │  (SSH channel closed after reading line)      │
  │                                               │
  │  ── UDP: Noise msg 1 (Initial) ───────────►  │
  │  ephemeral X25519 pubkey (e)                  │  (no server state
  │  + BLAKE3 cookie request                      │   until cookie echoed)
  │                                               │
  │  ◄── UDP: Noise msg 2 (Handshake) ─────────  │
  │  e, ee, s, es                                 │  server ephemeral key
  │  + server static X25519 pubkey (s)            │  server KEM pubkey
  │  + server ML-KEM-768 encapsulation key        │  cipher negotiation flag
  │  + cipher preference flag                     │
  │  + BLAKE3 cookie (IP:port bound, 30s TTL)     │
  │                                               │
  │  ── UDP: Noise msg 3 (Handshake) ───────────► │
  │  se                                           │  client static key
  │  + client static X25519 pubkey (s)            │
  │  + ML-KEM-768 ciphertext (encapsulation)      │
  │  + cipher preference flag                     │
  │  + BLAKE3 cookie echo                         │
  │                                               │  (server now allocates
  │                                               │   per-client state)
  │                                               │
  │  ── UDP: ML-DSA-65 identity proof ─────────► │
  │  mldsa_pk (1952 B) + signature over           │
  │  BLAKE3(handshake transcript) (3309 B)        │
  │                                               │
  │  ◄── UDP: ML-DSA-65 identity proof ─────────  │
  │  server mldsa_pk + signature                  │
  │                                               │
  │  ═══════════════════════════════════════════  │
  │  Session keys active — AEAD-encrypted UDP     │
  │  Application data (cp / shell / forward ...)  │
```

### Key Derivation

After Noise_XX completes, both sides share:
- The Noise handshake hash (BLAKE3 transcript of all three messages)
- The Noise-derived session secret (from X25519 key agreement)
- The ML-KEM-768 shared secret (from KEM encapsulation)

The final session root key is derived by mixing both secrets via BLAKE3:

```
root_key = BLAKE3(noise_secret || kem_shared_secret)
```

This ensures that a quantum adversary who breaks X25519 still cannot derive the session key without also breaking ML-KEM-768, and vice versa.

The ML-DSA-65 identity proofs bind each party's post-quantum identity to the session by signing the handshake transcript hash. This prevents a relay from substituting a different identity key without detection.

### DDoS Resistance

The server commits no per-client memory until the client echoes a valid BLAKE3 cookie:

- Cookie is bound to the client's source IP and port
- Cookie expires after 30 seconds
- Cookie is computed from a server-side secret and the client address — not predictable or forged by an attacker

This prevents an attacker from exhausting server state by sending large numbers of spoofed Initial packets.

---

## Packet Format

Each Seam UDP packet has a 32-byte protected header followed by an AEAD-encrypted payload and a 16-byte authentication tag.

```
┌──────────────────────────────────────────────┐
│  Header (32 bytes) — header-protected        │
│                                              │
│  [0..8]   session_id  (u64, little-endian)   │
│  [8..16]  packet_seq  (u64, little-endian)   │
│  [16]     pkt_type    (u8)                   │
│  [17..32] flags + padding                    │
├──────────────────────────────────────────────┤
│  Payload (variable) — AEAD-encrypted         │
│                                              │
│  Application data / control frames           │
├──────────────────────────────────────────────┤
│  AEAD Tag (16 bytes)                         │
│                                              │
│  ChaCha20-Poly1305 or AES-256-GCM tag        │
└──────────────────────────────────────────────┘

Total minimum: 32 + 16 = 48 bytes
Maximum accepted: 65535 bytes (IP datagram limit)
```

### Header Protection

The 32-byte header is encrypted by XORing with a keystream derived from a separate `hp_key` (header protection key) and the first 16 bytes of the AEAD ciphertext as a nonce input:

```
mask = ChaCha20(hp_key, nonce=ciphertext[0..12], counter=LE32(ciphertext[12..16]))
protected_header = header XOR mask[0..32]
```

This makes the session ID and packet number opaque to a passive observer. An on-path adversary cannot correlate packets to sessions or reconstruct sequence numbers without the session keys.

### Packet Types

| Type | Value | Description |
|---|---|---|
| `Initial` | `0x00` | First client-to-server packet; contains cookie request |
| `Handshake` | `0x01` | Noise handshake messages (msgs 2 and 3) |
| `Data` | `0x02` | Application payload |
| `Ack` | `0x03` | Acknowledgement / SACK bitmap |
| `FecRepair` | `0x04` | Reed-Solomon repair symbol |
| `Chaff` | `0x05` | Cover traffic / padding |
| `PathProbe` | `0x06` | MTU and RTT path probing |
| `Close` | `0x07` | Graceful session termination |
| `Datagram` | `0x08` | Unreliable application datagram (no retransmit) |
| `KeyUpdate` | `0x09` | Signal peer to advance to next ratchet epoch |
| `MaxData` | `0x0A` | Extend peer's send-side flow-control window (8-byte u64 limit) |
| `Ping` | `0x0B` | Keepalive ping — expects a Pong response |
| `Pong` | `0x0C` | Keepalive pong — resets idle timer |
| `SessionTicket` | `0x0D` | Encrypted session ticket for 0-RTT resumption |

---

## Session Lifecycle

```
HANDSHAKE → ESTABLISHED → [RATCHET EPOCH N] → CLOSED
                │                    │
                │             (every 1000 packets
                │              or 30 seconds)
                │                    │
                └────────────────────┘
                   DH ratchet step:
                   new ephemeral X25519 keys,
                   new root key derived,
                   old key material zeroized
```

### Establishment

1. Client sends Initial (BLAKE3 cookie request).
2. Server responds with Noise msg 2 + cookie.
3. Client echoes cookie + Noise msg 3.
4. Both sides exchange ML-DSA-65 identity proofs.
5. Session enters ESTABLISHED state.

### Data Transfer

Streams are opened from either side via `SeamMux`. Each stream is an independent ordered reliable byte channel backed by ARQ and the FEC layer. Streams implement `AsyncRead + AsyncWrite` and can be used directly with Tokio I/O utilities.

Unreliable datagrams (`send_datagram`) bypass ARQ and FEC — useful for real-time data where latency matters more than delivery guarantee.

### Keepalive and Idle Timeout

- Ping/Pong frames are sent every **15 seconds** of idle time.
- The session is terminated after **60 seconds** of total inactivity (no data, no pings).
- Control packets (Ack, Ping, Pong, MaxData) bypass congestion control and are sent immediately.

### Session Closure

Either side can close the session by sending a `Close` packet. The session enters a TIME_WAIT equivalent period, then all state is dropped. Old traffic keys are zeroized.

---

## Forward Error Correction

Seam uses a **GF(2⁸) Reed-Solomon systematic codec**. Systematic means the original `k` source packets are transmitted as-is; `r` repair symbols are appended. A receiver that gets any `k` of the `k+r` packets can reconstruct the group.

### Adaptive FEC Arbiter

The arbiter tracks packet loss rate using an EWMA (exponentially weighted moving average) and adjusts FEC parameters dynamically:

| Loss rate | Mode | Behavior |
|---|---|---|
| < ~2% | Pure ARQ | No FEC overhead; lost packets trigger retransmit |
| 2–15% | Hybrid FEC+ARQ | FEC repairs most losses without a round-trip; ARQ handles the rest |
| > 15% | Pure FEC | FEC absorbs all losses; ARQ disabled |
| Any, RTT > 100ms | Light FEC preloaded | Even on clean links, a few repair symbols are added proactively to avoid one ARQ round-trip at high latency |

Default FEC parameters (`fec_k`, `fec_r`) are managed automatically by the arbiter. You can override them in `~/.config/seam/config.toml`:

```toml
fec_k = 8   # 8 source symbols per group
fec_r = 2   # 2 repair symbols (25% overhead)
```

Recommended tuning by link type:

| Link | fec_k | fec_r | Notes |
|---|---|---|---|
| LAN / fiber | 0 | — | Disable FEC entirely; pure ARQ |
| Mobile / WiFi | 8 | 2 | 25% overhead, recovers 2/10 losses |
| Satellite / HF radio | 4 | 4 | 100% overhead, recovers 4/8 losses |

---

## Double Ratchet

Seam implements a double ratchet for per-epoch forward secrecy:

- **Symmetric ratchet (chain ratchet):** Advances every packet. A fresh BLAKE3 KDF step derives a unique message key from the current chain key. Compromise of the current key does not expose past message keys.
- **DH ratchet (root ratchet):** Advances every epoch (default: 1000 packets or 30 seconds, whichever comes first). A new ephemeral X25519 key pair is generated, a new root key is derived from the DH exchange, and old key material is zeroized.

Out-of-order packets are handled with a bounded skip-key cache (max 50 entries, 30-second TTL). Skipped keys are zeroized when they expire.

Epoch parameters are configurable:

```toml
ratchet_epoch_packets = 1000  # packets before DH ratchet step
ratchet_epoch_seconds = 30    # seconds before DH ratchet step
```

---

## Anti-Replay Window

Each session maintains a **1024-slot sliding bitmap window**. Every incoming packet's 64-bit sequence number is checked:

- If the sequence number falls below the window's base: rejected as `TooOld`.
- If the sequence number is within the window and the bit is set: rejected as a `Replay`.
- If the sequence number advances the window: old bits are shifted out, the new bit is set.
- If accepted: the bit is set and the packet is processed.

A replayed or duplicated packet is silently dropped regardless of its AEAD tag. An attacker who captures and retransmits a valid ciphertext cannot cause it to be processed twice.

---

## Flow Control

Seam uses a credit-based flow control model similar to QUIC:

- Each connection starts with a **16 MiB send window**.
- The receiver extends the window by sending `MaxData` frames.
- Control packets (Ack, Ping, Pong, MaxData) bypass the congestion control pacer and are delivered immediately.

---

## Congestion Control

Two congestion controllers are available:

| Controller | When to use |
|---|---|
| CUBIC (default) | General purpose; good on all link types |
| BBR | High-bandwidth, high-latency paths (satellite, transoceanic) |

Select via environment variable or config:

```sh
SEAM_CC=bbr seam bench alice@server
seam config set cc bbr
```

---

## Multi-Path Transport

When `--multipath addr1,addr2,...` is specified, seam binds to multiple local network interfaces simultaneously. Packets can be scheduled across paths in several modes:

| Mode | Description |
|---|---|
| `round-robin` | Rotate evenly across paths (default) |
| `min-latency` | Always use the lowest-RTT path |
| `redundant` | Send every packet on all paths simultaneously; receiver deduplicates by sequence number |
| `weighted` | Weight by bandwidth estimate |

Redundant mode provides anti-jamming protection: even if all but one path is jammed or degraded, delivery is guaranteed. Per-packet deduplication by sequence number prevents the anti-replay window from rejecting redundant copies.

---

## Repository Structure

```
src/
├── api.rs            # Client, Server, SeamConn public API
├── tunnel.rs         # SeamMux + SeamStream (AsyncRead + AsyncWrite)
├── packet.rs         # Packet types and wire format constants
├── error.rs          # Error types
├── crypto/
│   ├── mod.rs        # CipherSuite, AeadCipher trait
│   ├── keys.rs       # PacketKeys, key derivation
│   ├── header.rs     # Header protection (ChaCha20 keystream XOR)
│   ├── replay.rs     # 1024-slot sliding anti-replay window
│   ├── ratchet.rs    # Double ratchet (chain + DH ratchet)
│   ├── rekey.rs      # Key schedule / re-key state machine
│   ├── encoder.rs    # Packet encryption
│   └── decoder.rs    # Packet decryption + replay check
├── handshake/
│   ├── mod.rs        # Public handshake API
│   ├── state.rs      # Noise_XX state machine + ML-DSA-65 identity proof
│   ├── hybrid_keys.rs # IdentityKeypair (X25519 + ML-KEM-768 + ML-DSA-65)
│   └── cookie.rs     # BLAKE3 DDoS-resistant cookie
├── fec/
│   ├── gf.rs         # GF(2⁸) arithmetic
│   ├── codec.rs      # Systematic Reed-Solomon encoder/decoder
│   ├── arbiter.rs    # Adaptive FEC/ARQ arbiter
│   └── mod.rs
├── session/
│   ├── mod.rs        # Session main loop (packet dispatch, multiplexing)
│   ├── stream.rs     # Reliable ordered streams (StreamId, ARQ integration)
│   ├── arq.rs        # ARQ retransmission with exponential backoff
│   ├── ack.rs        # SACK bitmap acknowledgement
│   ├── flow.rs       # Flow control (credit-based, MaxData frames)
│   ├── rack.rs       # RACK-based loss detection
│   ├── datagram.rs   # Unreliable datagram delivery
│   └── ratchet_session.rs # Ratchet-to-session integration
└── transport/        # UDP socket, CUBIC/BBR CC, pacer, path probing

src/bin/seam/         # CLI implementation (see cli-reference.md)
benches/              # Criterion benchmarks (packet, fec, handshake, session)
fuzz/                 # cargo-fuzz targets (packet_decode)
```
