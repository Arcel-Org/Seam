# Seam Security Design

This document describes the cryptographic algorithms Seam uses, why each was chosen, and the security properties the combination provides.

---

## Honest Disclaimer

Seam is pre-1.0 software. The cryptographic design follows well-established patterns and uses audited primitives, but the protocol itself has not undergone a third-party security audit. Do not deploy it where your threat model requires independently audited software.

---

## Threat Model

Seam is designed to resist:

1. **Passive eavesdropping** — traffic is AEAD-encrypted; headers are additionally protected to prevent session correlation.
2. **Man-in-the-middle attacks** — mutual authentication via both classical (X25519) and post-quantum (ML-DSA-65) identity proofs.
3. **Replay attacks** — 1024-slot sliding bitmap anti-replay window; sequence numbers encrypted in header.
4. **"Harvest now, decrypt later" quantum attacks** — ML-KEM-768 ensures session keys cannot be decrypted by a future quantum computer even if handshake recordings are captured today.
5. **DDoS amplification** — BLAKE3 cookie challenge before any per-client state is allocated.
6. **Traffic analysis** — optional size-class padding, cover traffic, timing jitter, and header obfuscation.
7. **Key compromise going forward** — double ratchet provides per-epoch forward secrecy.

Seam does not currently protect against:
- Endpoint compromise (if the host running seam is compromised, session keys are exposed)
- Denial of service by a volumetric attacker overwhelming the UDP socket

---

## Algorithm Overview

| Function | Default algorithm | FIPS mode algorithm |
|---|---|---|
| Key encapsulation (PQ) | ML-KEM-768 (FIPS 203) | ML-KEM-768 (FIPS 203) |
| Identity signature (PQ) | ML-DSA-65 (FIPS 204) | ML-DSA-65 (FIPS 204) |
| Classical key agreement | X25519 via Noise_XX | X25519 via Noise_XX (SP 800-186) |
| AEAD encryption | ChaCha20-Poly1305 | AES-256-GCM (FIPS 197) |
| Header protection | ChaCha20 keystream | ChaCha20 keystream |
| Integrity (file/sync) | BLAKE3 | SHA-256 (FIPS 180-4) |
| Cookie / handshake hash | BLAKE3 | BLAKE3 |
| KDF (ratchet) | BLAKE3 | BLAKE3 |
| Noise hash | BLAKE2s (via snow crate) | BLAKE2s |

---

## ML-KEM-768 (FIPS 203) — Post-Quantum Key Encapsulation

### What it does

ML-KEM-768 (previously CRYSTALS-Kyber level 3) is a key encapsulation mechanism standardized by NIST as FIPS 203 in August 2024. During the Seam handshake:

1. The server's `EncapsulationKey768` (ML-KEM-768 public key, 1184 bytes) is advertised in the Noise handshake payload.
2. The client **encapsulates** a random 32-byte shared secret against the server's public key, producing a 1088-byte ciphertext.
3. The server **decapsulates** the ciphertext using its private key to recover the same 32-byte shared secret.
4. Both sides mix this shared secret into the session root key via BLAKE3.

### Why ML-KEM-768

- **FIPS 203** — Only NIST-standardized post-quantum KEM algorithm. Required for CNSA 2.0 and FIPS-140 compliant deployments.
- **Security level 3** — Targets 192-bit classical / 128-bit quantum security. The NSA's CNSA 2.0 guidance specifies ML-KEM-1024 for long-term protection of NSS, but ML-KEM-768 exceeds general-purpose requirements and is lighter weight.
- **IND-CCA2 secure** — Security proof holds even against adaptive chosen-ciphertext adversaries.

### Why KEM is not enough alone — the hybrid construction

ML-KEM-768 is relatively new. Elliptic-curve cryptography (X25519) has decades of cryptanalysis. The hybrid construction XORs both shared secrets into the root key:

```
root_key = BLAKE3(x25519_shared_secret || kem_shared_secret)
```

This means:
- A classical adversary cannot break the session (X25519 hardness holds)
- A quantum adversary cannot break the session (ML-KEM-768 hardness holds)
- If either primitive has an unknown weakness, the session is still protected by the other

Traffic recorded today cannot be decrypted later even if only one primitive is broken in the future.

---

## ML-DSA-65 (FIPS 204) — Post-Quantum Identity Signatures

### What it does

After the Noise_XX handshake completes, both client and server exchange **ML-DSA-65 identity proofs**:

```
IdentityProof {
    mldsa_pk:  [u8; 1952]   // ML-DSA-65 verify key
    signature: [u8; 3309]   // ML-DSA-65 signature over BLAKE3(handshake transcript)
}
```

The signature covers the BLAKE3 hash of the complete Noise handshake transcript, binding the ML-DSA-65 identity to this specific session.

### Why identity must be post-quantum, not just key exchange

This is a subtle but important point. The Noise_XX handshake provides mutual authentication via the X25519 static keys — but X25519 is a classical algorithm. A quantum adversary with a cryptographically relevant quantum computer (CRQC) can:

1. Record all handshake traffic today (the three Noise messages)
2. After a CRQC becomes available, recover the X25519 static private keys from the public keys
3. Forge a man-in-the-middle attack retroactively — recompute what the legitimate identity claimed during the handshake

If identity is only proven by X25519, this retroactive MitM attack succeeds. The ML-DSA-65 identity proof prevents it: even with a CRQC, an attacker cannot forge a valid ML-DSA-65 signature without the ML-DSA-65 private key. The identity binding is quantum-resistant.

This is why Seam carries both:
- X25519 static keys (for Noise_XX's current authentication mechanism)
- ML-DSA-65 identity proofs (for quantum-resistant identity binding)

### TOFU pinning uses ML-DSA-65 fingerprints

Server identity is pinned via the ML-DSA-65 public key fingerprint (SHA-256 of the 1952-byte public key), stored in `~/.config/seam/known_hosts`. This fingerprint remains valid across quantum attacks.

---

## X25519 — Classical Key Agreement

Seam uses the **Noise_XX** handshake pattern from the [Noise Protocol Framework](https://noiseprotocol.org/), specifically:

```
Noise_XX_25519_ChaChaPoly_BLAKE2s
```

This provides:
- **Mutual authentication** — both parties authenticate their static X25519 keys
- **Forward secrecy** — ephemeral X25519 key pairs are generated per session; compromise of static keys does not expose past sessions
- **Zero-knowledge** — the responder's static key is not exposed to passive observers before authentication completes

X25519 is retained as the classical component of the hybrid KEM because:
- 50+ years of elliptic-curve cryptanalysis provide high confidence
- No known quantum speedup for key agreement (Shor's algorithm applies to ECDLP discretely, but X25519 uses Montgomery curves where the group order has a different structure — standard Shor's attack still works, but X25519 keys are 256 bits so 128-bit quantum security is insufficient against a full CRQC)
- Belt-and-suspenders: hybrid construction means classical security is preserved until a CRQC exists

---

## ChaCha20-Poly1305 and AES-256-GCM — AEAD Encryption

### ChaCha20-Poly1305 (default)

All packet payloads are encrypted with ChaCha20-Poly1305 (256-bit key, 96-bit nonce, 128-bit authentication tag):

- **No hardware requirement** — constant-time software implementation; fast on all CPUs including ARM, RISC-V, embedded.
- **Timing side-channel resistant** — ChaCha20 is stream cipher with no table lookups; Poly1305 is a one-time MAC with constant-time field arithmetic.
- **IETF standardized** — RFC 8439.

### AES-256-GCM (FIPS mode / CNSA 2.0)

When `--fips-mode` is active or `--cipher aes256gcm` is specified:

- **FIPS 197** — AES is the NIST-standardized symmetric cipher. Required for NSA CNSA 2.0 and DoD IL2+ deployments.
- **Hardware-accelerated** — AES-NI instructions (Intel, AMD, ARM Cortex-A series) make AES-256-GCM extremely fast on modern hardware. Performance on AES-NI hardware can exceed ChaCha20-Poly1305 in software.
- **Same key/nonce/tag structure** — 256-bit key, 96-bit nonce (seam uses the 64-bit packet sequence number + 32-bit epoch counter), 128-bit GHASH authentication tag.

In FIPS mode, passing `--cipher chacha20poly1305` is rejected with an error.

### Cipher negotiation

During the handshake, each side appends a 1-byte cipher preference flag to the Noise payload:
- `0x00` = ChaCha20-Poly1305 only
- `0x01` = AES-256-GCM preferred (also accepts ChaCha20-Poly1305)

The responder's preference wins if both sides support AES-256-GCM; otherwise ChaCha20-Poly1305 is used.

---

## BLAKE3 and SHA-256 — Integrity

### BLAKE3 (default)

Used for:
- DDoS-resistant cookie (`BLAKE3(server_secret || client_addr || timestamp)`)
- Handshake transcript hash (bound by ML-DSA-65 identity proofs)
- KDF in the double ratchet chain key step
- File integrity checksums in `seam cp` and `seam sync`

BLAKE3 is not FIPS-approved. It is used in non-FIPS mode for its speed and modern security properties.

### SHA-256 (FIPS mode)

In FIPS mode, SHA-256 (FIPS 180-4) replaces BLAKE3 for **file integrity checksums only**. The cookie and ratchet KDF continue to use BLAKE3 internally because the Noise protocol framework uses BLAKE2s, and changing those components would break the Noise handshake transcript.

---

## Double Ratchet — Forward Secrecy After Handshake

Seam implements a double ratchet adapted from the Signal Protocol design:

### Chain ratchet (symmetric)

Every packet advances the chain ratchet:

```
(chain_key, message_key) = BLAKE3_KDF(chain_key)
```

The message key encrypts that packet's AEAD payload. After use, `message_key` is discarded. Compromise of the current chain key does not expose message keys from packets already delivered.

### DH ratchet (ephemeral)

Every epoch (default: 1000 packets or 30 seconds), a new ephemeral X25519 key pair is generated:

```
ratchet_secret = X25519(my_new_ephemeral_sk, peer_current_ephemeral_pk)
(root_key, send_chain_key) = BLAKE3_KDF(root_key, ratchet_secret)
```

The old root key and chain keys are **zeroized** (using the `zeroize` crate). An adversary who compromises the current session keys cannot decrypt traffic from past epochs.

### Out-of-order packet handling

Skipped message keys are cached in a bounded window (max 50 entries, 30-second TTL). Entries older than 30 seconds are zeroized. This handles out-of-order UDP delivery without retaining keys indefinitely.

---

## Anti-Replay Window

Each session maintains a **1024-slot sliding bitmap window**:

- Window is implemented as 16 × `u64` values = 1024 bits
- The window slides forward as new sequence numbers arrive
- Packets with sequence numbers below the window base are rejected as `TooOld`
- Packets with sequence numbers in the window where the bit is already set are rejected as `Replay`
- Accepted packets set the corresponding bit

This prevents an attacker who captures a valid encrypted packet from causing it to be processed a second time. The replay check happens after header unprotection but before AEAD decryption.

---

## Header Protection

The 32-byte packet header (session ID, packet sequence number, packet type, flags) is protected against passive observation using a separate keystream:

```
mask = ChaCha20(hp_key, nonce=ciphertext[0..12], counter=LE32(ciphertext[12..16]))
protected_header = header XOR mask[0..32]
```

The mask is derived from the `hp_key` (a separate key derived during handshake, not used for AEAD) and the first 16 bytes of the AEAD ciphertext as a sample. This design matches QUIC's header protection (RFC 9001 section 5.4).

Consequences:
- Session IDs are not visible in plaintext — passive observer cannot correlate packets to sessions
- Sequence numbers are not visible — cannot infer packet ordering or gaps without the session key
- No fixed magic bytes — DPI engines cannot identify seam traffic by header patterns (combinable with `obfuscate = true` for additional DPI resistance)

---

## Traffic Analysis Resistance

Seam implements four optional mechanisms to reduce information leaked by traffic patterns:

### Size-class padding

Packets are padded to the nearest size-class boundary: 256, 512, 1024, or 1400 bytes. Padding bytes are random (Chaff packet type). This prevents an observer from inferring payload length from UDP datagram size.

Enabled by default in FIPS mode; disabled by default otherwise. Configure via:
```toml
traffic_padding = true
```

### Cover traffic

A background task injects encrypted random-byte Chaff packets at a configurable constant rate:
```toml
cover_traffic_kbps = 50  # 50 kbps constant traffic
```

This makes the apparent bandwidth constant regardless of actual data flow, defeating timing-volume correlation attacks.

### Timing jitter

A uniformly random per-packet delay is applied before sending:
```toml
timing_jitter_ms = 10  # 0–10 ms random delay per packet
```

This breaks timing-correlation attacks where an adversary watches both endpoints and attempts to correlate packet arrival times.

### Header obfuscation

The first 8 bytes of the protected header are XOR'd with a per-session secret derived from the handshake keys:
```toml
obfuscate = true
```

This removes any remaining fixed structure that DPI engines might use to identify seam traffic, even after header protection is applied.

---

## TOFU Host Pinning

On first connection to a host with `--tofu`:

1. The server's X25519 public key fingerprint is stored in `~/.config/seam/known_hosts`.
2. On subsequent connections, the server's key is compared against the stored fingerprint.
3. A mismatch aborts with a prominent warning analogous to SSH's `REMOTE HOST IDENTIFICATION HAS CHANGED`.

The pinned fingerprint is based on the X25519 public key (from the Noise_XX handshake). The ML-DSA-65 fingerprint is displayed separately by `seam key --list-pins`.

Pin policy is set by global flags:

| Flag | Behavior |
|---|---|
| `--tofu` | Trust-On-First-Use: pin on first connection, enforce thereafter |
| *(default)* | Enforce: require a pin to already exist |
| `--insecure-ignore-pin` | Skip pin verification entirely (loud warning; testing only) |

---

## DDoS Resistance

The server commits no per-client state until the client echoes a valid BLAKE3 cookie:

```
cookie = BLAKE3(server_secret || client_ip || client_port || timestamp_30s_bucket)
```

The cookie is bound to the client's source IP and port and expires after 30 seconds. An attacker spoofing the client's source address cannot guess the cookie (BLAKE3 preimage resistance). An attacker sending valid unspoofed Initial packets must complete the cookie round-trip before the server allocates state, limiting amplification to a single small Initial response.

---

## Identity Key Storage

The identity keypair is stored at `~/.config/seam/identity` with permissions `0600`. The file is created automatically on first use and must be backed up to maintain persistent identity across reinstalls.

File format (version 3):
```
[1]     version = 3
[32]    x25519 secret key
[4+64]  ML-KEM-768 seed (length-prefixed)
[4+1184] ML-KEM-768 public key (length-prefixed)
[4032]  ML-DSA-65 signing key
[1952]  ML-DSA-65 verify key
```

All key material is zeroized on drop using the `zeroize` crate.

---

## Key Rotation

Rotate the identity keypair with:
```sh
seam key --rotate
```

This:
1. Backs up the existing key to `identity.YYYYMMDDTHHMMSSZ` (same directory, permissions 0600)
2. Generates a new keypair
3. Writes the new key to `identity` (permissions 0600)
4. Prints old and new public keys

After rotation, update all peer configurations (relay servers, `auth-keys` files, TOFU pins) with the new public key.
