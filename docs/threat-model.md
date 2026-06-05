# Seam Protocol — Formal Threat Model

**Document Classification:** UNCLASSIFIED // FOR OFFICIAL USE ONLY  
**Version:** 1.0  
**Date:** 2026-06-05  
**Prepared by:** North9 Labs  
**Product:** Seam v0.1.32 — Post-Quantum UDP Transport Protocol  
**Status:** Pre-audit (third-party security audit not yet completed; see Section 6)

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Security Goals](#2-security-goals)
3. [Adversary Model](#3-adversary-model)
4. [Attack Surface](#4-attack-surface)
5. [Security Properties Claimed](#5-security-properties-claimed)
6. [Known Limitations and Out-of-Scope Items](#6-known-limitations-and-out-of-scope-items)
7. [Incident Response](#7-incident-response)
8. [References](#8-references)

---

## 1. System Overview

### 1.1 What Seam Is

Seam is a post-quantum encrypted UDP transport protocol and application toolkit implemented in Rust. It replaces classical encrypted transports (SSH-based `scp`, `ssh -L`, `netcat`) with a single, unified transport stack that is resistant to adversaries equipped with cryptographically-relevant quantum computers (CRQCs). Seam is designed for use in environments where long-term confidentiality of communications is required — that is, environments where an adversary may record ciphertext today and decrypt it in the future using a CRQC (the "harvest-now-decrypt-later" threat model).

Seam provides the following user-facing capabilities:

- **`seam cp`** — Quantum-safe file transfer (replaces `scp`)
- **`seam pipe`** — Quantum-safe bidirectional pipe / remote execution (replaces `netcat`)
- **`seam tunnel`** — Quantum-safe local TCP port forwarding (replaces `ssh -L`)
- **`seam fwd`** — Quantum-safe reverse TCP port forwarding (replaces `ssh -R`)
- **`seam bench`** / **`seam stats`** — Link quality measurement

All functionality is built atop a shared cryptographic session layer. No separate daemon is required; Seam bootstraps a receiver process on the remote host over an existing SSH connection and then establishes a direct UDP session.

### 1.2 Deployment Model

Seam is deployed as a peer-to-peer protocol between two endpoints. The typical deployment involves:

- **Client endpoint:** A workstation or laptop running the `seam` CLI binary, originating the connection.
- **Server endpoint:** A remote host (server, VM, bastion host) on which a Seam receiver process is bootstrapped on-demand by the client via SSH.
- **Network path:** One or more UDP paths across a potentially adversarial network (public internet, enterprise WAN, tactical network).
- **Identity store:** Per-host files at `~/.config/seam/identity` (mode 0600) containing long-term keypairs.
- **Known-hosts store:** Per-user TOFU pin database at `~/.config/seam/known_hosts` storing SHA-256 fingerprints of previously-seen server X25519 and ML-DSA-65 public keys.

Optionally, a Seamless relay may be interposed between client and server. The relay is not trusted with plaintext; all encryption is end-to-end between client and server.

### 1.3 Trust Boundaries

Seam operates across the following trust boundaries:

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  CLIENT HOST (trusted)                                           │
  │                                                                  │
  │   ~/.config/seam/identity  (mode 0600, long-term keypair)        │
  │   ~/.config/seam/known_hosts  (TOFU pin store)                  │
  │   ~/.local/share/seam/audit.jsonl  (audit log)                  │
  │                                                                  │
  │   seam CLI binary  ─────────── TCP 22 (SSH bootstrap) ─────────►│
  │        │                                                         │
  │        │  UDP (Seam session, post-quantum encrypted)             │
  └────────┼────────────────────────────────────────────────────────┘
           │
     ══════╪══════════════════════════════════════════╗  TRUST BOUNDARY
           │  UNTRUSTED NETWORK                       ║  (TB-1: client/network)
           │  (Internet / WAN / tactical link)        ║
           │                                          ║
           │  Optional: Seamless relay                ║
           │  (sees only ciphertext + metadata)       ║
           │                                          ║
     ══════╪══════════════════════════════════════════╝
           │
  ┌────────┼────────────────────────────────────────────────────────┐
  │  SERVER HOST (trusted by operator, not by protocol)             │
  │        │                                                         │
  │   seam receiver process (ephemeral, spawned by SSH)             │
  │        │                                                         │
  │   SSH daemon  ◄──────── TCP 22 (SSH bootstrap) ─────────────────│
  │                                                                  │
  │   ~/.config/seam/identity  (mode 0600, long-term keypair)        │
  └─────────────────────────────────────────────────────────────────┘

  TB-1: Client process / network wire. Seam cryptography is the
        security control at this boundary.

  TB-2: Server process / server OS filesystem. OS-level access
        controls (file permissions, user isolation) govern this
        boundary. Seam does not protect against a compromised server OS.

  TB-3: Client process / SSH daemon. SSH is used only for bootstrap;
        the Seam session is independent of SSH once established. SSH
        host-key verification and SSH authentication are prerequisites.
```

### 1.4 Data Flows

| Flow | Transport | Protection |
|------|-----------|------------|
| SSH bootstrap (binary invocation + port exchange) | TCP/SSH | SSH encryption + SSH host-key authentication |
| Seam handshake (Noise_XX + ML-KEM-768 + ML-DSA-65 identity proof) | UDP | Noise_XX AEAD; DDoS-resistant BLAKE3 cookie challenge pre-handshake |
| Seam session data (file, pipe, tunnel, datagrams) | UDP | ChaCha20-Poly1305 or AES-256-GCM AEAD + header protection + double ratchet |
| Audit log writes | Local filesystem | OS file permissions (no additional encryption) |

---

## 2. Security Goals

### 2.1 Confidentiality

**What is protected:** All application-layer data transmitted between client and server, including file contents, pipe data, tunneled TCP streams, and unreliable datagrams. The 32-byte packet header (session ID, sequence number, flags) is additionally encrypted via ChaCha20-based header protection, preventing a passive observer from correlating packets to sessions or reading packet sequence numbers.

**Mechanism:** ChaCha20-Poly1305 (default) or AES-256-GCM (FIPS mode), both with 256-bit keys. Each packet is authenticated with a 128-bit AEAD tag. The AEAD key is a function of both the Noise_XX handshake output (X25519 Diffie-Hellman) and the ML-KEM-768 encapsulation shared secret; an adversary must break both to obtain the session key.

**Condition:** Achieved for all data after the handshake is complete. SSH bootstrap data is protected only by SSH, not Seam, and must be assumed observable by parties that can observe the SSH connection.

### 2.2 Integrity

**What is protected:** Every Seam packet is integrity-protected by the AEAD tag. Modification of any bit in the ciphertext or the authenticated header causes decryption failure; the packet is silently discarded. The AEAD additionally covers the plaintext-length field, preventing padding-oracle attacks.

**Mechanism:** AEAD authentication tag (128-bit Poly1305 or GCM). Any tampered packet is rejected with certainty (probability of undetected forgery is 2^(-128), negligible).

**Identity binding:** After the Noise_XX handshake, both parties exchange `IdentityProof` messages. Each proof is an ML-DSA-65 (FIPS 204) signature over the BLAKE3 transcript hash of the entire Noise handshake, with context string `"seam-identity-proof/v1"`. This binds the long-term ML-DSA-65 identity key to the specific session, preventing key confusion across sessions.

### 2.3 Authentication

**What Seam guarantees:** Mutual authentication. Neither party can successfully complete a session with a peer that does not possess the correct private keys.

**Classical component:** Noise_XX pattern (`Noise_XX_25519_ChaChaPoly_BLAKE2s`) provides mutual authentication via X25519 static key pairs. The initiator authenticates the responder's X25519 static key in message 2; the responder authenticates the initiator's static key in message 3. The X25519 static keys are components of the long-term `IdentityKeypair`.

**Post-quantum component:** After the Noise_XX handshake, both parties exchange `IdentityProof` messages containing their ML-DSA-65 public keys and signatures (3309 bytes, FIPS 204) over the handshake transcript hash. Verification uses `mldsa_verify` with the context string `"seam-identity-proof/v1"`. This provides quantum-resistant authentication binding: even a quantum adversary cannot forge a valid ML-DSA-65 signature without the corresponding private key.

**Trust establishment:** On first connection to a host, the client stores the server's X25519 and ML-DSA-65 fingerprints in `~/.config/seam/known_hosts` (TOFU). On subsequent connections, Seam verifies both fingerprints and raises a fatal error if either has changed. The known_hosts format supports both classical-only (v1) and hybrid quantum-resistant (v2) fingerprint entries.

### 2.4 Forward Secrecy

Seam implements forward secrecy at multiple granularities:

| Granularity | Mechanism | Exposure Window |
|-------------|-----------|-----------------|
| Session | Noise_XX ephemeral X25519 + ML-KEM-768 per-session encapsulation | One session (new keys on reconnect) |
| Epoch (double ratchet DH step) | X25519 DH on new ephemeral keys; BLAKE3 KDF derives new root and chain keys | 1000 packets or 30 seconds, whichever comes first (configurable) |
| Packet (symmetric ratchet) | BLAKE3 KDF on chain key; each packet uses a unique message key | One packet |
| Key update (KEYUPDATE frame) | BLAKE3 KDF: `next_secret = BLAKE3_KDF("apex/key-update/v1", current_secret)` | One key epoch |

**Implementation details:** The `DoubleRatchet` implementation (`src/crypto/ratchet.rs`) uses `Zeroizing<[u8; 32]>` wrappers for all key material. Root key, send chain key, receive chain key, and all per-epoch ephemeral private keys are explicitly zeroized via both Rust's `Drop` trait and the `zeroize` crate on both normal and panic paths. Skipped message keys (out-of-order window, max 50 entries) are zeroized after 30 seconds TTL or on consumption, whichever is first.

**0-RTT session resumption caveat:** Session tickets (`src/transport/resumption.rs`) allow 0-RTT resumption within a 24-hour window. The code explicitly documents: `"WARNING: session tickets weaken forward secrecy — if the server ticket key leaks, past 0-RTT sessions can be decrypted."` Session tickets are an optional feature and should be disabled in high-assurance deployments.

### 2.5 Availability (DoS Resistance)

Seam implements the following DoS resistance mechanisms:

**BLAKE3 cookie challenge (pre-handshake, stateless):** Before allocating any per-client state, the server sends a 32-byte cookie computed as `BLAKE3_keyed_hash(server_secret || client_IP:port || time_bucket_30s)`. The client must echo this cookie in its first Noise message. Cookie verification uses `subtle::ConstantTimeEq` to prevent timing-based cookie forgery oracle attacks. The server allocates no memory and performs no public-key operations until a valid cookie is received.

**Packet size validation:** The maximum accepted UDP payload is 65535 bytes (`MAX_PACKET_LEN`). Any packet that exceeds the minimum size (`HEADER_LEN(32) + TAG_LEN(16) = 48 bytes`) is rejected before AEAD decryption. This prevents attacker-crafted oversized packets from consuming AEAD computation resources.

**Replay window:** A 1024-bit sliding bitmap window (`src/crypto/replay.rs`) tracks the last 1024 sequence numbers. Replayed or out-of-window packets are rejected with `SeamError::Replay` or `SeamError::TooOld` before any application processing.

**Keepalive and idle timeout:** Automatic Ping/Pong every 15 seconds; connections idle for 60 seconds are closed, freeing server resources.

**Handshake retry backoff:** The client retries the handshake up to 3 times with exponential backoff before giving up, limiting the rate at which a client can consume server handshake resources.

### 2.6 Non-Repudiation and Audit Trail

**Audit log:** Every Seam command invocation is appended to `~/.local/share/seam/audit.jsonl` (JSONL format, O_APPEND writes, POSIX-atomic for records under 4096 bytes). Each record contains: ISO-8601 UTC timestamp, subcommand, remote host, sanitized argument list (credentials redacted), exit code, bytes transferred, FIPS mode flag, and process ID. This design is documented as meeting NIST SP 800-53 AU-2 / AU-12 requirements for auditable privileged operations.

**Limitation:** The audit log is client-side only. Server-side audit trails depend on the server host's system logging (tracing spans are emitted by the Seam server component via the `tracing` crate). The audit log file is append-only by convention but is not cryptographically integrity-protected; a local administrator with write access to the user's home directory can delete or modify it.

---

## 3. Adversary Model

This section defines each adversary class, their assumed capabilities, and the guarantees Seam makes against them.

### 3.1 Passive Network Observer

**Profile:** ISP, backbone tap, nation-state passive collection, intelligence service with access to fiber taps. Can observe all packets on the network path.

**Capabilities:**
- Full packet capture of all UDP traffic between client and server
- Timing correlation of packet flows across multiple observation points
- Packet size analysis
- Protocol fingerprinting via DPI

**Seam Guarantees:**
- Cannot learn plaintext content. All payload is encrypted with ChaCha20-Poly1305 or AES-256-GCM under a 256-bit session key.
- Cannot read packet metadata (session ID, sequence number, flags). The 32-byte header is encrypted using ChaCha20-based header protection (`apply_header_protection`), keyed with a per-session `hp_key` derived independently of the encryption key.
- Cannot correlate traffic flows across sessions when TAR is enabled. With `--cover-traffic` and `--timing-jitter` enabled, the observer sees a constant-rate stream of fixed-size packets with exponentially-distributed inter-arrival times.
- Cannot determine packet contents or true payload sizes when padding is enabled. Four wire-size classes (256, 512, 1024, 1400 bytes) obscure actual payload lengths.
- **Cannot decrypt recorded traffic even with a future quantum computer.** The session key derivation requires both the X25519 shared secret and the ML-KEM-768 shared secret; breaking one primitive is insufficient.

**Residual Risk:** With TAR disabled (default for performance), a passive observer can observe inter-packet timing and size distributions. This enables statistical traffic analysis, flow correlation, and volume analysis. TAR features carry latency cost and must be explicitly enabled.

### 3.2 Active Network Attacker (MITM)

**Profile:** Adversary positioned between client and server who can inject, drop, replay, and reorder UDP packets. Includes rogue ISPs, ARP/BGP hijackers, and physical layer attackers on tactical networks.

**Capabilities:**
- Inject arbitrary UDP packets purporting to be from either party
- Drop or selectively delay legitimate packets
- Replay previously observed packets
- Reorder packets within or across sessions
- Modify packet content in transit

**Seam Guarantees:**
- **Injected packets are rejected.** Any packet not encrypted with the session AEAD key produces a 128-bit authentication failure (probability of undetected forgery: 2^(-128)). The attacker cannot forge valid AEAD tags without the session key.
- **Modified packets are rejected.** AEAD authentication covers both payload and header fields.
- **Replayed packets are rejected.** The 1024-slot sliding window anti-replay bitmap (`ReplayWindow`) detects duplicate sequence numbers. Packets with sequence numbers more than 1024 below the current window base are rejected as `TooOld`.
- **Reordered packets are tolerated.** Out-of-order delivery within the 1024-packet window is accepted. The double-ratchet skip-window (max 50 entries, 30-second TTL) handles key derivation for out-of-order packets.
- **MITM against the handshake is defeated by TOFU pinning.** An attacker who substitutes their own X25519 or ML-DSA-65 keys during a handshake will be detected on the second connection when the stored TOFU pin does not match. On a first connection (no pin exists), the client is vulnerable to MITM unless out-of-band key verification is performed.

**Residual Risk:** First-connection TOFU is vulnerable to MITM if the attacker controls the network path at the moment of first contact. Operators in high-assurance environments should establish key pins out-of-band before first connection.

### 3.3 Cryptanalytic Adversary with Quantum Computer

**Profile:** Nation-state adversary operating a cryptographically-relevant quantum computer (CRQC) capable of running Shor's algorithm to break RSA, ECC, and Diffie-Hellman, and Grover's algorithm to halve symmetric key security.

**Capabilities:**
- Break X25519 Diffie-Hellman (Shor's algorithm, polynomial time on CRQC)
- Break ECDSA/Ed25519 signatures (Shor's algorithm)
- Grover search over 256-bit symmetric keys (effective 128-bit security on CRQC)

**Seam Guarantees:**
- **ML-KEM-768 key exchange is secure against CRQC.** ML-KEM-768 (CRYSTALS-Kyber, NIST FIPS 203) achieves NIST Post-Quantum Security Level 3 (at least as hard as AES-192 against quantum search). The classical X25519 DH component is also included; breaking the session requires breaking both independently. The shared secret is `BLAKE3_derive_key("apex/x25519-component/v1", noise_hash)` XOR'd with the KEM shared secret before key derivation, ensuring that subversion of one component does not invalidate the other.
- **ML-DSA-65 identity authentication is unforgeable against CRQC.** ML-DSA-65 (CRYSTALS-Dilithium, NIST FIPS 204) at Security Level 3 provides quantum-resistant existential unforgeability. A CRQC cannot forge an ML-DSA-65 signature for a key it does not possess.
- **Session keys are not derivable by CRQC.** Because the session key depends on ML-KEM-768 (post-quantum secure), recovering the session key requires a classical attack on the KEM ciphertext, which is computationally infeasible.
- **AES-256-GCM retains 128-bit security against Grover's algorithm.** When FIPS mode is enabled, AES-256-GCM is used. Grover's algorithm reduces the effective key search space to 2^128, which remains computationally infeasible.

**Residual Risk:** The `snow` library's Noise_XX implementation uses X25519 and BLAKE2s internally. The X25519 component provides no post-quantum security; however, the hybrid construction ensures that compromising X25519 alone is insufficient — the attacker must also break ML-KEM-768. This follows the hybrid construction recommendation in NIST IR 8413.

### 3.4 Compromised Session Key

**Profile:** Adversary who has obtained the current AEAD encryption key for an active session. This could result from a memory disclosure vulnerability, cold boot attack, or insider access to a running Seam process.

**Capabilities:**
- Decrypt packets encrypted under the compromised AEAD key
- Forge AEAD-authenticated packets under the compromised key

**Seam Guarantees:**
- **Exposure is limited to the current ratchet epoch.** The double-ratchet design limits key compromise to at most 1000 packets or 30 seconds of traffic, whichever triggers the next DH ratchet step. Past epochs have been zeroized using `Zeroizing<[u8; 32]>` wrappers and explicit `zeroize()` calls in the `DoubleRatchet::drop()` implementation.
- **Future epochs are protected.** The next epoch key is derived from a DH exchange using a newly-generated ephemeral key pair. An adversary who learns the current send chain key cannot derive future epoch keys without performing X25519 DH with the next ephemeral public key, which requires the private key that has already been generated locally and zeroized.
- **Skipped message keys are bounded and time-limited.** At most 50 skipped message keys are retained (for out-of-order delivery), each with a 30-second TTL, after which they are zeroized.

**Residual Risk:** If an adversary can obtain the session key and observe traffic continuously across epoch boundaries, they may be able to correlate the session up to the next ratchet step. Key update frames (`KeyUpdate`, type 0x09) allow either party to trigger early key rotation.

### 3.5 Compromised Long-Term Identity Key

**Profile:** Adversary who obtains the long-term `IdentityKeypair` file from disk, whether through filesystem access, backup compromise, or physical media theft. The file is stored at `~/.config/seam/identity` with mode 0600 on Unix.

**Capabilities:**
- Impersonate the compromised endpoint to new peers (after TOFU pins are cleared)
- Authenticate as the legitimate party in future sessions

**Seam Guarantees:**
- **Past sessions are unaffected (forward secrecy).** Session keys are derived from ephemeral X25519 and ML-KEM-768 key material that is generated fresh for each session and zeroized after use. The long-term identity key is not a component of session key derivation. A compromised identity key does not allow decryption of previously recorded sessions.
- **TOFU pinning alerts operators to key change on reconnect.** When `seam key --rotate` is used to generate a new identity, or when a compromised key is used to impersonate a host, the mismatch against stored TOFU pins produces a fatal error with an SSH-style "REMOTE HOST IDENTIFICATION HAS CHANGED" warning. Peers who have pinned the original key will refuse connection.
- **Key rotation procedure is documented.** `seam key --rotate` backs up the existing key with a timestamp suffix, generates a new keypair, and prints both old and new public keys for relay configuration update.

**Residual Risk:** On first connection, TOFU provides no protection against an adversary who has pre-positioned a forged identity. The ML-DSA-65 identity proof provides quantum-resistant authentication, but identity trust still bootstraps through TOFU on first use unless keys are distributed out-of-band.

### 3.6 Harvest-Now-Decrypt-Later (HNDL) Adversary

**Profile:** A nation-state adversary that records encrypted Seam traffic today with the intent to decrypt it once a CRQC becomes available. Traffic from sessions established before post-quantum cryptography was deployed may be retroactively decryptable.

**Capabilities:**
- Bulk collection and archival of encrypted UDP traffic
- Future CRQC access (assumed)
- Patience (long-term archive of collected traffic)

**Seam Guarantees:**
- **ML-KEM-768 ciphertext provides NIST Level 3 security against quantum decryption.** The KEM ciphertext for each session is a function of the ML-KEM-768 encapsulation, which requires solving the Module Learning With Errors (MLWE) problem at NIST Security Level 3. No known quantum algorithm provides a meaningful speedup over classical algorithms for MLWE at this parameter set.
- **Each session uses a fresh ML-KEM-768 encapsulation.** A separate KEM ciphertext is produced for every Seam session. Compromising one session's KEM ciphertext (if that were possible) does not affect other sessions.
- **The hybrid construction prevents retroactive decryption if either primitive holds.** An HNDL adversary who archives traffic must break both the X25519 component and the ML-KEM-768 component to recover a session key. If ML-KEM-768 remains secure against CRQC (as currently assessed), archived traffic cannot be decrypted retroactively.

**Residual Risk:** If ML-KEM-768 is later found to be vulnerable (e.g., due to a mathematical break), the X25519 component provides no post-quantum resistance. However, as of NIST's finalization of FIPS 203 in August 2024, no such vulnerability is known. Operators should plan for algorithm agility and monitor NIST post-quantum standardization updates.

### 3.7 Traffic Analysis Adversary

**Profile:** Nation-state adversary or intelligence service with capabilities to correlate timing and size patterns of encrypted traffic. Includes entities operating multiple passive observation points on backbone infrastructure.

**Capabilities:**
- Inter-arrival timing measurement at microsecond precision
- Per-packet size observation
- Cross-correlation of traffic across observation points to de-anonymize endpoints
- Statistical analysis of volume and rate patterns

**Seam Guarantees (with TAR enabled):**
- **Fixed size classes prevent size-based correlation.** When `no_padding = false`, packets are padded to one of four wire sizes (256, 512, 1024, or 1400 bytes using class boundaries in `PacketSizeClass`). An observer cannot determine true payload size.
- **Cover traffic prevents rate-based inference.** `CoverTrafficConfig` maintains a target bitrate by injecting encrypted random-byte cover packets (`Chaff` packet type 0x05) when real data rate is below target. Cover packets are identical in size and format to real packets; an observer cannot distinguish them from application data.
- **Per-packet timing jitter breaks timing-correlation attacks.** `JitterConfig::sample_delay()` introduces a random delay of 0–N milliseconds (configurable) before each send, using an LCG seeded from session state. This prevents precise inter-arrival timing fingerprinting.
- **Protocol fingerprint obfuscation.** When `obfuscate = true`, the first 8 bytes of each packet are XORed with a per-session BLAKE3-derived mask (`derive_obfuscation_secret`), preventing DPI engines from detecting a fixed magic-number header.
- **Chaff scheduler uses exponentially-distributed inter-packet intervals.** `ChaffScheduler::mark_sent()` draws intervals from an approximate exponential distribution (mean 50ms, clamped to [12.5ms, 200ms]). Exponential inter-arrival is memoryless, making it harder to distinguish from random background traffic.

**Seam Guarantees (TAR disabled, default):**
- No traffic-analysis resistance is provided. An observer can observe packet sizes, rates, and timing. TAR is disabled by default for performance reasons.

**Residual Risk:** With TAR enabled, high-volume transfers may still be partially distinguishable from idle connections by aggregate data volume, even when individual packets are size-padded. Cover traffic adds bandwidth overhead equal to the configured target bitrate. In practice, sufficiently determined adversaries with multiple observation points may still be able to perform endpoint correlation, particularly for long-duration sessions.

### 3.8 Denial-of-Service Attacker

**Profile:** Adversary attempting to exhaust server resources (memory, CPU, sockets) or network bandwidth by flooding the server with connection attempts or data.

**Capabilities:**
- Send high volumes of UDP packets to the server's listening address
- Spoof source IP addresses (on networks without BCP 38 filtering)
- Send oversized or malformed UDP payloads

**Seam Guarantees:**
- **No per-client state is allocated before cookie validation.** The server's `ServerWaitCookie` state sends a stateless BLAKE3 cookie challenge (32 bytes) in response to any `CookieRequest` packet (type 0x10). No session state is allocated until the client echoes a valid cookie (`CookieEcho`, type 0x12). An attacker spoofing source IPs cannot complete the cookie challenge because the cookie is bound to the claimed source IP:port via `blake3::keyed_hash(server_secret || client_addr || time_bucket)`.
- **Oversized packets are rejected before AEAD.** Any UDP payload exceeding 65535 bytes is hard-rejected without cryptographic processing.
- **Packets shorter than the minimum length (48 bytes) are discarded.** This prevents crafted short packets from triggering out-of-bounds array accesses in the decoder.
- **Idle connections are closed after 60 seconds.** Server-side resources for idle sessions are reclaimed automatically.
- **Cookie verification uses constant-time comparison.** `subtle::ConstantTimeEq` prevents timing oracle attacks on cookie bytes that could accelerate forgery.

**Residual Risk:** A volumetric UDP flood can saturate network interfaces and degrade service for legitimate users regardless of protocol-level defenses. Network-layer rate limiting and upstream DDoS mitigation (e.g., BCP 38 enforcement, RTBH, anycast scrubbing) remain necessary for high-availability deployments. Seam does not implement connection-rate limiting or per-IP connection quotas at the application level; operators should configure these at the network layer.

### 3.9 Compromised Relay (Seamless Relay)

**Profile:** The optional Seamless relay between client and server is compromised by an adversary who gains full control of the relay process and memory.

**Capabilities:**
- Observe all UDP packets transiting the relay (source/destination IP, sizes, timing)
- Modify or drop packets in transit
- Inject packets into the relay's UDP stream

**Seam Guarantees:**
- **End-to-end encryption means the relay cannot read plaintext.** All Seam session encryption is between the client and server endpoints. The relay does not possess session keys and cannot decrypt payload contents.
- **Modified packets are rejected by AEAD.** Relay-injected or relay-modified packets are indistinguishable from attacker-injected packets at the AEAD level; they will fail authentication and be silently dropped.
- **Relay compromise leaks only metadata.** A compromised relay can observe: (a) client and server IP addresses and UDP ports, (b) packet sizes (unless TAR padding is enabled), (c) inter-packet timing, (d) session duration, and (e) approximate data volume. It cannot read payload contents.

**Residual Risk:** Relay metadata (connection graph, timing, volume) may be significant in some threat models. Operators in high-sensitivity environments should assume relay metadata is observable by adversaries and apply appropriate compartmentalization.

---

## 4. Attack Surface

### 4.1 UDP Socket (Public-Facing)

**Location:** Bound to `0.0.0.0:<port>` or a specific interface on the server.

**Threats:**
- **Packet injection:** Any reachable adversary can send UDP packets to the server's port. Mitigated by the BLAKE3 cookie challenge (pre-handshake) and AEAD authentication (post-handshake). No valid response is produced for unauthenticated packets.
- **Amplification attacks:** A spoofed `CookieRequest` (1 byte) elicits a `CookieChallenge` response (33 bytes), producing a ~33x amplification factor. This is a modest amplification risk. Operators should deploy rate limiting on cookie responses to mitigate amplification abuse.
- **Reflection:** UDP source-IP spoofing can cause cookie challenge packets to be sent to spoofed victims. BCP 38 enforcement at the network layer is the primary mitigation; Seam cannot prevent reflection at the application layer.
- **State exhaustion:** The cookie mechanism prevents per-client memory exhaustion. CPU exhaustion via high-volume `CookieRequest` floods remains a risk; kernel-level UDP socket buffer limits and network-layer rate limiting are the appropriate controls.

### 4.2 Identity File on Disk

**Location:** `~/.config/seam/identity` (mode 0600 on Unix, generated by `IdentityKeypair::load_or_generate`).

**Content:** Version byte (3) + X25519 secret key (32 bytes) + ML-KEM-768 seed (64 bytes) + ML-KEM-768 public key (1184 bytes) + ML-DSA-65 private key (4032 bytes) + ML-DSA-65 public key (1952 bytes).

**Threats:**
- **Filesystem read access:** A local adversary with read access to the identity file (e.g., root, another user on a misconfigured system) can extract all three private keys (X25519, ML-KEM-768, ML-DSA-65), enabling full impersonation of the compromised identity and, for active sessions, potential session key derivation if the ML-KEM decapsulation key is usable.
- **Backup compromise:** If the identity file is included in unencrypted backups, the same risks apply to anyone who can access the backup.
- **File deletion:** Deleting the identity file causes Seam to generate a new identity on next use, breaking all existing TOFU pins for remote hosts that expected the old identity.

**Mitigations currently implemented:** File created with mode 0600 (owner read/write only). Key rotation creates a timestamped backup before overwriting. No additional encryption of the identity file is currently performed (at-rest encryption depends on OS-level facilities such as LUKS or FileVault).

**Recommended operator action:** Store identity files on encrypted filesystems. Exclude Seam identity files from unencrypted backup sets. Monitor access to the identity file via auditd or equivalent.

### 4.3 Known-Hosts File

**Location:** `~/.config/seam/known_hosts` (text file, world-readable by default on most Unix systems).

**Content:** Hostname + SHA-256 fingerprint of server X25519 key, optionally including `mldsa65:<fingerprint>` for post-quantum identity pinning.

**Threats:**
- **File modification (TOFU bypass):** An adversary with write access to `~/.config/seam/known_hosts` can silently remove a host's TOFU pin, allowing a subsequent MITM attack on reconnection without triggering a warning. Alternatively, an attacker could modify the stored fingerprint to match the fingerprint of a key they control.
- **Information disclosure:** The known_hosts file reveals which hosts the user connects to, which may itself be sensitive metadata.

**Mitigations currently implemented:** File is written atomically via a rename of a `.tmp` file. Key-change warnings are prominently displayed and fatal (connection is refused) when a mismatch is detected.

**Recommended operator action:** Set `known_hosts` file permissions to 0600. Consider read-only bind mounts for the `~/.config/seam/` directory in high-sensitivity deployments. Maintain out-of-band records of expected fingerprints.

### 4.4 Configuration File

**Location:** `~/.config/seam/config.toml` (parsed by `seam config`).

**Content:** Default settings including congestion control algorithm, compression flag, cipher suite preference, FEC parameters, and identity path.

**Threats:**
- **Cipher downgrade via config modification:** An adversary with write access to `config.toml` could change the default cipher suite from `aes256gcm` to `chacha20poly1305` (or vice versa), or disable TAR features. In isolation, changing the cipher suite does not break security (both supported ciphers are considered secure); however, disabling TAR could expose traffic analysis metadata.
- **Path injection:** Modifying `identity_path` in config could redirect Seam to load a different identity file.
- **FEC parameter manipulation:** Setting extreme FEC parameters could degrade performance but is unlikely to affect security properties.

**Mitigations currently implemented:** Config values are validated by the application before use. Cipher negotiation requires mutual agreement; a unilaterally-downgraded client will only use the weaker cipher if the server also agrees.

### 4.5 SSH Bootstrap Channel

**Location:** TCP port 22 (or custom SSH port) on the server.

**Nature of exposure:** Seam uses SSH only during the bootstrap phase to invoke the remote receiver binary and read back UDP connection parameters. The Seam session is independent of SSH once established.

**Threats:**
- **SSH host-key impersonation:** If SSH host-key verification is disabled or the SSH known_hosts file is compromised, an adversary controlling the SSH session can substitute a malicious receiver binary, inject false connection parameters, or observe the bootstrap exchange. The Seam session subsequently established would be with the attacker rather than the legitimate server.
- **SSH credential exposure:** Seam respects `~/.ssh/config` and uses the user's SSH agent or key files. Compromise of SSH private keys or the SSH agent allows the attacker to perform the bootstrap on behalf of the user.
- **Remote binary execution:** The bootstrap installs a Seam receiver binary on the remote host if one is not already present (downloaded from `https://install.north9.org/seam.sh`). This download is over HTTPS with SHA-256 checksum verification; however, supply-chain compromise of the installer or download server could substitute a malicious binary.

**Mitigations:** The Seam TOFU pin established after the first successful session mitigates subsequent SSH-MITM attacks — the server's Seam identity must match the stored TOFU pin even if the SSH host key changes. Operators should verify SSH host keys independently and use pre-installed binaries rather than auto-bootstrapping in high-security environments.

**Recommended operator action:** Verify SSH host keys out-of-band. Pre-install Seam binaries with verified checksums rather than relying on auto-bootstrap in sensitive environments. Enforce SSH certificate authentication to eliminate credential-based attacks.

### 4.6 Audit Log

**Location:** `~/.local/share/seam/audit.jsonl` (O_APPEND writes, POSIX-atomic for records under 4096 bytes).

**Threats:**
- **Log deletion:** An adversary with user-level filesystem access can delete or truncate the audit log, eliminating the record of malicious activity. The log is not write-protected by any access control beyond file ownership.
- **Log injection:** The `args` field in each audit entry is described as "sanitized" (credentials/keys redacted), but a malicious remote hostname or path argument could potentially inject control characters or JSON-breaking content. Seam uses `serde_json` for serialization, which escapes special characters, making this low-risk.
- **Log overflow:** No log rotation is implemented. On long-running endpoints the audit log may grow without bound.

**Mitigations currently implemented:** Writes use `O_APPEND` mode for POSIX atomicity. Failure to write the audit log is non-fatal (warns to stderr but does not abort the operation).

**Recommended operator action:** Forward audit log entries to a centralized, append-only logging system (e.g., syslog forwarding, SIEM integration) that is not writable by the user being audited. Implement log rotation via `logrotate` or equivalent.

---

## 5. Security Properties Claimed

The following table enumerates the security properties Seam claims, the specific mechanism implementing each property, and the conditions under which the property holds. Evaluators should verify implementation against the cited source files.

| Property | Mechanism | Implementation Reference | Condition |
|---|---|---|---|
| Payload confidentiality | ChaCha20-Poly1305 (256-bit key) | `src/crypto/mod.rs`: `ChaCha20Poly1305Cipher` | Default, always applied to session data |
| Payload confidentiality (FIPS mode) | AES-256-GCM (256-bit key) | `src/crypto/mod.rs`: `Aes256GcmCipher` | `--fips-mode` or `aes256gcm` cipher configured on both sides |
| Header confidentiality | ChaCha20 stream cipher XOR of 32-byte header, keyed with `hp_key` derived from session secret | `src/crypto/header.rs`: `apply_header_protection` | Always applied post-handshake |
| Post-quantum key exchange | ML-KEM-768 (NIST FIPS 203, Security Level 3) encapsulation combined with X25519 via hybrid construction | `src/handshake/hybrid_keys.rs`: `kem_encapsulate`, `kem_decapsulate`, `HybridSharedSecret` | Always; per-session |
| Post-quantum identity authentication | ML-DSA-65 (NIST FIPS 204, Security Level 3) signature over BLAKE3 handshake transcript, context `"seam-identity-proof/v1"` | `src/handshake/state.rs`: `IdentityProof::sign`, `IdentityProof::verify` | Post-handshake identity proof exchange; requires both parties to support v3 identity format |
| Classical mutual authentication | Noise_XX pattern (`Noise_XX_25519_ChaChaPoly_BLAKE2s`) via `snow` crate | `src/handshake/state.rs`: `ClientHandshake`, `ServerHandshake` | Always; part of 3-message handshake |
| Session-level forward secrecy | Fresh X25519 ephemeral key + ML-KEM-768 encapsulation per session; static keys not used in key derivation | `src/handshake/state.rs`: `write_msg3_and_finish`, `read_msg3_and_finish` | Each new session |
| Epoch-level forward secrecy (double ratchet DH step) | X25519 DH on new ephemeral keys; BLAKE3 KDF derives new root, send-chain, recv-chain keys; old keys zeroized | `src/crypto/ratchet.rs`: `DoubleRatchet::advance_send_ratchet`, `apply_peer_ratchet_step` | Triggered at 1000-packet or 30-second epoch limit; configurable |
| Per-packet forward secrecy (symmetric ratchet) | `ratchet_step()`: BLAKE3 KDF derives independent chain key update and message key per packet | `src/crypto/ratchet.rs`: `ratchet_step` | Each transmitted packet |
| Session key update (KEYUPDATE) | One-way BLAKE3 KDF chain: `next_secret = BLAKE3_KDF("apex/key-update/v1", current_secret)`; old secret zeroized | `src/crypto/rekey.rs`: `KeySchedule::rotate` | On KEYUPDATE frame receipt or send |
| Replay prevention | 1024-bit sliding bitmap window indexed by 64-bit sequence number; `SeamError::Replay` on duplicate, `SeamError::TooOld` on out-of-window | `src/crypto/replay.rs`: `ReplayWindow::check_and_insert` | Always applied on receive path |
| DDoS-resistant handshake | Stateless BLAKE3 cookie challenge; server allocates no state until valid cookie echoed; constant-time cookie comparison | `src/handshake/cookie.rs`: `CookieFactory`; `src/transport/connection.rs`: `ServerWaitCookie` phase | Always; server-side |
| TOFU identity pinning (X25519) | SHA-256 fingerprint of X25519 public key stored in `known_hosts`; fatal error on mismatch | `src/bin/seam/known_hosts.rs`: `verify_or_pin` | When `--tofu` or `Enforce` policy active |
| TOFU identity pinning (ML-DSA-65, quantum-resistant) | SHA-256 fingerprint of ML-DSA-65 public key stored in `known_hosts` (v2 format: `mldsa65:<hex>`) | `src/bin/seam/known_hosts.rs`: `mldsa_fingerprint` | When v2 known_hosts format in use |
| Traffic padding (size classes) | Packets padded to 256 / 512 / 1024 / 1400-byte wire-size classes using LCG-generated random padding bytes | `src/transport/tar.rs`: `pad_to_size_class`, `PacketSizeClass` | `no_padding = false` (opt-in) |
| Cover traffic | Encrypted random-byte packets injected at configured bitrate to maintain constant-rate appearance | `src/transport/tar.rs`: `TarState::cover_payload`, `CoverTrafficConfig` | `cover.target_kbps > 0` (opt-in) |
| Timing jitter | Per-packet LCG random delay 0–N ms before send; recommended ≤10ms for interactive, ≤50ms for bulk transfer | `src/transport/tar.rs`: `JitterConfig::sample_delay` | `max_jitter_ms > 0` (opt-in) |
| Protocol fingerprint obfuscation | First 8 bytes of each packet XORed with BLAKE3-derived per-session mask | `src/transport/tar.rs`: `obfuscate_header`, `derive_obfuscation_secret` | `obfuscate = true` (opt-in) |
| Chaff scheduling (exponential inter-packet intervals) | Chaff packets at exponentially-distributed intervals (mean 50ms); MTU padding to path MTU | `src/transport/chaff.rs`: `ChaffScheduler` | `ChaffScheduler::enable()` called |
| Multi-path redundancy (anti-jamming) | Simultaneous transmission on all active paths; per-path and global dedup windows (64 packets) prevent duplicate delivery | `src/transport/multipath.rs`: `MultiPathEndpoint`, `PathScheduler::Redundant` | Multiple network interfaces configured |
| Audit logging | JSONL O_APPEND log at `~/.local/share/seam/audit.jsonl`; records timestamp, subcommand, remote, exit code, bytes, FIPS flag, PID | `src/bin/seam/audit.rs`: `AuditEntry`, `log()` | Always; non-fatal if write fails |
| Key zeroization | `Zeroizing<[u8; 32]>` wrappers on all key material; explicit `zeroize()` in `Drop` impls for `DoubleRatchet`, `KeySchedule`, `PacketKeys` | `src/crypto/ratchet.rs`, `src/crypto/rekey.rs`, `src/crypto/keys.rs` | Always; on session close and on panic |
| Cipher negotiation (downgrade resistance) | AES-256-GCM used only if both sides indicate preference; defaults to ChaCha20-Poly1305 otherwise | `src/handshake/state.rs`: `ServerHandshake::read_msg1` negotiation | Always; negotiated in handshake |
| Identity key permissions | Identity file created with mode 0600 on Unix; mode set atomically after write | `src/handshake/hybrid_keys.rs`: `IdentityKeypair::load_or_generate` | Unix platforms |

---

## 6. Known Limitations and Out-of-Scope Items

### 6.1 Endpoint Compromise

Seam does not protect against compromise of the client or server operating system. If an adversary gains OS-level access (root or process injection), all key material in memory, all files on disk, and all network traffic may be exposed. Seam's memory zeroization (`Zeroizing<>`, explicit `zeroize()` calls) reduces the window of key exposure in memory but cannot prevent a persistent adversary with OS access from reading key material during active sessions.

**Mitigation:** Deploy on hardened OS configurations with enforced Mandatory Access Control (SELinux, AppArmor), minimal software installation, and tamper-evident boot chains (UEFI Secure Boot, measured boot). Consult NIST SP 800-53 SI-7 and NIST SP 800-193.

### 6.2 Side-Channel Attacks

Seam does not claim resistance to hardware side-channel attacks (power analysis, electromagnetic analysis, cache-timing attacks on crypto primitives). The underlying cryptographic libraries (`ml-kem` v0.3, `fips204` v0.4, `chacha20poly1305` v0.10, `aes-gcm` v0.10) may provide varying degrees of constant-time execution depending on platform and compiler optimizations.

**Notable:** The `CookieFactory::verify` function uses `subtle::ConstantTimeEq` explicitly to prevent timing side-channels in cookie comparison. The AEAD implementations from the `RustCrypto` ecosystem use constant-time operations for their authentication tag comparisons. ML-KEM and ML-DSA constant-time properties depend on the respective crate implementations.

### 6.3 Traffic Analysis Resistance (TAR) Latency Tradeoff

Traffic analysis resistance features impose latency overhead:

| Feature | Typical Latency Impact |
|---------|----------------------|
| Packet padding | Negligible (padding is CPU-bound, not latency-bound) |
| Cover traffic | None to application data; adds bandwidth overhead |
| Timing jitter (interactive) | 0–10ms added latency per packet |
| Timing jitter (bulk transfer) | 0–50ms added latency per packet; significant impact on throughput |
| Chaff scheduler jitter | 0–5ms per packet |

**Recommendation:** Enable `max_jitter_ms ≤ 10` for interactive sessions (shells, tunnels) and accept up to 50ms for bulk file transfers if traffic analysis resistance is required. Full TAR mode with 50ms jitter and cover traffic is not suitable for real-time applications (VoIP, video).

### 6.4 Multi-Path Requirements

Multi-path operation (`MultiPathEndpoint`) requires multiple independent network interfaces on the sending endpoint. This is available in military tactical environments with multi-radio hardware but is not commonly available on standard enterprise or consumer endpoints. Without multiple interfaces, the `Redundant` scheduler provides no anti-jamming benefit.

### 6.5 SSH Bootstrap Security Dependency

The bootstrap phase establishes the initial connection via SSH. The security of the bootstrap is bounded by the security of the SSH implementation and configuration on both endpoints. Specifically:

- If SSH host-key verification is not enforced (e.g., `StrictHostKeyChecking=no` in `~/.ssh/config`), the bootstrap is vulnerable to MITM.
- If SSH authentication uses password-based credentials, brute-force or phishing attacks against SSH credentials can enable bootstrap-phase MITM.
- The auto-bootstrap feature downloads a Seam binary from `https://install.north9.org/seam.sh` with SHA-256 checksum verification. A supply-chain compromise of the installer service would compromise the server-side binary.

**Mitigation:** After the first successful connection with TOFU pinning, subsequent sessions verify the server's Seam identity against the stored pin, regardless of SSH state. However, the very first connection remains dependent on SSH integrity. Operators should pre-install Seam binaries via verified package management rather than relying on auto-bootstrap.

### 6.6 No Formal Verification

The Seam protocol has not been formally modeled or verified using tools such as ProVerif, Tamarin Prover, or CryptoVerif. The handshake protocol closely follows the Noise_XX pattern (which has been formally analyzed) and standard double-ratchet design (which has received formal analysis in the context of Signal Protocol), but the specific hybrid ML-KEM augmentation and identity proof extensions have not been independently verified.

**Status:** Formal verification (ProVerif/Tamarin model of the hybrid Noise_XX + ML-KEM-768 + ML-DSA-65 handshake) is planned but not yet available.

### 6.7 No Third-Party Security Audit

As stated in the README: "Seam is pre-1.0 software. The cryptographic design follows well-established patterns and uses audited primitives, but the protocol itself has not undergone a third-party security audit. Do not use it where your threat model requires independently audited software."

**Recommendation for government deployments:** A third-party cryptographic and security protocol audit is strongly recommended before use in environments processing classified information or where loss or compromise of communications would have significant national security impact.

### 6.8 0-RTT Session Tickets (Reduced Forward Secrecy)

The 0-RTT session resumption feature (`src/transport/resumption.rs`) stores traffic keys in a server-issued ticket encrypted with a long-term server ticket key. If this ticket key is compromised, past 0-RTT session keys may be recoverable, weakening forward secrecy for those sessions. The code explicitly documents this with `WEAKER_FS_WARNING`.

**Recommendation:** Disable session tickets (`SessionTicket` packet type 0x0D) in high-assurance deployments that prioritize forward secrecy over connection latency.

### 6.9 LCG-Based Randomness for Non-Security Purposes

Several TAR components (`pad_to_size_class`, `JitterConfig::sample_delay`, `ChaffScheduler::mark_sent`) use a linear congruential generator (LCG) for generating random padding bytes and jitter values. The LCG is explicitly chosen for performance (no OS entropy calls per packet). This is appropriate for these use cases because:

- Padding content is not secret (it follows ciphertext and is discarded by the receiver).
- Jitter values are statistical countermeasures, not cryptographic secrets.

The LCG is **not** used for any cryptographic key generation. All cryptographic key material uses `OsRng` (OS entropy, i.e., `getrandom`) as required by NIST SP 800-90A.

---

## 7. Incident Response

### 7.1 Suspected Identity Key Compromise

**Indicators:** Unexpected key-change warnings on peer systems, reports of unauthorized connections from endpoints using your identity fingerprint, or confirmed unauthorized access to the identity file.

**Response procedure:**

```sh
# 1. Rotate the identity keypair immediately. Creates a timestamped backup.
seam key --rotate

# 2. Record the new and old public key fingerprints from the rotation output.

# 3. Update all Seamless relay configurations with the new public keys.
#    (Relay configuration is deployment-specific; contact relay operators.)

# 4. Notify all known peers to remove the old identity pin and re-pin on
#    next connection:
seam key --list-pins                    # see all pinned hosts on your side
seam key --remove-pin <host>            # remove specific pin (will re-TOFU on next connect)

# 5. On peer systems that pinned your old identity, they must run:
seam known_hosts --remove <your-hostname>

# 6. Preserve the old identity file backup for forensic analysis.
#    The backup is at ~/.config/seam/identity.<YYYYMMDDTHHMMSSZ>

# 7. Review the audit log for suspicious activity.
seam audit show --since <date-of-suspected-compromise> --json | \
    tee incident-audit-$(date +%Y%m%d).jsonl
```

**Cryptographic impact assessment:** Past sessions established before key compromise are protected by forward secrecy — the compromised identity key does not enable decryption of past sessions. New sessions initiated by an adversary using the compromised key will be blocked by TOFU mismatches on peers who have already pinned the legitimate identity.

### 7.2 Suspected Man-in-the-Middle Attack

**Indicators:** `seam` displays a "REMOTE HOST IDENTIFICATION HAS CHANGED" error with a fingerprint mismatch, or a peer reports unexpected identity changes.

**Response procedure:**

```sh
# 1. Do NOT use --insecure-ignore-pin. Abort the connection.

# 2. Verify the expected server identity out-of-band (phone, separate channel).
#    Obtain the expected ML-DSA-65 fingerprint from the server operator.

# 3. On the server, display the current identity:
seam key                                # shows X25519, ML-KEM-768, ML-DSA-65 fingerprints

# 4. Compare the displayed fingerprint against what the client was offered.
#    If they do not match, the network path is actively compromised.

# 5. If the key has legitimately changed (e.g., server reinstall, rotation):
seam key --remove-pin <server-hostname> # on the client
# Reconnect; Seam will re-TOFU with the new key.

# 6. If MITM is confirmed, escalate per your organization's incident response plan.
#    Rotate relay keys and audit all connections made during the suspected MITM window.

# 7. Review audit logs for the affected host and time window:
seam audit show --host <server-hostname> --since <start-date>
```

### 7.3 Suspected Session Key Compromise

**Indicators:** Evidence that an active session's encrypted traffic has been decrypted by an unauthorized party, or a memory disclosure vulnerability is discovered in the Seam binary.

**Response procedure:**

1. Terminate all active Seam sessions to the affected endpoint immediately. The double ratchet's epoch-limited exposure means that zeroizing in-memory keys on termination limits the exposure window.
2. If the Seam binary has a known memory disclosure vulnerability, update to a patched version before re-establishing sessions.
3. The session key compromise does not expose past session keys (forward secrecy) or the long-term identity key (keys are derived independently). Assess whether future sessions need additional protective measures.
4. Review the audit log for the session in question to determine what data was in transit during the estimated compromise window.

### 7.4 Audit Log Review and Integrity

```sh
# Review recent activity
seam audit show -n 50

# Review activity since a specific date (ISO 8601)
seam audit show --since 2026-01-01

# Review activity to a specific remote
seam audit show --host bastion.example.gov

# Export to JSONL for SIEM ingestion
seam audit show --json --since 2026-01-01 > /var/log/seam-export.jsonl
```

**Note:** The audit log is client-side only and is not tamper-evident. For forensic purposes, contemporaneous forwarding of audit log entries to a centralized SIEM (via syslog or log shipping) is strongly recommended. The audit log `clear` command requires explicit confirmation and should be restricted via OS-level access controls in high-assurance environments.

---

## 8. References

| Document | Description |
|----------|-------------|
| NIST FIPS 203 (August 2024) | Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM / CRYSTALS-Kyber) |
| NIST FIPS 204 (August 2024) | Module-Lattice-Based Digital Signature Standard (ML-DSA / CRYSTALS-Dilithium) |
| NIST IR 8413 (September 2022) | Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process |
| NIST SP 800-56C Rev. 2 | Recommendation for Key-Derivation Methods in Key-Establishment Schemes |
| NIST SP 800-90A Rev. 1 | Recommendation for Random Number Generation Using Deterministic Random Bit Generators |
| NIST SP 800-53 Rev. 5 | Security and Privacy Controls for Information Systems and Organizations (AU-2, AU-12, SI-7) |
| NSA CNSA 2.0 (September 2022) | Commercial National Security Algorithm Suite 2.0 (requires ML-KEM-768+, ML-DSA-65+, AES-256-GCM) |
| RFC 8446 | The Transport Layer Security (TLS) Protocol Version 1.3 (reference for key schedule design patterns) |
| Noise Protocol Framework (rev. 34) | Specification for the Noise handshake pattern family; specifically Noise_XX |
| Signal Double Ratchet Algorithm | Trevor Perrin, Moxie Marlinspike (2016) — foundational specification for the double ratchet design implemented in `src/crypto/ratchet.rs` |
| RFC 6298 | Computing TCP's Retransmission Timer (EWMA RTT estimation, referenced in `src/transport/multipath.rs`) |
| BLAKE3 Specification | O'Connor et al. — hash and KDF used throughout for key derivation with domain-separated context strings |
| `ml-kem` crate v0.3 | Rust implementation of FIPS 203 ML-KEM-768 |
| `fips204` crate v0.4 | Rust implementation of FIPS 204 ML-DSA-65 |
| `snow` crate v0.9 | Rust implementation of the Noise Protocol Framework |
| `chacha20poly1305` crate v0.10 | RustCrypto ChaCha20-Poly1305 AEAD implementation |
| `aes-gcm` crate v0.10 | RustCrypto AES-256-GCM AEAD implementation |
| `zeroize` crate v1 | Secure memory zeroization for key material |
| `subtle` crate v2 | Constant-time cryptographic comparison primitives |

---

*This document was prepared by North9 Labs for the Seam v0.1.32 release. It reflects the state of the implementation as read from the source tree at the time of writing. Security properties are conditional on correct implementation; evaluators should perform independent code review against the source files cited in Section 5. This document does not constitute a security certification or accreditation.*
