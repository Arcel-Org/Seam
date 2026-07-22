# FIPS Mode

Seam includes a FIPS-140 compliant mode that restricts algorithm selection to NIST-approved algorithms and enforces additional policy requirements. This document describes what FIPS mode changes, how to enable it, and what compliance it targets.

---

## What FIPS Mode Does

When FIPS mode is active, Seam makes the following changes:

| Component | Normal mode | FIPS mode |
|---|---|---|
| AEAD cipher | ChaCha20-Poly1305 | AES-256-GCM (FIPS 197) |
| File integrity hash | BLAKE3 | SHA-256 (FIPS 180-4) |
| Traffic padding | Disabled (default) | Enabled (default) |
| Startup banner | Silent | Prints algorithm list to stderr |

The following components are **unchanged** by FIPS mode (they use NIST-approved algorithms regardless):

| Component | Algorithm | FIPS citation |
|---|---|---|
| Post-quantum KEM | ML-KEM-768 | FIPS 203 |
| Post-quantum identity signature | ML-DSA-65 | FIPS 204 |
| Classical key agreement | X25519 | NIST SP 800-186 |
| Noise handshake hash | BLAKE2s (internal to snow crate) | — |
| DDoS cookie | BLAKE3 (internal) | — |

> Note: BLAKE3 is retained for the Noise handshake transcript and DDoS cookie because those are internal protocol mechanisms not visible to external observers. The Noise Protocol Framework specifies BLAKE2s as the hash function for the `Noise_XX_25519_ChaChaPoly_BLAKE2s` pattern; replacing it would break the handshake. External-facing integrity (file checksums sent over the wire) use SHA-256 in FIPS mode.

---

## FIPS Startup Banner

When FIPS mode is active, Seam prints a banner to stderr at startup:

```
FIPS mode active: AES-256-GCM (FIPS 197), ML-KEM-768 (FIPS 203), X25519 (SP 800-186), SHA-256 (FIPS 180-4)
```

This banner appears before any command runs. In scripted environments, redirect stderr to capture it:

```sh
seam --fips-mode cp ./data alice@server:/dest 2>seam-fips.log
```

---

## How to Enable FIPS Mode

FIPS mode can be enabled from three sources. Later sources override earlier ones:

### 1. Config file (persistent)

```sh
seam config set fips_mode true
```

This writes `fips_mode = true` to `~/.config/seam/config.toml`. All subsequent `seam` invocations will use FIPS mode unless overridden.

Alternatively, edit the file directly:

```toml
# ~/.config/seam/config.toml
fips_mode = true
cipher = "aes256gcm"
```

### 2. Environment variable

```sh
export SEAM_FIPS_MODE=1
seam cp ./data alice@server:/dest

# Or inline:
SEAM_FIPS_MODE=1 seam cp ./data alice@server:/dest
```

Accepted values: `1` or `true` (case-insensitive). Any other value (including empty string) is treated as false.

### 3. CLI flag (per-invocation)

```sh
seam --fips-mode cp ./data alice@server:/dest
seam --fips-mode serve --port 2222
seam --fips-mode shell alice@server
```

The `--fips-mode` flag is a global flag and applies to all subcommands.

---

## FIPS Mode and Cipher Selection

In FIPS mode, AES-256-GCM is **required**. If `--cipher chacha20poly1305` is explicitly passed alongside `--fips-mode`, seam exits with an error:

```
FIPS mode is active: ChaCha20-Poly1305 is not FIPS-approved.
Use --cipher aes256gcm or remove --cipher to use the FIPS-required AES-256-GCM.
```

The correct invocation when FIPS mode is active is either:
- Omit `--cipher` (FIPS mode auto-selects AES-256-GCM)
- Pass `--cipher aes256gcm` explicitly

---

## Effect on seam serve

When `seam serve` is started with `--fips-mode`, the server:

- Uses AES-256-GCM for all sessions (clients that negotiate ChaCha20-Poly1305 are downgraded to AES-256-GCM)
- Prints the cipher in its startup output: `Cipher: AES-256-GCM (FIPS mode)`
- Enables traffic padding by default

```sh
seam serve --fips-mode --port 2222
```

Startup output:

```
  seam serve — post-quantum Seam daemon  v1.0.2
  Listening:   udp://0.0.0.0:2222
  X25519 key:  <hex>
  KEM key:     <hex>…
  Cipher:      AES-256-GCM (FIPS mode)
```

---

## Effect on seam cp and seam sync

In FIPS mode, file integrity checksums use SHA-256 (FIPS 180-4) instead of BLAKE3:

- The checksum algorithm is negotiated implicitly: if both client and server are in FIPS mode, SHA-256 is used; otherwise BLAKE3 is used.
- The algorithm name is printed in the transfer completion message.
- On checksum mismatch in FIPS mode, the error message identifies the algorithm: `integrity check failed for <file>: receiver reported SHA-256 hash mismatch`

---

## FIPS Citation Table

| Algorithm | FIPS document | Role in Seam |
|---|---|---|
| AES-256-GCM | FIPS 197 (AES) + NIST SP 800-38D (GCM) | Packet AEAD encryption (FIPS mode) |
| ML-KEM-768 | FIPS 203 | Post-quantum key encapsulation |
| ML-DSA-65 | FIPS 204 | Post-quantum identity signature |
| SHA-256 | FIPS 180-4 | File integrity checksums (FIPS mode) |
| X25519 | NIST SP 800-186 | Classical key agreement (Noise_XX) |

---

## Verifying FIPS Mode is Active

### CLI check

```sh
seam version
```

Look for `Traffic analysis resistance` — in FIPS mode, `size-class padding` is listed.

```sh
seam version --json | jq '.traffic_analysis_resistance.size_class_padding'
```

Returns `true` when FIPS mode is active (and `traffic_padding` is not explicitly disabled in config).

### Audit log check

Every audit log entry includes a `fips_mode` boolean field. To confirm all recent operations used FIPS mode:

```sh
seam audit show --json | jq 'select(.fips_mode == false)'
```

An empty result means all shown entries had FIPS mode active.

### Startup banner

The startup banner is the most reliable signal. In scripted environments, check stderr:

```sh
seam --fips-mode version 2>&1 | grep -q "FIPS mode active"
```

---

## FIPS Mode and the seam serve Daemon

For persistent daemon deployments, FIPS mode should be set in the config file or environment so it applies across restarts:

```sh
# /etc/seam/config.toml (if using a system config path)
# or configure via environment in the systemd unit:
Environment="SEAM_FIPS_MODE=1"
```

See [deployment.md](deployment.md) for a complete systemd unit file with FIPS mode configured.

---

## Limitations

- **BLAKE2s** (internal to the `snow` Noise crate) is used for the Noise handshake hash. BLAKE2s is not FIPS-approved. This is an internal protocol mechanism that does not affect the security properties of the symmetric encryption or key derivation seen by external observers. Resolving this would require replacing the `snow` crate with a custom Noise implementation.
- **BLAKE3** is used for the DDoS cookie and the double ratchet KDF. These are not exposed over the wire in a form observable to external parties beyond the handshake.
- Seam has not been submitted for FIPS 140-3 module validation. The algorithms used are NIST-standardized, but formal validation requires testing and certification by an accredited laboratory.
