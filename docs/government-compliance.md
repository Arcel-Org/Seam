# Government and Compliance Reference

This document covers Seam's alignment with U.S. government security standards: NSA CNSA 2.0, NIST SP 800-52, NIST SP 800-53 audit controls, and FedRAMP considerations.

---

## Important Caveats

- Seam is **v1.0 software** and has not yet undergone a third-party security audit.
- Seam has not been submitted for FIPS 140-3 module validation by an accredited laboratory.
- This document describes Seam's *design intent* and *algorithm choices* as they relate to government standards — it does not constitute a compliance certification.
- For NSS, DoD IL4+, and classified deployments, obtain independent security review before use.

---

## CNSA 2.0 Algorithm Mapping

The NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0, announced 2022) specifies the algorithm transition timeline for national security systems. The table below maps CNSA 2.0 requirements to Seam's implementation.

| CNSA 2.0 Requirement | Specified Algorithm | Seam Implementation | Status |
|---|---|---|---|
| Key Encapsulation | ML-KEM (FIPS 203) — ML-KEM-768 minimum, ML-KEM-1024 for long-term NSS | ML-KEM-768 (FIPS 203) | Partial — meets minimum; ML-KEM-1024 not available |
| Digital Signatures | ML-DSA (FIPS 204) — ML-DSA-65 minimum | ML-DSA-65 (FIPS 204) | Meets minimum |
| Symmetric Encryption | AES-256 (FIPS 197) | AES-256-GCM via `--fips-mode` or `--cipher aes256gcm` | Meets requirement in FIPS mode |
| Hash / KDF | SHA-384 or SHA-512 (FIPS 180-4) | SHA-256 in FIPS mode (for file integrity); BLAKE3 otherwise | Partial — SHA-256 is below SHA-384 target |
| Key Exchange | ML-KEM replaces ECDH for NSS by 2030 | ML-KEM-768 + X25519 hybrid | On track; X25519 retained as classical belt-and-suspenders |

**Notes:**
- CNSA 2.0 timelines specify ML-KEM-1024 and ML-DSA-87 for the highest-assurance NSS by 2030. Seam uses ML-KEM-768 and ML-DSA-65, which are below the highest tier but above the general minimum.
- The SHA-256 hash used for file integrity checksums in FIPS mode is below the CNSA 2.0 SHA-384 recommendation. This applies only to the file transfer integrity check, not to session key derivation (which uses the Noise handshake chain).

---

## NIST SP 800-52 Rev. 2 Notes

NIST SP 800-52 covers TLS implementation guidelines for federal systems. Seam is not TLS — it uses the Noise Protocol Framework over UDP — but the algorithm choices are comparable:

| SP 800-52 Control | Seam Equivalent |
|---|---|
| TLS 1.3 required | Noise_XX (provides equivalent: ephemeral key exchange, mutual auth, forward secrecy) |
| AES-128-GCM or AES-256-GCM required | AES-256-GCM in FIPS mode |
| ECDHE or DHE for key exchange | X25519 (Noise_XX) + ML-KEM-768 (post-quantum hybrid) |
| Certificate-based authentication | ML-DSA-65 identity proofs (post-quantum equivalent) |
| Session resumption | Session tickets (SessionTicket packet type; 0-RTT) |

Seam's handshake provides equivalent security properties to TLS 1.3 with post-quantum extensions, adapted for UDP transport.

---

## Audit Log Compliance

### NIST SP 800-53 AU-2 (Audit Events)

SP 800-53 AU-2 requires organizations to determine which events are to be logged. Seam's client-side audit log records the following events for every user-initiated operation:

| Field | Description |
|---|---|
| `ts` | ISO-8601 UTC timestamp — satisfies AU-2(3) (timestamp precision) |
| `subcommand` | Event type (cp, shell, sync, forward, etc.) |
| `remote` | Remote host — satisfies requirement to log source and destination |
| `exit_code` | Outcome (0 = success; non-zero = failure) |
| `bytes_tx` | Volume of data transferred (for cp/sync) |
| `fips_mode` | Whether FIPS-140 compliant algorithms were active |
| `pid` | Process ID for cross-referencing with system logs |

Client-side audit log location: `~/.local/share/seam/audit.jsonl` (JSONL format, append-only).

For the `seam` service user in a systemd deployment: `/home/seam/.local/share/seam/audit.jsonl`.

### NIST SP 800-53 AU-12 (Audit Record Generation)

SP 800-53 AU-12 requires the information system to generate audit records for the events defined in AU-2. Seam satisfies this by logging every client-initiated operation via an `audited!` macro wrapper in `main.rs`:

- Logging is attempted at command completion.
- Failures to write the audit log emit a stderr warning but do not block the operation (non-fatal, to avoid denial-of-service via audit failure).
- Internal (server-side) subcommands (`_shell-recv`, `_send`, `recv`, etc.) are excluded from the client audit log — they run on the remote side and are not client-initiated operations.

For full AU-12 compliance, supplement client-side audit logs with server-side logging (from `seam serve`'s systemd journal output) and centralize both in a SIEM.

### Audit log integrity

The audit log is append-only. Atomic writes via `O_APPEND` ensure POSIX-safe concurrent writes on Linux (writes ≤ PIPE_BUF = 4096 bytes are atomic). The log file itself is not cryptographically signed; for tamper-evidence, pipe the log to a cryptographic log management system or place it on an append-only storage volume.

---

## FedRAMP Considerations

FedRAMP (Federal Risk and Authorization Management Program) requires cloud services used by federal agencies to meet specific security controls. Seam is a transport tool, not a cloud service, but if deployed as part of a FedRAMP-authorized offering:

### Algorithm requirements

- FedRAMP requires FIPS 140-3 validated cryptographic modules for security controls. Seam's cryptographic primitives (AES-256-GCM, ML-KEM-768, ML-DSA-65) are implemented by Rust crates that have not undergone formal FIPS 140-3 module validation.
- For FedRAMP environments, confirm with your ISSO/AO whether a validated module is required or whether algorithm compliance alone is sufficient for the specific control.

### Relevant FedRAMP controls

| Control | Seam Capability |
|---|---|
| SC-8 (Transmission Confidentiality and Integrity) | All traffic is AEAD-encrypted; headers are protected |
| SC-8(1) (Cryptographic Protection) | ChaCha20-Poly1305 or AES-256-GCM; ML-KEM-768 + X25519 key agreement |
| SC-28 (Protection of Information at Rest) | Not applicable (transport only; no data at rest) |
| AU-2 / AU-12 (Audit) | Client-side JSONL audit log; server-side journal logging |
| IA-3 (Device Identification and Authentication) | ML-DSA-65 + X25519 mutual authentication; TOFU host pinning |
| SC-23 (Session Authenticity) | Anti-replay window; per-session AEAD encryption |

### Data classification

Seam does not enforce data classification controls beyond what the underlying operating system and network provide. For classified or CUI data:

- Enable FIPS mode (`--fips-mode` or `SEAM_FIPS_MODE=1`)
- Use authorized key files to restrict which clients can connect
- Use `--tofu` for server identity pinning
- Ensure the audit log is forwarded to a SIEM
- Apply OS-level controls (SELinux, DAC) to the identity key file

---

## Enabling FIPS Mode for Government Deployments

For CNSA 2.0 and FIPS-relevant deployments, enable FIPS mode:

```sh
# Per-command
seam --fips-mode cp ./data ops@server:/dest

# Persistent (config file)
seam config set fips_mode true

# Environment (for scripts and systemd)
export SEAM_FIPS_MODE=1

# Verify
seam version | grep -A5 "Cipher suites"
seam version --json | jq '.traffic_analysis_resistance'
```

In FIPS mode:
- AES-256-GCM (FIPS 197) is enforced for packet encryption
- SHA-256 (FIPS 180-4) is used for file integrity checksums
- Traffic padding is enabled by default

See [fips-mode.md](fips-mode.md) for complete FIPS mode documentation.

---

## CNSA 2.0 Compliance Summary

| Requirement | Status | Notes |
|---|---|---|
| ML-KEM-768+ for key exchange | Implemented | ML-KEM-768 (FIPS 203). ML-KEM-1024 not currently available. |
| ML-DSA-65+ for signatures | Implemented | ML-DSA-65 (FIPS 204) for identity proofs. |
| AES-256 for symmetric encryption | Implemented (FIPS mode) | Enable `--fips-mode` or `SEAM_FIPS_MODE=1`. |
| Hybrid classical/PQ key exchange | Implemented | X25519 + ML-KEM-768 hybrid; both must be broken to compromise. |
| Deprecation of ECDSA/RSA | N/A | Seam does not use ECDSA or RSA; uses ML-DSA-65 and X25519 only. |
| Forward secrecy | Implemented | Noise_XX ephemeral keys + double ratchet per-epoch key rotation. |
| Quantum-resistant identity | Implemented | ML-DSA-65 identity proofs bind identity to session via PQ signature. |
| Audit logging | Implemented | JSONL audit log with subcommand, remote, exit_code, fips_mode fields. |
