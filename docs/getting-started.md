# Getting Started with Seam

This guide walks through installing seam, verifying the installation, and completing your first post-quantum encrypted file transfer.

---

## Requirements

- **Linux, macOS, or Windows** (prebuilt binaries available for common targets)
- **SSH client** in PATH — seam uses SSH for the initial bootstrap to remotes
- **Rust 1.88+** only if building from source

---

## Installation

### Prebuilt binary (recommended)

```sh
curl -fsSL https://install.arcel.org/seam.sh | sh
```

Installs to `~/.local/bin/seam`. The script verifies a SHA-256 checksum before placing the binary.

To install to a different directory:

```sh
SEAM_INSTALL_DIR=/usr/local/bin curl -fsSL https://install.arcel.org/seam.sh | sh
```

### Self-update

Once seam is installed, keep it current with:

```sh
seam update          # download and replace the binary
seam update --check  # print available version without installing
```

The update command fetches the latest release from GitHub, verifies the SHA-256 checksum against the published `checksums.sha256` file, and atomically replaces the running binary.

### Build from source

```sh
# Prerequisites: Rust 1.88+
git clone https://github.com/Arcel-Org/Seam
cd Seam
cargo build --release --bin seam
./target/release/seam --version
```

### Shell completions

```sh
seam completions bash > /etc/bash_completion.d/seam       # system-wide (Linux)
seam completions zsh  > ~/.zsh/completions/_seam           # user (zsh)
seam completions fish > ~/.config/fish/completions/seam.fish
```

---

## First-Time Setup

### System readiness check

```sh
seam doctor
```

`seam doctor` checks:

- seam binary is in PATH
- SSH client is available (required for bootstrap)
- `ssh -G` works (verifies `~/.ssh/config` can be parsed)
- Identity key exists at `~/.config/seam/identity` and has correct permissions (0600)
- ML-DSA-65 key roundtrip sanity (post-quantum identity signature)
- Audit log health (readable, writable)
- UDP socket buffer sizes (warns if below recommended 8 MiB)

If you see warnings about UDP buffers, apply the recommended tuning:

```sh
sudo sysctl -w net.core.rmem_max=8388608
sudo sysctl -w net.core.wmem_max=8388608
```

To persist these across reboots, add to `/etc/sysctl.d/99-seam.conf`:

```
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
```

### Identity key

Seam stores a persistent identity keypair at `~/.config/seam/identity`. This file contains your X25519, ML-KEM-768, and ML-DSA-65 keys. It is created automatically on first use.

View your public key material:

```sh
seam key               # human-readable
seam key --format json # machine-readable
```

Output includes:
- **X25519 public key** (32 bytes, classical key agreement)
- **ML-KEM-768 public key** (1184 bytes, post-quantum key encapsulation, FIPS 203)
- **ML-DSA-65 public key** (1952 bytes, post-quantum identity signature, FIPS 204)
- **ML-DSA-65 fingerprint** (SHA-256 of the ML-DSA-65 public key)

The identity file has permissions `0600`. Never share the private key file.

### SSH config integration

Seam reads your `~/.ssh/config` automatically. Host aliases, `User`, `Port`, and `IdentityFile` directives all work as expected:

```
# ~/.ssh/config
Host prod
    HostName 10.0.0.1
    User deploy
    IdentityFile ~/.ssh/id_ed25519
```

```sh
seam cp ./release.tar.gz prod:/srv/releases/  # uses SSH config
```

---

## Quick Start

### Check that seam is ready

```sh
seam doctor
```

All checks should pass. Fix any reported issues before proceeding.

### Copy a file to a remote server

```sh
seam cp ./report.pdf alice@server:/home/alice/report.pdf
```

Seam will:

1. Connect to `server` via SSH and start a receiver process (bootstrapping seam there if needed)
2. Perform a Noise_XX + ML-KEM-768 handshake over UDP
3. Transfer the file with zstd compression and BLAKE3 integrity verification
4. Print transfer speed

### Copy a file from a remote server

```sh
seam cp alice@server:/var/log/app.log ./local-logs/
```

### Sync a directory

```sh
seam sync ./project/ alice@server:/srv/project
```

Only files that differ (by content hash) are transferred. Files missing on the remote are added; files that exist on the remote but not locally are left untouched unless `--delete` is passed.

### Open an interactive shell

```sh
seam shell alice@server
```

This allocates a PTY on the remote and forwards your terminal. Resize events and the `TERM` environment variable are forwarded automatically.

### Run a remote command

```sh
seam shell alice@server -- journalctl -f
seam shell alice@server -- df -h
```

### Port forward

Forward local port 8080 to the remote's localhost:3000:

```sh
seam forward 8080:localhost:3000 alice@server
```

Then in another terminal:

```sh
curl http://localhost:8080/api/status
```

The forward runs until you press Ctrl-C. All traffic is post-quantum encrypted over UDP.

### Latency check

```sh
seam ping alice@server
```

### Throughput benchmark

```sh
seam bench alice@server         # 100 MiB test
seam bench alice@server --mib 500
```

---

## First Connection Walkthrough

This section shows in detail what happens when you run `seam cp ./data.tar.gz alice@server:/tmp/`.

**Step 1 — SSH bootstrap**

Seam opens an SSH connection to `server` as `alice` using your existing SSH credentials and config. Over that SSH channel it runs `seam recv /tmp/ --port 0 --once` on the remote, which binds a UDP port and prints a SEAM line to stdout:

```
SEAM PORT=54321 X25519=<hex> KEM=<hex>
```

Seam reads this line back over the SSH channel and closes the SSH connection.

**Step 2 — Post-quantum handshake**

Seam connects to `server:54321` over UDP and performs:

- Noise_XX handshake (mutual authentication, ephemeral X25519 key agreement)
- ML-KEM-768 encapsulation (adds post-quantum key material)
- ML-DSA-65 identity proof exchange (quantum-resistant identity binding)
- Cipher negotiation (ChaCha20-Poly1305 by default, AES-256-GCM in FIPS mode)

The handshake takes approximately 247 µs. Both sides now share session keys that neither could force to be weak, and that cannot be decrypted by a quantum computer even if recordings of the handshake are captured today.

**Step 3 — File transfer**

The file is chunked, zstd-compressed (level 3), and sent over the encrypted UDP transport. Each packet is AEAD-encrypted with ChaCha20-Poly1305. The transport handles packet loss via ARQ retransmission and optionally FEC repair symbols.

On completion, BLAKE3 (or SHA-256 in FIPS mode) end-to-end integrity verification confirms the file arrived intact.

**Step 4 — Audit log**

An entry is appended to `~/.local/share/seam/audit.jsonl`:

```json
{"ts":"2025-06-05T10:30:00Z","subcommand":"cp","remote":"alice@server","args":[],"exit_code":0,"bytes_tx":null,"fips_mode":false,"pid":12345}
```

---

## Verbosity

Add `-v` (info), `-vv` (debug), or `-vvv` (trace) to any command:

```sh
seam -vv cp ./data user@host:/dest
seam -v shell alice@server
```

Verbosity flags are global and work with all subcommands.

---

## Configuration

Seam stores persistent defaults in `~/.config/seam/config.toml`.

```sh
seam config init          # create the file with defaults
seam config list          # show all current settings
seam config get cipher    # show one value
seam config set cipher aes256gcm   # change a setting
```

Key settings:

| Key | Default | Description |
|---|---|---|
| `cc` | `cubic` | Congestion controller (`cubic` or `bbr`) |
| `compress` | `true` | Enable zstd compression for `cp` by default |
| `cipher` | `chacha20poly1305` | AEAD cipher (`chacha20poly1305` or `aes256gcm`) |
| `fips_mode` | `false` | Enable FIPS-140 compliant mode |
| `max_connections` | `1024` | Max concurrent connections for server endpoint |
| `listen_port` | `0` | Default UDP listen port (0 = OS-assigned) |

See [cli-reference.md](cli-reference.md#seam-config) for the full list of config keys.
