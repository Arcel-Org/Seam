# CLI Reference

This document covers every subcommand, flag, and option in the `seam` CLI (version 1.0.1).

---

## Global Flags

These flags are available on every subcommand:

| Flag | Description |
|---|---|
| `-v` / `--verbose` | Increase verbosity. Repeat for more: `-v` (info), `-vv` (debug), `-vvv` (trace) |
| `--cipher <SUITE>` | AEAD cipher suite: `chacha20poly1305` (default) or `aes256gcm` (CNSA 2.0 compliant) |
| `--fips-mode` | Enable FIPS-140 compliant mode (also: `SEAM_FIPS_MODE=1` or `fips_mode=true` in config) |
| `--tofu` | Trust-On-First-Use: pin the server's identity key on first connection |
| `--insecure-ignore-pin` | Bypass server identity pinning verification (insecure; prints a warning) |

### FIPS mode precedence

FIPS mode is resolved from three sources in order (later sources override earlier ones):

1. `~/.config/seam/config.toml` — `fips_mode = true`
2. Environment — `SEAM_FIPS_MODE=1` or `SEAM_FIPS_MODE=true`
3. CLI flag — `--fips-mode`

When FIPS mode is active:
- AES-256-GCM is forced; passing `--cipher chacha20poly1305` is an error
- SHA-256 (FIPS 180-4) is used instead of BLAKE3 for file integrity checksums
- A compliance algorithm banner is printed to stderr on startup
- Traffic padding defaults to enabled

---

## seam cp

Copy files to or from a remote host. Equivalent to `scp` but uses post-quantum UDP transport.

```sh
seam cp <src> <dest> [flags]
```

Exactly one of `src` or `dest` must be remote (`user@host:/path`). Both cannot be remote.

### Examples

```sh
# Push a file to remote
seam cp ./report.pdf alice@server:/home/alice/report.pdf

# Push a directory recursively
seam cp ./dataset/ alice@server:/data/dataset

# Pull a file from remote
seam cp alice@server:/var/log/app.log ./local-logs/

# Resume an interrupted transfer
seam cp --resume ./large.iso alice@server:/data/

# Disable compression (for already-compressed files)
seam cp --no-compress ./archive.tar.gz alice@server:/backups/

# Limit to 10 Mbps (useful during business hours)
seam cp --rate 10 ./backup.tar.gz alice@server:/backups/

# Multi-path transfer across two interfaces
seam cp --multipath 192.168.1.100:0,10.0.0.1:0 ./data alice@server:/dest
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--no-compress` | false | Disable zstd compression |
| `--resume` | false | Resume an interrupted transfer (uses `.seam-partial` staging files; atomic rename on success) |
| `--direct <LINE>` | — | Skip SSH bootstrap; use a pre-started SEAM connection line directly. Format: `"SEAM PORT=<n> X25519=<hex> KEM=<hex>"` |
| `--rate <Mbps>` | — | Cap bandwidth to N Mbps using a token-bucket limiter |
| `--multipath <addr1,...>` | — | Comma-separated local bind addresses for multi-path transport |
| `--multipath-redundant` | false | Send every packet on all paths simultaneously (anti-jamming) |

### Behavior

- Compression is enabled by default (zstd level 3). Disable with `--no-compress` or `seam config set compress false`.
- Each file is checksummed end-to-end. BLAKE3 is used by default; SHA-256 in FIPS mode. A mismatch aborts with an error.
- When `--resume` is active, incomplete files are staged as `<name>.seam-partial`. On successful checksum verification, the partial is atomically renamed to the final path. On mismatch, the partial is deleted and the transfer must restart.
- If seam is not found on the remote, it is bootstrapped automatically by copying the local binary over SSH.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Transfer completed and integrity verified |
| 1 | Transfer failed (network error, checksum mismatch, bad path) |

---

## seam sync

Synchronize a local directory to or from a remote host. Only files that differ are transferred.

```sh
seam sync <src> <dest> [flags]
```

### Examples

```sh
# Push local directory to remote
seam sync ./project/ alice@server:/srv/project

# Pull remote directory to local
seam sync alice@server:/srv/project ./project/

# Delete remote files that are not in the local source
seam sync --delete ./project/ alice@server:/srv/project

# Bypass manifest cache (always re-hash remote)
seam sync --no-cache ./project/ alice@server:/srv/project
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--delete` | false | Delete remote files not present in the local manifest |
| `--no-compress` | false | Disable zstd compression |
| `--no-cache` | false | Bypass the remote manifest cache |
| `--fips-mode` | false | Inherited from global `--fips-mode` |

### Protocol

1. Client hashes all local files (BLAKE3 or SHA-256 in FIPS mode).
2. Remote hashes all its files (using cached manifest if available and valid).
3. Client sends only files that differ or are missing on remote.
4. Each file is integrity-verified after transfer.
5. With `--delete`: remote removes files in its manifest but not the client's.

The remote manifest cache is stored at `~/.cache/seam/sync/<host>/<dir_key>.json`. Cache entries are invalidated by mtime or size changes.

---

## seam shell

Execute a command on a remote host over a post-quantum Seam channel. With no command, opens an interactive shell.

```sh
seam shell <user@host> [flags] [-- command [args...]]
```

### Examples

```sh
# Interactive shell
seam shell alice@server

# Run a specific command
seam shell alice@server -- ls -la /etc

# Run a command with stdin piped
echo "select 1" | seam shell alice@server -- psql -U postgres

# Specify SSH port for bootstrap
seam shell -p 2222 alice@server

# Force non-interactive mode (no PTY)
seam shell --no-pty alice@server -- cat /etc/os-release
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | — | SSH port for bootstrap |
| `--no-pty` | false | Force non-interactive mode (no PTY) even when stdin is a TTY |
| `--multipath <addr1,...>` | — | Multi-path local bind addresses |
| `--multipath-redundant` | false | Send on all paths simultaneously |

### Behavior

- When stdin and stdout are both TTYs (interactive), seam allocates a PTY on the remote. Terminal dimensions are forwarded on startup and on `SIGWINCH`. The `TERM` environment variable is forwarded. Raw mode is set on the local terminal.
- When stdin is a pipe (non-interactive), stdin is forwarded as `SHELL_STDIN` frames; stdout and stderr are streamed back.
- The remote user's `$SHELL` is used when no command is given (with `-l` flag to get a login shell).
- Exit code from the remote command is propagated to the local process.

---

## seam forward

Forward a local TCP port through a post-quantum Seam tunnel to a remote destination.

```sh
seam forward <LOCAL_PORT:REMOTE_HOST:REMOTE_PORT> <user@host> [flags]
```

This is the primary primitive for TCP port forwarding, analogous to `ssh -L`.

### Examples

```sh
# Forward local 8080 to remote localhost:3000
seam forward 8080:localhost:3000 alice@server

# Forward local 5432 to a database on the remote's internal network
seam forward 5432:db.internal:5432 alice@server

# Bind on all interfaces (allow other local machines to use the tunnel)
seam forward --bind-all 8080:localhost:3000 alice@server

# Multi-hop: reach air-gapped host through a jump server
seam forward 8080:localhost:80 --via alice@jumphost alice@air-gapped

# Use custom SSH port
seam forward -p 2222 8080:localhost:3000 alice@server
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | — | SSH port for bootstrap |
| `--bind-all` | false | Bind local port on `0.0.0.0` instead of `127.0.0.1` |
| `--via <user@relay>` | — | Route through an intermediate Seam relay node (two-hop tunnel) |
| `--multipath <addr1,...>` | — | Multi-path local bind addresses |
| `--multipath-redundant` | false | Send on all paths simultaneously |

### Multi-hop tunneling

When `--via user@jumphost` is specified, seam creates a two-hop encrypted tunnel:

```
local ──[Seam PQ]── jumphost ──[Seam PQ]── air-gapped-target
```

Both hops are independently post-quantum encrypted. The relay host cannot read the traffic between the client and the final target.

---

## seam fwd

Reverse port forward: the remote server listens on a port and forwards incoming connections to your local machine. Analogous to `ssh -R`.

```sh
seam fwd <user@host:REMOTE_PORT> <LOCAL_PORT> [flags]
```

### Examples

```sh
# Remote listens on :3000, connections forwarded to local :8080
seam fwd alice@server:3000 8080

# Expose local service to remote machine
seam fwd alice@bastion:9090 8080 --local-host 0.0.0.0

# Custom SSH port
seam fwd -p 2222 alice@server:5432 5432
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | — | SSH port for bootstrap |
| `--local-host <HOST>` | `127.0.0.1` | Local host to forward connections to |

---

## seam tunnel

Forward a TCP port through a Seam tunnel using the legacy spec format. Prefer `seam forward` for new usage.

```sh
seam tunnel <LOCAL_PORT:user@host:REMOTE_PORT> [flags]
```

### Examples

```sh
seam tunnel 8080:alice@server:3000
seam tunnel 5432:alice@server:db.internal:5432
```

---

## seam proxy

Run a local SOCKS5 proxy server; all SOCKS5 connections are tunneled through a post-quantum Seam connection to the remote host.

```sh
seam proxy <user@host> [flags]
```

### Examples

```sh
# Start SOCKS5 proxy on default port 1080
seam proxy alice@server

# Use a custom port
seam proxy alice@server --port 9050

# Allow connections from other machines (use with caution)
seam proxy alice@server --bind-all

# Configure curl to use the proxy
curl --socks5 127.0.0.1:1080 https://example.com/
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | `1080` | Local SOCKS5 port to bind |
| `--bind-all` | false | Bind on `0.0.0.0` instead of `127.0.0.1` |
| `--ssh-port <PORT>` | — | SSH port for bootstrap |

### Behavior

Implements SOCKS5 (RFC 1928). Supports IPv4, IPv6, and domain name address types. `CMD_CONNECT` only; `BIND` and `UDP ASSOCIATE` are not supported. All TCP connections initiated through the SOCKS5 proxy are resolved and forwarded by the remote host.

---

## seam pipe

Bidirectional pipe between local stdin/stdout and a remote command. Post-quantum encrypted replacement for netcat.

```sh
seam pipe <user@host> [flags] -- <command> [args...]
```

### Examples

```sh
# Open a remote shell via pipe
seam pipe alice@server -- bash

# Stream remote journald output
seam pipe alice@server -- journalctl -f

# Pipe data between machines
tar cf - ./project | seam pipe alice@server -- tar xf - -C /dest

# Remote port scan
seam pipe alice@server -- nmap -sV 10.0.0.0/24
```

---

## seam serve

Start a persistent Seam server daemon that accepts multiple concurrent client connections without requiring SSH on the remote.

```sh
seam serve [flags]
```

### Examples

```sh
# Listen on default port 2222
seam serve

# Listen on a custom port
seam serve --port 4433

# Bind on all interfaces (default is already 0.0.0.0)
seam serve --port 2222 --bind 0.0.0.0

# Require client key authorization
seam serve --auth-keys /etc/seam/authorized_keys

# Load keys from a directory
seam serve --auth-keys-dir /etc/seam/authorized_keys.d/

# Disable shell access (forward and info only)
seam serve --no-shell

# Limit to 32 concurrent connections
seam serve --max-connections 32

# FIPS mode
seam serve --fips-mode --port 2222
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | `2222` | UDP port to listen on |
| `-b` / `--bind <ADDR>` | `0.0.0.0` | Address to bind on |
| `--max-connections <N>` | `64` | Maximum concurrent client connections (0 = unlimited) |
| `--no-shell` | false | Disable the shell service (forward and info remain available) |
| `--auth-keys <FILE>` | — | Path to a file containing authorized client X25519 public keys (one hex key per line) |
| `--auth-keys-dir <DIR>` | — | Directory containing `*.pub` files with authorized keys |
| `--multipath <addr1,...>` | — | Listen on multiple interfaces simultaneously |
| `--multipath-redundant` | false | Send every packet on all paths simultaneously |

### Auth-keys file format

```
# alice's workstation
a1b2c3d4e5f6...  (64 hex chars, 32 bytes = X25519 public key)

# bob's laptop
deadbeef...
```

Lines starting with `#` are comments. Empty lines are ignored. Keys must be exactly 64 hex characters (32 bytes).

Get a client's key with: `seam key`

### Auth-keys directory format

All files with a `.pub` extension in the directory are loaded. Each file may contain one or more hex X25519 keys (one per line, `#` comments allowed).

```
/etc/seam/authorized_keys.d/
  alice.pub       # one or more keys
  bob.pub
  ops-team.pub
```

### Services provided

`seam serve` implements four internal services identified by a one-byte tag on each stream:

| Tag | Service | Description |
|---|---|---|
| `0x01` | Shell | Execute a command (PTY or pipe) and stream I/O |
| `0x02` | Forward | Connect to a TCP destination and bridge bidirectionally |
| `0x03` | Info | Return JSON metadata (version, cipher, supported services) |
| `0x04` | Ping | Echo 4-byte payload for RTT measurement by `seam health` |

### Server identity key

`seam serve` loads (or generates) a persistent identity keypair from `~/.config/seam/identity`. This keypair is stable across restarts, enabling clients to pin the server identity with `--tofu`.

---

## seam health

Check the health of a remote `seam serve` instance.

```sh
seam health <user@host> [flags]
```

### Examples

```sh
# SSH bootstrap to start a seam serve instance and check it
seam health alice@server

# Connect to an already-running seam serve
seam health myserver --direct "SEAM PORT=2222 X25519=<hex> KEM=<hex>"

# JSON output for monitoring systems
seam health alice@server --json

# Suppress progress, show summary only
seam health alice@server --quiet

# More ping samples for RTT accuracy
seam health alice@server --ping-count 20
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | — | SSH port for bootstrap |
| `--direct <LINE>` | — | Connect to an already-running seam serve directly |
| `--ping-count <N>` | `5` | Number of RTT ping samples to collect |
| `--json` | false | Machine-readable JSON output |
| `--quiet` | false | Suppress progress messages (summary only) |

### Checks performed

1. **connection** — Post-quantum handshake completed successfully; reports handshake latency in ms
2. **key-fingerprint** — Server X25519 public key (TOFU check against `~/.config/seam/known_hosts`)
3. **version** — Server and client versions match (warns on mismatch; does not fail)
4. **rtt** — RTT samples via SVC_PING; reports min/avg/max and loss percentage

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All checks passed (or passed with warnings) |
| 1 | One or more checks failed |

---

## seam ping

Measure round-trip latency to a remote host over post-quantum encrypted UDP.

```sh
seam ping <user@host> [flags]
```

### Examples

```sh
# Send 5 pings (default)
seam ping alice@server

# Send 20 pings
seam ping alice@server -n 20

# Continuous mode (Ctrl-C for statistics)
seam ping alice@server -n 0

# Custom interval (200ms)
seam ping alice@server -i 200
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | — | SSH port for bootstrap |
| `-n` / `--count <N>` | `5` | Number of pings to send (0 = continuous until Ctrl-C) |
| `-i` / `--interval <MS>` | `1000` | Interval between pings in milliseconds |
| `--multipath <addr1,...>` | — | Multi-path local bind addresses |
| `--multipath-redundant` | false | Send on all paths simultaneously |

### Output

```
PING alice@server over Seam (post-quantum UDP)
seq=0 rtt=12.34ms
seq=1 rtt=11.89ms
seq=2 rtt=13.01ms
seq=3 rtt=12.45ms
seq=4 rtt=12.67ms

--- alice@server ping statistics ---
5 sent, 5 received, 0 lost (0% loss)
rtt min/avg/max/stddev = 11.89/12.47/13.01/0.41 ms
```

---

## seam bench

Measure transfer throughput to a remote host and compare against known baselines.

```sh
seam bench <user@host> [flags]
```

### Examples

```sh
# 100 MiB benchmark (default)
seam bench alice@server

# 1 GiB benchmark
seam bench alice@server --mib 1000

# Stop after 30 seconds (partial result)
seam bench alice@server --timeout 30

# Simulate a 10 Mbps constrained link
seam bench alice@server --bw-cap 10

# BBR congestion control
SEAM_CC=bbr seam bench alice@server

# Connect to an already-running receiver
seam bench alice@server --direct "SEAM PORT=N X25519=<hex> KEM=<hex>"
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | — | SSH port for bootstrap |
| `--mib <N>` | `100` | Amount of data to transfer in MiB |
| `--direct <LINE>` | — | Skip SSH bootstrap; use a pre-started SEAM line |
| `--timeout <SECS>` | — | Stop after this many seconds; print partial results |
| `--bw-cap <MBPS>` | — | Cap receiver bandwidth to simulate a constrained link |

### Output

```
  ────────────────────────────────────────────────────────────────────
  tool     throughput                            MiB/s   notes
  ────────────────────────────────────────────────────────────────────
  seam     █████████████████████████████████       847   0.706 Gbps  ← measured
  scp      █████████████████░░░░░░░░░░░░░░░░       400   encrypted TCP  (est.)
  rsync    ████████████████░░░░░░░░░░░░░░░░░       380   encrypted TCP  (est.)
  netcat   ██████████████████████████████████░     950   unencrypted TCP  (est.)
  ────────────────────────────────────────────────────────────────────

  seam is 2.1× faster than scp on this path
  post-quantum safe · UDP · FEC recovery · 247 µs handshake
```

Also reports estimated packet loss rate, jitter, and throughput stability (coefficient of variation).

---

## seam stats

Show real-time connection statistics (RTT, throughput, path MTU, congestion window).

```sh
seam stats <user@host> [flags]
```

### Examples

```sh
# 5-second measurement window (default)
seam stats alice@server

# 10-second window
seam stats alice@server --duration 10
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-p` / `--port <PORT>` | — | SSH port for bootstrap |
| `--duration <SECS>` | `5` | Measurement window in seconds |
| `--direct <LINE>` | — | Skip SSH bootstrap; use a pre-started SEAM line |

### Output

```
  Seam connection stats  alice@server  (5s window)
  ─────────────────────────────────────────────────
  RTT           min 44ms  avg 51ms  max 79ms
  Throughput    recv 234 MiB/s
  Path MTU      1400 bytes
  cwnd          512 KiB
```

---

## seam ls

List files on a remote host.

```sh
seam ls <user@host:/path> [flags]
```

### Examples

```sh
seam ls alice@server:/var/log
seam ls alice@server:/data
```

Output includes Unix-style permissions, human-readable sizes, and filenames.

---

## seam key

Show and manage the local identity key.

```sh
seam key [flags]
```

### Examples

```sh
# Show public key components (text)
seam key

# Show in JSON format
seam key --format json

# Rotate the identity keypair (backs up old key with timestamp)
seam key --rotate

# List all TOFU-pinned server keys
seam key --list-pins

# Remove a TOFU pin for a specific host
seam key --remove-pin alice@server
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--format <FORMAT>` | `text` | Output format: `text` or `json` |
| `--rotate` | false | Generate a new keypair; backs up old key as `identity.YYYYMMDDTHHMMSSZ` |
| `--list-pins` | false | List all TOFU-pinned server keys from `~/.config/seam/known_hosts` |
| `--remove-pin <HOST>` | — | Remove the TOFU pin for HOST |

### Key components

| Component | Size | Algorithm | Purpose |
|---|---|---|---|
| X25519 | 32 bytes | Classical ECDH | Key agreement in Noise_XX |
| ML-KEM-768 | 1184 bytes (public) | FIPS 203 | Post-quantum key encapsulation |
| ML-DSA-65 | 1952 bytes (public) | FIPS 204 | Quantum-resistant identity signature |
| ML-DSA-65 fingerprint | SHA-256 of pk | — | Human-readable identity fingerprint |

After key rotation, update all peer configurations (relay servers, `auth-keys` files) with the new public key.

---

## seam version

Show version, build metadata, supported cipher suites, and active traffic analysis resistance settings.

```sh
seam version [flags]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--json` | false | Machine-readable JSON output |

### Output (text)

```
seam 1.0.1
Build date   : 2025-06-01
Noise pattern: Noise_XX_25519_ChaChaPoly_BLAKE2s
KEM          : ML-KEM-768 (FIPS 203, CRYSTALS-Kyber)
Key exchange : X25519 + ML-KEM-768 (hybrid post-quantum)
Identity sig : ML-DSA-65 (FIPS 204, CRYSTALS-Dilithium3) — quantum-resistant identity
Ratchet      : Double ratchet: per-epoch forward secrecy (epoch: 1000 packets / 30s)
Cipher suites:
  chacha20poly1305       ChaCha20-Poly1305 — default, cross-platform, no hardware requirement
  aes256gcm              AES-256-GCM — NSA CNSA 2.0 / DoD compliant, hardware-accelerated on AES-NI

Traffic analysis resistance: none (all disabled)
```

---

## seam config

Manage persistent settings in `~/.config/seam/config.toml`.

```sh
seam config <subcommand> [args]
```

### Subcommands

| Subcommand | Description |
|---|---|
| `init` | Create `~/.config/seam/config.toml` with defaults (no-op if file exists) |
| `list` | Print the full effective configuration (alias: `show`) |
| `get <key>` | Show the current value of one setting |
| `set <key> <value>` | Change one setting and persist |

### Examples

```sh
seam config init
seam config list
seam config get cipher
seam config set cipher aes256gcm
seam config set cc bbr
seam config set compress false
seam config set fips_mode true
```

### Configuration keys

| Key | Type | Default | Description |
|---|---|---|---|
| `cc` | string | `cubic` | Congestion controller: `cubic` or `bbr` |
| `compress` | bool | `true` | Enable zstd compression for `cp` by default |
| `identity` | string | — | Path to identity key (default: `~/.config/seam/identity`) |
| `cipher` | string | `chacha20poly1305` | AEAD cipher: `chacha20poly1305` or `aes256gcm` |
| `max_connections` | int | `1024` | Max concurrent server endpoint connections |
| `listen_port` | int | `0` | Default UDP listen port (0 = OS-assigned) |
| `fec_k` | int | — | FEC source symbols per group (0 = disabled, defer to arbiter) |
| `fec_r` | int | — | FEC repair symbols per group (used when `fec_k` > 0) |
| `fips_mode` | bool | `false` | Enable FIPS-140 compliant mode |
| `relays` | list | `[]` | Relay hosts to ping in `seam doctor` |
| `traffic_padding` | bool | — | Pad packets to size-class boundaries (default: enabled in FIPS mode) |
| `cover_traffic_kbps` | int | `0` | Constant-rate cover traffic in kbps (0 = disabled) |
| `timing_jitter_ms` | int | `0` | Per-packet random delay in ms (0 = disabled) |
| `obfuscate` | bool | `false` | XOR first 8 bytes of header with per-session secret |
| `multipath_addrs` | string | — | Default multi-path bind addresses (comma-separated ip:port) |
| `multipath_mode` | string | `round-robin` | Multi-path scheduling: `round-robin`, `min-latency`, `redundant`, `weighted` |
| `ratchet_epoch_packets` | int | `1000` | Packets before a DH ratchet step |
| `ratchet_epoch_seconds` | int | `30` | Seconds before a DH ratchet step |

---

## seam doctor

Check system readiness and diagnose common problems.

```sh
seam doctor
```

No flags. Checks (in order):

1. Binary location (resolves own path)
2. `seam` in PATH
3. SSH client in PATH (required for bootstrap)
4. `ssh -G` works (config parsing)
5. Identity key exists, has correct permissions (0600), and is valid (X25519 + ML-KEM-768 + ML-DSA-65)
6. ML-DSA-65 key roundtrip sanity check
7. Audit log health (exists, readable, writable)
8. UDP socket buffer sizes (warns if below 8 MiB)
9. Relay connectivity (if `relays` are configured in config file)

Exits 0 if all required checks pass (warnings are allowed). Exits 1 if any required check fails.

---

## seam audit

View and query the local audit log at `~/.local/share/seam/audit.jsonl`.

```sh
seam audit <subcommand> [flags]
```

### seam audit show

```sh
seam audit show [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-n` / `--lines <N>` | `20` | Number of entries to show (0 = all) |
| `--since <DATE>` | — | Filter entries on or after this date (YYYY-MM-DD or RFC3339) |
| `--host <HOST>` | — | Filter by remote host (substring match) |
| `--json` | false | Output raw JSONL instead of formatted table |

### Examples

```sh
# Show last 20 entries
seam audit show

# Show all entries since a date
seam audit show --since 2025-06-01

# Show entries for a specific host
seam audit show --host alice@server

# Raw JSONL for processing with jq
seam audit show --json | jq '.subcommand'

# Show 100 entries
seam audit show -n 100
```

### seam audit clear

```sh
seam audit clear [--yes]
```

Removes all entries from the audit log. Prompts for confirmation unless `--yes` is passed.

| Flag | Description |
|---|---|
| `--yes` | Skip confirmation prompt |

### Audit log format

Each line is a JSON object (JSONL):

```json
{
  "ts": "2025-06-05T10:30:00Z",
  "subcommand": "cp",
  "remote": "alice@server",
  "args": [],
  "exit_code": 0,
  "bytes_tx": null,
  "fips_mode": false,
  "pid": 12345
}
```

Fields:

| Field | Description |
|---|---|
| `ts` | ISO-8601 UTC timestamp |
| `subcommand` | Command name (cp, shell, sync, etc.) |
| `remote` | Remote host string (empty for local-only commands) |
| `args` | Sanitized argument list (no secrets) |
| `exit_code` | Integer exit code (0 = success, null = unknown/in-progress) |
| `bytes_tx` | Bytes transferred (cp/sync only; null otherwise) |
| `fips_mode` | Whether FIPS mode was active |
| `pid` | Process ID for cross-referencing with server-side logs |

The file is opened with `O_APPEND`; concurrent writes are safe on POSIX (each write ≤ PIPE_BUF = 4096 bytes, which is atomic on Linux).

---

## seam update

Update seam to the latest release from GitHub.

```sh
seam update [flags]
```

### Flags

| Flag | Description |
|---|---|
| `--check` | Print available version without installing |

### Behavior

1. Fetches the latest release metadata from `https://api.github.com/repos/Arcel-Org/Seam/releases/latest`
2. If already up to date, prints a message and exits
3. Downloads the platform-appropriate `.tar.gz` asset
4. Verifies SHA-256 checksum against the published `checksums.sha256` file — aborts on mismatch
5. Extracts the binary and atomically replaces the running binary (write to `.new` then rename)

---

## seam completions

Generate shell completion scripts.

```sh
seam completions <shell>
```

Supported shells: `bash`, `zsh`, `fish`

```sh
seam completions bash > /etc/bash_completion.d/seam
seam completions zsh  > ~/.zsh/completions/_seam
seam completions fish > ~/.config/fish/completions/seam.fish
```

---

## Environment Variables

| Variable | Description |
|---|---|
| `SEAM_FIPS_MODE` | Set to `1` or `true` to enable FIPS mode |
| `SEAM_CC` | Congestion controller: `cubic` or `bbr` |
