# Deployment Guide

This guide covers running `seam serve` in production: systemd service setup, authorized key configuration, firewall rules, monitoring with `seam health`, and audit log management.

---

## Overview

Seam has two operating modes:

1. **SSH bootstrap mode** — seam uses an existing SSH connection to start a per-session receiver process. No persistent daemon is required. Works for `seam cp`, `seam shell`, `seam forward`, `seam sync`, `seam bench`, and others.

2. **Standalone daemon mode** (`seam serve`) — a persistent UDP server that accepts multiple concurrent connections without SSH. Required when SSH is not available, for lower-latency connections (avoids the SSH bootstrap round-trip), or for container/embedded deployments.

This guide focuses on standalone daemon mode.

---

## Prerequisites

- seam binary installed on both client and server
- UDP port (default 2222) reachable from clients
- Systemd (for service management; adapt for other init systems as needed)
- A user account to run the daemon (a dedicated `seam` service account is recommended for production)

---

## Firewall Rules

Seam uses UDP. Open the server's listen port in your firewall:

### iptables

```sh
# Allow inbound UDP on port 2222
iptables -A INPUT -p udp --dport 2222 -j ACCEPT

# If you use a specific source CIDR (recommended for restricted deployments):
iptables -A INPUT -p udp --dport 2222 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p udp --dport 2222 -j DROP
```

### nftables

```nft
table inet filter {
    chain input {
        udp dport 2222 accept
    }
}
```

### ufw

```sh
ufw allow 2222/udp
# Or with source restriction:
ufw allow from 10.0.0.0/8 to any port 2222 proto udp
```

### Notes

- Seam's DDoS-resistant cookie mechanism means the server does not allocate per-client state until the client echoes the BLAKE3 cookie. Even with the port open, spoofed connection attempts cannot exhaust server memory.
- If clients are behind NAT and your firewall has connection tracking, UDP tracking may time out if the connection is idle for more than the keepalive interval (15s Ping/Pong). Configure your firewall's UDP timeout to at least 90 seconds.

---

## Socket Buffer Tuning

On Linux, apply these sysctl settings for optimal UDP performance:

```sh
# One-time (not persistent)
sudo sysctl -w net.core.rmem_max=8388608
sudo sysctl -w net.core.wmem_max=8388608
sudo sysctl -w net.core.rmem_default=1048576
sudo sysctl -w net.core.wmem_default=1048576
```

To persist across reboots:

```sh
cat > /etc/sysctl.d/99-seam.conf << 'EOF'
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
EOF
sysctl -p /etc/sysctl.d/99-seam.conf
```

`seam doctor` will warn if these buffers are below recommended values.

---

## Authorized Keys Setup

`seam serve` supports two methods of authorized key configuration. Both use hex-encoded X25519 public keys.

### Obtaining a client's key

On the **client** machine:

```sh
seam key
```

Output:

```
identity key: /home/alice/.config/seam/identity

  X25519 public key:          a1b2c3d4e5f6... (64 hex chars)
  ML-KEM-768 public key:      <long hex>
  ML-DSA-65 public key:       <long hex>
  ML-DSA-65 fingerprint:      SHA256:<fingerprint>
```

Copy the **X25519 public key** (64 hex characters) to the server's authorized keys.

### Method 1: Single authorized_keys file

```sh
# Create the file
mkdir -p /etc/seam
cat > /etc/seam/authorized_keys << 'EOF'
# alice's workstation
a1b2c3d4e5f6000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

# ops team shared key
deadbeefcafe000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
EOF
chmod 640 /etc/seam/authorized_keys
```

Pass to `seam serve`:

```sh
seam serve --port 2222 --auth-keys /etc/seam/authorized_keys
```

### Method 2: Authorized keys directory

```sh
mkdir -p /etc/seam/authorized_keys.d
chmod 750 /etc/seam/authorized_keys.d

# One file per user or team
echo "a1b2c3d4e5f6..." > /etc/seam/authorized_keys.d/alice.pub
echo "deadbeefcafe..." > /etc/seam/authorized_keys.d/ops-team.pub
chmod 640 /etc/seam/authorized_keys.d/*.pub
```

Pass to `seam serve`:

```sh
seam serve --port 2222 --auth-keys-dir /etc/seam/authorized_keys.d/
```

Files must have a `.pub` extension. Keys are reloaded at startup only (not watched at runtime). Restart the daemon after adding or removing keys.

### What happens with auth enabled

When `--auth-keys` or `--auth-keys-dir` is specified:

- A client must complete the post-quantum Noise_XX handshake before its key is checked (the handshake is unauthenticated at the protocol level; authentication is enforced after).
- After the handshake, the client's X25519 static public key is extracted and compared against the authorized key set.
- If the key is not in the set, the connection is dropped immediately with a log message.
- If no keys are loaded (empty file or empty directory), **all connections are rejected**. The daemon warns on startup: `WARNING: auth enabled but no keys loaded — ALL connections will be rejected`.

Without `--auth-keys` or `--auth-keys-dir`, any client that completes the handshake is accepted (anonymous mode). Combined with `--tofu` on the client side, this still provides identity pinning on the client.

---

## Systemd Unit File

Create `/etc/systemd/system/seam-serve.service`:

```ini
[Unit]
Description=Seam post-quantum UDP server
Documentation=https://github.com/North9-Labs/Seam
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=seam
Group=seam
ExecStart=/usr/local/bin/seam serve \
    --port 2222 \
    --bind 0.0.0.0 \
    --max-connections 64 \
    --auth-keys-dir /etc/seam/authorized_keys.d/
Restart=on-failure
RestartSec=5s

# FIPS mode — uncomment for compliant deployments:
# Environment="SEAM_FIPS_MODE=1"

# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/seam /home/seam/.config/seam /home/seam/.local/share/seam
AmbientCapabilities=
CapabilityBoundingSet=

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=seam-serve

[Install]
WantedBy=multi-user.target
```

### Service account setup

```sh
# Create system user (no login shell, no home directory password)
useradd --system --no-create-home --shell /usr/sbin/nologin seam

# Create home for config and identity key
mkdir -p /home/seam/.config/seam /home/seam/.local/share/seam
chown -R seam:seam /home/seam

# Pre-generate a persistent identity key as the seam user
sudo -u seam seam key
# This creates /home/seam/.config/seam/identity (perms 0600)

# Set up authorized keys directory
mkdir -p /etc/seam/authorized_keys.d
chown seam:seam /etc/seam
chmod 750 /etc/seam
```

### Enable and start

```sh
systemctl daemon-reload
systemctl enable seam-serve
systemctl start seam-serve
systemctl status seam-serve
```

### Log viewing

```sh
journalctl -u seam-serve -f
journalctl -u seam-serve --since "1 hour ago"
```

---

## FIPS Mode in Production

To run `seam serve` in FIPS mode:

Option 1 — Environment variable in the unit file (recommended):

```ini
[Service]
Environment="SEAM_FIPS_MODE=1"
```

Option 2 — CLI flag:

```ini
ExecStart=/usr/local/bin/seam serve --fips-mode --port 2222 ...
```

Option 3 — Config file for the `seam` user:

```sh
sudo -u seam seam config set fips_mode true
sudo -u seam seam config set cipher aes256gcm
```

Verify FIPS mode is active in the logs:

```sh
journalctl -u seam-serve | grep "FIPS mode active"
```

---

## Monitoring with seam health

`seam health` performs a post-quantum connection and runs a battery of checks against a running `seam serve` instance. Use it for:

- **Kubernetes liveness probes**
- **Nagios / Icinga / Prometheus alerting**
- **Cron-based health checks**
- **Post-deployment verification**

### Basic check

```sh
# SSH bootstrap + check
seam health ops@server

# Direct connection (for monitoring from inside the network)
seam health myserver \
    --direct "SEAM PORT=2222 X25519=<hex> KEM=<hex>" \
    --json
```

### JSON output for monitoring systems

```sh
seam health myserver --direct "SEAM PORT=2222 X25519=<hex> KEM=<hex>" \
    --json --quiet
```

```json
{
  "target": "myserver",
  "overall": "PASS",
  "checks": [
    {"check": "connection", "status": "PASS", "detail": "post-quantum handshake in 12ms"},
    {"check": "key-fingerprint", "status": "PASS", "detail": "X25519: a1b2c3d4e5f6… (known_hosts ok)"},
    {"check": "version", "status": "PASS", "detail": "server=0.1.32 client=0.1.32"},
    {"check": "rtt", "status": "PASS", "detail": "min=11.50ms avg=12.30ms max=13.10ms loss=0% (5/5 ok)"}
  ]
}
```

Exit code 0 = all checks passed; exit code 1 = one or more failed.

### Obtaining the SEAM line for direct monitoring

Start the server with `--print-seam-line` to emit the SEAM connection line and continue running:

```sh
seam serve --port 2222 --print-seam-line > /var/run/seam.line &
```

Then use the line in monitoring:

```sh
SEAM_LINE=$(cat /var/run/seam.line)
seam health myserver --direct "$SEAM_LINE" --json --quiet
```

### Nagios / Icinga check script

```sh
#!/bin/bash
# /usr/local/lib/nagios/plugins/check_seam
set -euo pipefail

HOST="${1:?HOST required}"
PORT="${2:-2222}"
X25519="${3:?X25519 key required}"
KEM="${4:?KEM key required}"

SEAM_LINE="SEAM PORT=${PORT} X25519=${X25519} KEM=${KEM}"

if seam health "$HOST" --direct "$SEAM_LINE" --json --quiet 2>/dev/null | \
    jq -e '.overall == "PASS"' > /dev/null; then
    echo "OK: seam serve on ${HOST}:${PORT} is healthy"
    exit 0
else
    echo "CRITICAL: seam serve on ${HOST}:${PORT} health check failed"
    exit 2
fi
```

---

## Audit Log Management

Seam writes an append-only audit log to `~/.local/share/seam/audit.jsonl` (for the user running `seam`; for the systemd service user, this is `/home/seam/.local/share/seam/audit.jsonl`).

### Log rotation

The audit log is append-only JSONL (one JSON object per line). Use logrotate to manage it:

```
# /etc/logrotate.d/seam-audit
/home/seam/.local/share/seam/audit.jsonl {
    daily
    rotate 90
    compress
    missingok
    notifempty
    copytruncate
    su seam seam
}
```

`copytruncate` is used because seam opens the file with `O_APPEND` and does not support logrotate's `postrotate` / signal-based rotation. `copytruncate` copies the log then truncates the original in-place — there is a small window where a few entries may be lost.

For compliance environments requiring zero-loss audit trails, mount the audit log directory on a dedicated append-only storage volume and skip truncation; rely on archive and retention policies at the storage level.

### Querying the audit log

```sh
# Show last 20 entries
seam audit show

# Entries since a date
seam audit show --since 2025-06-01

# Filter by remote host
seam audit show --host server.example.com

# Raw JSONL for custom processing
seam audit show --json | jq 'select(.exit_code != 0)'

# Count operations by type in the last week
seam audit show -n 0 --since 2025-05-28 --json \
    | jq -r '.subcommand' | sort | uniq -c | sort -rn
```

### Audit log health check

`seam doctor` checks whether the audit log is readable and writable. For automated health checks:

```sh
seam doctor 2>&1 | grep -i audit
```

---

## Key Management

### Viewing the server's public key

```sh
# Run as the seam service user
sudo -u seam seam key
```

The X25519 and ML-KEM-768 public keys are printed on startup of `seam serve` and can also be retrieved with `seam key`. Distribute these to clients for use with `--tofu` pinning or for configuring relay nodes.

### Key rotation procedure

1. Rotate the key:
   ```sh
   sudo -u seam seam key --rotate
   ```
2. Note the new X25519 and KEM public keys from the output.
3. Update all client `known_hosts` entries: clients will see a key mismatch warning on next connection.
4. Remove old pins on each client:
   ```sh
   seam key --remove-pin server.example.com
   ```
5. On next connection with `--tofu`, the new key is pinned automatically.
6. Update any `auth-keys` files on other servers that list this server as a client.
7. Restart `seam-serve`:
   ```sh
   systemctl restart seam-serve
   ```

---

## Multi-Server Deployments

For deployments with multiple seam servers:

- Each server has its own persistent identity key (`~/.config/seam/identity` or the service user's equivalent).
- Clients maintain a `~/.config/seam/known_hosts` file with per-hostname key pins.
- Authorized key sets can be shared across servers by distributing the same `authorized_keys` file or keys directory.
- Use `--via user@jumphost` on `seam forward` to route through relay servers without opening direct UDP paths from all clients to all servers.

### Relay topology example

```
client ──[Seam PQ]── relay.example.com ──[Seam PQ]── internal.corp.example.com
```

```sh
seam forward 8080:localhost:80 --via ops@relay.example.com ops@internal.corp.example.com
```

Both hops are independently post-quantum encrypted. The relay cannot read the payload of the inner connection.
