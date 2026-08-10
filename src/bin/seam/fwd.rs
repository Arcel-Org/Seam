use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::Args;
use seam_protocol::{
    api::Server,
    handshake::{IdentityKeypair, pk_to_bytes},
    tunnel::SeamMux,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::{connect, ssh};

/// Maximum number of forwarded connections/streams handled concurrently by a
/// single `seam fwd` (client) or `_fwd-recv` (remote receiver) process.
///
/// `seam fwd` deliberately exposes a TCP port to inbound traffic — that's the
/// whole point of a reverse forward — so without a cap, anyone able to reach
/// that port could open unbounded concurrent connections. Each one
/// unconditionally spawned a Tokio task and opened a new mux stream on both
/// sides with no limit, which is fd/memory exhaustion triggerable by anyone
/// who can reach the forwarded port, not just the operator. 256 is a
/// generous default for interactive/reverse-tunnel use; adjust if needed.
const MAX_CONCURRENT_FORWARDS: usize = 256;

/// Acquire a forward slot from `slots`, waiting (and logging once) if the
/// pool is already saturated. Shared by both the client (`run`) and receiver
/// (`run_recv`) accept loops so a burst of inbound connections can't spawn
/// unbounded concurrent work — callers acquire this *before* accepting the
/// next connection/stream, so excess connections queue for a slot (kernel
/// backlog on the TCP side) instead of all being accepted and spawned at
/// once.
async fn acquire_forward_slot(
    slots: &Arc<Semaphore>,
    context: &str,
) -> tokio::sync::OwnedSemaphorePermit {
    match Arc::clone(slots).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            eprintln!(
                "{context}: {MAX_CONCURRENT_FORWARDS} concurrent forwarded connections already \
                 in use; waiting for a slot before accepting more"
            );
            Arc::clone(slots)
                .acquire_owned()
                .await
                .expect("forward_slots semaphore is never closed")
        }
    }
}

// ── Client args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct FwdArgs {
    /// Reverse tunnel spec: user@host:REMOTE_PORT  (remote listens on REMOTE_PORT)
    pub remote_spec: String,
    /// Local port to forward connections to (on this machine)
    pub local_port: u16,
    /// SSH port for the bootstrap connection
    #[arg(short = 'p', long)]
    pub port: Option<u16>,
    /// Local host to forward connections to (default: 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1")]
    pub local_host: String,
}

// ── Server args ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct FwdRecvArgs {
    /// TCP port the remote side should listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub listen_port: u16,
    /// UDP port for the Seam server (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
}

// ── Parse fwd spec ────────────────────────────────────────────────────────────

/// Parse `user@host:RPORT` → `(user, host, remote_port)`.
fn parse_fwd_spec(spec: &str) -> Result<(Option<String>, String, u16)> {
    let (userhost, port_str) = spec
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("fwd spec must be user@host:REMOTE_PORT"))?;

    let remote_port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("invalid remote port: {port_str}"))?;

    let (user, host) = if let Some(at) = userhost.find('@') {
        (
            Some(userhost[..at].to_string()),
            userhost[at + 1..].to_string(),
        )
    } else {
        (None, userhost.to_string())
    };

    Ok((user, host, remote_port))
}

// ── Client (initiating side) ──────────────────────────────────────────────────

pub async fn run(args: FwdArgs) -> Result<()> {
    let (user, host, remote_port) = parse_fwd_spec(&args.remote_spec)?;
    let local_host = args.local_host.clone();
    let local_port = args.local_port;
    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();

    let remote = ssh::RemoteInfo {
        host: host.clone(),
        user: user.clone(),
        ssh_port: args.port,
    };

    // Start the remote receiver: it will listen on TCP :remote_port and wait for
    // the Seam client (us) to connect, then forward accepted TCP connections back.
    let subcmd = format!("_fwd-recv --listen-port {} --port 0", remote_port);
    let (conn, child) = connect::bootstrap_and_connect(&remote, &host, &subcmd, cipher).await?;

    let mux = SeamMux::new(conn);

    eprintln!(
        "reverse tunnel ready: {}{}:{} → {}:{}",
        user.as_deref().map(|u| format!("{u}@")).unwrap_or_default(),
        host,
        remote_port,
        local_host,
        local_port,
    );
    eprintln!(
        "  (connections on remote :{remote_port} forwarded to local {local_host}:{local_port})"
    );

    // The remote side pushes streams to us whenever a TCP connection is accepted.
    // We accept each stream and connect it to local_host:local_port.
    // consecutive_failures tracks repeated local connect failures; after 5 in a row
    // we back off briefly to avoid spamming logs and burning CPU.
    let consecutive_failures: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
    let forward_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_FORWARDS));

    loop {
        // Acquire a slot before accepting the next stream, so we don't keep
        // pulling in unbounded work from the mux when we're already at
        // capacity — this provides real backpressure rather than just
        // capping the count of spawned tasks.
        let permit = acquire_forward_slot(&forward_slots, "fwd").await;

        let stream = match mux.accept_stream().await {
            Some(s) => s,
            None => break,
        };
        let target = format!("{local_host}:{local_port}");
        let failures = Arc::clone(&consecutive_failures);
        tokio::spawn(async move {
            let _permit = permit;
            // Back off if local target has been repeatedly unreachable.
            let fail_count = failures.load(Ordering::Relaxed);
            if fail_count > 0 {
                let delay = Duration::from_millis(match fail_count {
                    1..=2 => 100,
                    3..=5 => 500,
                    _ => 2000,
                });
                tokio::time::sleep(delay).await;
            }

            match tokio::net::TcpStream::connect(&target).await {
                Ok(mut tcp) => {
                    failures.store(0, Ordering::Relaxed);
                    let mut s = stream;
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut tcp).await;
                }
                Err(e) => {
                    let n = failures.fetch_add(1, Ordering::Relaxed) + 1;
                    eprintln!("fwd: could not connect to local {target}: {e} (failure #{n})");
                    // Dropping stream signals EOF to the remote side.
                    drop(stream);
                }
            }
        });
    }

    // The mux/connection is done — tear down the bootstrap SSH child (and
    // the remote `seam` worker it started) explicitly. Just letting `child`
    // drop here would NOT signal the process (Child::drop only closes our
    // handle to it), leaking an orphaned local `ssh` process and remote
    // worker on every successful `seam fwd` run.
    ssh::terminate_async(child).await;

    Ok(())
}

// ── Remote receiver ───────────────────────────────────────────────────────────

pub async fn run_recv(args: FwdRecvArgs) -> Result<()> {
    // Start the Seam server so the client can connect back.
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let cipher = seam_protocol::crypto::CipherSuite::parse(&cfg.cipher).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow!("{e}"))?;
    let udp_port = server.local_addr()?.port();

    // Bind the TCP listener before announcing — so the port is ready when the
    // client connects.
    let tcp_listener = TcpListener::bind(("0.0.0.0", args.listen_port))
        .await
        .map_err(|e| anyhow!("failed to bind TCP :{}: {e}", args.listen_port))?;
    let actual_tcp_port = tcp_listener.local_addr()?.port();

    // Announce both UDP seam port and the TCP listen port.
    println!("SEAM PORT={udp_port} X25519={x25519_hex} KEM={kem_hex} TCP={actual_tcp_port}");

    let conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow!("no connection"))?;
    let mux = SeamMux::new(conn);
    eprintln!("reverse tunnel receiver ready on TCP :{actual_tcp_port}");

    // Accept TCP connections from the outside world and open Seam streams back
    // to the originating client for each one. This is the side directly
    // reachable by inbound traffic, so it's the primary place an unbounded
    // accept loop turns into remotely-triggerable fd/memory exhaustion —
    // gate it with the same forward-slot cap as the client loop above.
    let forward_slots = Arc::new(Semaphore::new(MAX_CONCURRENT_FORWARDS));
    loop {
        let permit = acquire_forward_slot(&forward_slots, "fwd-recv").await;

        let (mut tcp, peer) = match tcp_listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("tcp accept error: {e}");
                // Sustained accept errors (e.g. EMFILE) would otherwise busy-spin
                // this loop; a brief backoff keeps CPU/log usage sane.
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        tracing::debug!("fwd-recv: new TCP connection from {peer}");
        let mux = mux.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let mut seam = mux.open_stream().await;
            let _ = tokio::io::copy_bidirectional(&mut seam, &mut tcp).await;
        });
    }
}

// ── We need to handle the extra TCP= field in the SEAM line ─────────────────
// The client uses connect::parse_seam_line which ignores unknown fields, so
// the extra TCP= field is silently skipped. That's fine — we derive the
// remote TCP port from args, not from the SEAM line.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Regression test for the unbounded-connection-fanout bug: `seam fwd` exposes
    /// a local TCP port to inbound traffic and, before this fix, unconditionally
    /// spawned a Tokio task + opened a new mux stream per accepted connection with
    /// no cap — fd/memory exhaustion triggerable by anyone who can reach the
    /// forwarded port. `acquire_forward_slot` is the shared choke point both
    /// accept loops (`run` and `run_recv`) now gate on; verify directly (using a
    /// real `Semaphore`, not a mock) that:
    ///   1. no more than `cap` callers ever hold a permit concurrently, and
    ///   2. callers beyond the cap wait (backpressure) rather than being dropped
    ///      or all being let through at once.
    #[tokio::test]
    async fn acquire_forward_slot_caps_concurrency_and_queues_the_rest() {
        let cap = 4usize;
        let total = cap * 3;
        let slots = Arc::new(Semaphore::new(cap));
        let current = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        // Opened only after we've confirmed the cap is being enforced; gates how
        // many callers may finish and release their forward slot.
        let release_gate = Arc::new(Semaphore::new(0));

        let mut handles = Vec::with_capacity(total);
        for _ in 0..total {
            let slots = Arc::clone(&slots);
            let current = Arc::clone(&current);
            let max_seen = Arc::clone(&max_seen);
            let completed = Arc::clone(&completed);
            let release_gate = Arc::clone(&release_gate);
            handles.push(tokio::spawn(async move {
                let permit = acquire_forward_slot(&slots, "test").await;
                let now = current.fetch_add(1, Ordering::SeqCst) + 1;
                max_seen.fetch_max(now, Ordering::SeqCst);

                // Hold the slot until the test releases us.
                let _release_permit = release_gate.acquire_owned().await.unwrap();

                current.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
                drop(permit);
            }));
        }

        // Wait until exactly `cap` callers are holding a permit concurrently.
        // Bounded by an overall timeout (not a fixed sleep) so this can't hang the
        // suite if the cap is broken; the poll itself doesn't assert on timing.
        tokio::time::timeout(Duration::from_secs(5), async {
            while current.load(Ordering::SeqCst) < cap {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expected `cap` callers to acquire a permit concurrently");

        // Give the scheduler plenty of chances to let more than `cap` through if
        // the semaphore weren't actually bounding concurrency.
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            current.load(Ordering::SeqCst),
            cap,
            "no more than `cap` forwarded connections should be in flight at once"
        );
        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            cap,
            "concurrency must never have exceeded the cap"
        );
        assert_eq!(
            completed.load(Ordering::SeqCst),
            0,
            "excess callers must still be queued, not dropped or completed early"
        );

        // Release everyone; every queued caller must eventually get a slot and
        // finish (proving they were waiting, not silently dropped).
        release_gate.add_permits(total);
        for h in handles {
            tokio::time::timeout(Duration::from_secs(5), h)
                .await
                .expect("queued caller never completed after its slot was released")
                .unwrap();
        }
        assert_eq!(completed.load(Ordering::SeqCst), total);
    }
}
