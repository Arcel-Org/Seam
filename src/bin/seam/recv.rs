use anyhow::{Result, bail};
use clap::Args;
use seam_protocol::{
    api::{SeamConn, Server},
    handshake::{IdentityKeypair, pk_to_bytes},
    session::stream::StreamId,
};
use std::path::PathBuf;

use crate::proto::{self, read_frame, read_frame_opt, send_frame, wait_for_stream};

#[derive(Args)]
pub struct RecvArgs {
    /// Destination directory for received files
    pub dest: PathBuf,
    /// UDP port to listen on (0 = OS-assigned)
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Exit after one transfer. Without this flag, the receiver stays up and
    /// accepts additional HELLO/file rounds on the same connection until the
    /// sender closes it — used by `seam watch` to avoid re-handshaking for
    /// every sync cycle.
    #[arg(long)]
    pub once: bool,
    /// Accept this many independent connections instead of one, each drained
    /// concurrently into the same destination directory. Used internally by
    /// `seam cp --multipath` — each local path on the sender's side opens its
    /// own fully-handshaked connection here, so no server-side awareness of
    /// "multiple addresses, one session" is needed.
    #[arg(long, default_value_t = 1)]
    pub multipath_count: usize,
}

pub async fn run(args: RecvArgs, cli_fips_mode: bool) -> Result<()> {
    let id = IdentityKeypair::generate();
    let x25519_hex = hex::encode(id.x25519_public.as_bytes());
    let kem_hex = hex::encode(pk_to_bytes(&id.kem_pk));

    let cfg = super::config::Config::load().ok().unwrap_or_default();
    let fips_mode = super::config::Config::effective_fips_mode(cfg.fips_mode, cli_fips_mode);
    let cipher_str = if fips_mode { "aes256gcm" } else { &cfg.cipher };
    let cipher = seam_protocol::crypto::CipherSuite::parse(cipher_str).unwrap_or_default();
    let addr: std::net::SocketAddr = format!("0.0.0.0:{}", args.port).parse()?;
    let mut server = Server::bind_with_cipher(addr, id, cipher)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let port = server.local_addr()?.port();

    // Sender reads this line over SSH to get connection info.
    println!("SEAM PORT={port} X25519={x25519_hex} KEM={kem_hex}");

    std::fs::create_dir_all(&args.dest)?;

    if args.multipath_count > 1 {
        let mut conns = Vec::with_capacity(args.multipath_count);
        for _ in 0..args.multipath_count {
            conns.push(
                server
                    .accept()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("no connection"))?,
            );
        }
        let mut tasks = Vec::with_capacity(conns.len());
        for mut conn in conns {
            let dest = args.dest.clone();
            tasks.push(tokio::spawn(async move {
                let result = serve_connection(&mut conn, &dest, fips_mode, true).await;
                conn.close().await;
                result
            }));
        }
        for task in tasks {
            task.await.map_err(|e| anyhow::anyhow!("{e}"))??;
        }
        return Ok(());
    }

    let mut conn = server
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("no connection"))?;

    serve_connection(&mut conn, &args.dest, fips_mode, args.once).await?;

    conn.close().await;
    Ok(())
}

/// Accept HELLO..DONE rounds on `conn` until either `once` is set (exit after
/// the first round) or the sender closes the connection cleanly between
/// rounds. Split out from [`run`] so it's directly testable over a local
/// loopback connection without going through SSH bootstrap.
async fn serve_connection(
    conn: &mut SeamConn,
    dest: &std::path::Path,
    fips_mode: bool,
    once: bool,
) -> Result<()> {
    let ctrl_sid = wait_for_stream(conn).await?;
    let _ = conn.tick().await;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        let hello = match read_frame_opt(conn, ctrl_sid, &mut buf).await? {
            Some(f) => f,
            None => break, // peer disconnected without a clean BYE (e.g. crash)
        };
        if hello.first() == Some(&proto::BYE) {
            break; // sender is done for good
        }
        receive_round(conn, ctrl_sid, &hello, dest, fips_mode, &mut buf).await?;
        if once {
            break;
        }
    }
    Ok(())
}

/// Handle one HELLO..DONE round on an already-open control stream.
async fn receive_round(
    conn: &mut SeamConn,
    ctrl_sid: StreamId,
    hello: &[u8],
    dest: &std::path::Path,
    fips_mode: bool,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let _ = conn.tick().await;
    if hello.is_empty() || hello[0] != proto::HELLO {
        bail!(
            "expected HELLO, got {:02x}",
            hello.first().copied().unwrap_or(0)
        );
    }
    let compress = hello.len() > 1 && hello[1] == proto::COMPRESS_ZSTD;

    // ACK — send_frame calls flush(), so ACKs go out here too.
    send_frame(conn, ctrl_sid, &[proto::ACK]).await?;

    // File receive loop
    loop {
        let frame = read_frame(conn, ctrl_sid, buf).await?;
        // Flush ACKs for all packets received while assembling this frame.
        let _ = conn.tick().await;

        if frame.is_empty() {
            bail!("empty frame");
        }
        match frame[0] {
            proto::FILE_INFO => {
                receive_file(conn, ctrl_sid, &frame, dest, compress, buf, fips_mode).await?;
            }
            proto::PARALLEL_INIT => {
                if frame.len() < 2 {
                    bail!("PARALLEL_INIT frame too short");
                }
                let n_chunks = frame[1] as usize;
                receive_parallel(conn, ctrl_sid, n_chunks, dest, compress, buf, fips_mode).await?;
            }
            proto::DONE => break,
            t => bail!("unexpected frame type 0x{:02x}", t),
        }
    }
    Ok(())
}

/// Receive a file split across N parallel chunk streams.
///
/// The sender has already sent PARALLEL_INIT on ctrl_sid. We now accept N
/// chunk streams (via wait_for_stream), parse their CHUNK_INFO headers, write
/// each byte range directly to the output file at the correct offset, verify
/// per-chunk checksums, and send ACK on each chunk stream.
async fn receive_parallel(
    conn: &mut SeamConn,
    _ctrl_sid: StreamId,
    n_chunks: usize,
    dest: &std::path::Path,
    compress: bool,
    _buf: &mut Vec<u8>,
    fips_mode: bool,
) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    // Accept the N chunk streams. They arrive in the order the sender opened them.
    let mut chunk_sids = Vec::with_capacity(n_chunks);
    for _ in 0..n_chunks {
        let sid = wait_for_stream(conn).await?;
        chunk_sids.push(sid);
    }

    // First pass: read all CHUNK_INFO headers to learn the file name and total size.
    // We need to create the output file before writing chunks.
    let mut chunk_infos: Vec<(u8, u64, u64, String)> = Vec::with_capacity(n_chunks); // (index, offset, chunk_size, name)
    let mut chunk_bufs: Vec<Vec<u8>> = vec![Vec::new(); n_chunks];

    for (i, &sid) in chunk_sids.iter().enumerate() {
        let info_frame = read_frame(conn, sid, &mut chunk_bufs[i]).await?;
        if info_frame.len() < 21 || info_frame[0] != proto::CHUNK_INFO {
            bail!("expected CHUNK_INFO on chunk stream {i}");
        }
        let chunk_index = info_frame[1];
        let offset = u64::from_be_bytes(info_frame[3..11].try_into()?);
        let chunk_size = u64::from_be_bytes(info_frame[11..19].try_into()?);
        let name_len = u16::from_be_bytes(info_frame[19..21].try_into()?) as usize;
        if info_frame.len() < 21 + name_len {
            bail!("CHUNK_INFO name truncated on chunk stream {i}");
        }
        let name = String::from_utf8(info_frame[21..21 + name_len].to_vec())?;
        if name.contains("..") || std::path::Path::new(&name).is_absolute() {
            bail!("refusing dangerous filename in parallel chunk: {name}");
        }
        chunk_infos.push((chunk_index, offset, chunk_size, name));
    }

    // Derive output path from chunk 0.
    let name = &chunk_infos[0].3;
    let out_path = dest.join(name);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Compute total size from chunk offsets.
    let total_size: u64 = chunk_infos
        .iter()
        .map(|(_, o, s, _)| o + s)
        .max()
        .unwrap_or(0);

    // Pre-allocate the output file.
    {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&out_path)?;
        f.set_len(total_size)?;
    }

    use crate::copy::IncrementalHasher;
    let algo_name = if fips_mode { "SHA-256" } else { "BLAKE3" };

    // Receive each chunk and write at its offset.
    for (i, &sid) in chunk_sids.iter().enumerate() {
        let (_, offset, chunk_size, _) = &chunk_infos[i];
        let offset = *offset;
        let chunk_size = *chunk_size;

        let mut file = std::fs::OpenOptions::new().write(true).open(&out_path)?;
        file.seek(SeekFrom::Start(offset))?;

        let mut hasher = IncrementalHasher::new(fips_mode);
        let mut received: u64 = 0;
        while received < chunk_size {
            let data_frame = read_frame(conn, sid, &mut chunk_bufs[i]).await?;
            if data_frame.is_empty() || data_frame[0] != proto::DATA {
                bail!("expected DATA frame in chunk stream {i}");
            }
            let raw = &data_frame[1..];
            if compress {
                let decoded = zstd::decode_all(raw)?;
                hasher.update(&decoded);
                file.write_all(&decoded)?;
                received += decoded.len() as u64;
            } else {
                hasher.update(raw);
                file.write_all(raw)?;
                received += raw.len() as u64;
            }
        }
        file.flush()?;
        drop(file);

        // Verify per-chunk checksum.
        let cksum_frame = read_frame(conn, sid, &mut chunk_bufs[i]).await?;
        if cksum_frame.len() == 33 && cksum_frame[0] == proto::CHECKSUM {
            let expected = &cksum_frame[1..33];
            let actual = hasher.finalize();
            if actual == expected {
                send_frame(conn, sid, &[proto::ACK]).await?;
                eprintln!(
                    "chunk {i}: {chunk_size} bytes [{algo_name} OK: {}]",
                    hex::encode(&expected[..8])
                );
            } else {
                bail!(
                    "chunk {i} {algo_name} mismatch: expected {} got {}",
                    hex::encode(expected),
                    hex::encode(actual)
                );
            }
        } else {
            bail!("missing CHECKSUM frame from chunk stream {i}");
        }
    }

    eprintln!(
        "received: {name} ({total_size} bytes) [parallel {n_chunks} streams, {algo_name} OK]"
    );
    Ok(())
}

async fn receive_file(
    conn: &mut SeamConn,
    ctrl_sid: StreamId,
    info_frame: &[u8],
    dest: &std::path::Path,
    compress: bool,
    buf: &mut Vec<u8>,
    fips_mode: bool,
) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    if info_frame.len() < 11 {
        bail!("FILE_INFO too short");
    }
    let size = u64::from_be_bytes(info_frame[1..9].try_into()?);
    let name_len = u16::from_be_bytes(info_frame[9..11].try_into()?) as usize;
    if info_frame.len() < 11 + name_len {
        bail!("FILE_INFO name truncated");
    }
    let name = String::from_utf8(info_frame[11..11 + name_len].to_vec())?;

    // Reject path traversal and absolute paths.
    if name.contains("..") || std::path::Path::new(&name).is_absolute() {
        bail!("refusing dangerous filename: {name}");
    }

    let out_path = dest.join(&name);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // ── Partial-file resume using .seam-partial staging ──────────────────────
    // We write to `<name>.seam-partial` during transfer and atomically rename
    // to the final name on successful checksum verification. This ensures:
    //   1. The output file is never left in a partial/corrupt state.
    //   2. If a previous transfer was interrupted, we resume from the partial.
    //   3. On checksum mismatch we delete the partial and signal the sender.
    let partial_path = {
        let mut p = out_path.clone();
        let mut fname = p.file_name().unwrap_or_default().to_owned();
        fname.push(".seam-partial");
        p.set_file_name(fname);
        p
    };

    // Check whether a compatible partial exists for resuming.
    let partial_size = partial_path.metadata().map(|m| m.len()).unwrap_or(0);
    let resume_from = if partial_size > 0 && partial_size < size {
        eprintln!("  resuming {name}: found {partial_size} of {size} bytes in partial file");
        let mut resume_frame = Vec::with_capacity(1 + 8);
        resume_frame.push(proto::RESUME);
        resume_frame.extend_from_slice(&partial_size.to_be_bytes());
        send_frame(conn, ctrl_sid, &resume_frame).await?;
        partial_size
    } else {
        // No usable partial — sender will send from byte 0.
        if partial_path.exists() {
            // Stale or complete-but-unfinished partial — remove it.
            let _ = std::fs::remove_file(&partial_path);
        }
        0
    };

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(resume_from == 0)
        .open(&partial_path)?;
    if resume_from > 0 {
        file.seek(SeekFrom::Start(resume_from))?;
    }

    use crate::copy::IncrementalHasher;
    let mut hasher = IncrementalHasher::new(fips_mode);
    let algo_name = if fips_mode { "SHA-256" } else { "BLAKE3" };
    let mut received: u64 = resume_from;
    while received < size {
        let data_frame = read_frame(conn, ctrl_sid, buf).await?;
        let _ = conn.tick().await;

        if data_frame.is_empty() || data_frame[0] != proto::DATA {
            bail!("expected DATA frame");
        }
        let raw = &data_frame[1..];
        if compress {
            let decoded = zstd::decode_all(raw)?;
            hasher.update(&decoded);
            file.write_all(&decoded)?;
            received += decoded.len() as u64;
        } else {
            hasher.update(raw);
            file.write_all(raw)?;
            received += raw.len() as u64;
        }
    }
    // Flush and sync before verifying integrity.
    file.flush()?;
    drop(file);

    // Verify checksum sent by the sender (SHA-256 in FIPS mode, BLAKE3 otherwise).
    let cksum_frame = read_frame(conn, ctrl_sid, buf).await?;
    if cksum_frame.len() == 33 && cksum_frame[0] == proto::CHECKSUM {
        let expected = &cksum_frame[1..33];
        let actual = hasher.finalize();
        if actual == expected {
            // ── Atomic promotion: partial → final path ────────────────────────
            std::fs::rename(&partial_path, &out_path)?;
            send_frame(conn, ctrl_sid, &[proto::ACK]).await?;
            eprintln!(
                "received: {name} ({size} bytes) [{algo_name} OK: {}]",
                hex::encode(&expected[..8])
            );
        } else {
            // ── Checksum mismatch: remove corrupted partial ───────────────────
            // Do NOT keep the partial — it is corrupt. The caller will need to
            // restart the transfer from byte 0 on the next attempt.
            let _ = std::fs::remove_file(&partial_path);
            bail!(
                "{algo_name} integrity check FAILED for {name}: expected {} got {} — partial deleted, retry transfer",
                hex::encode(expected),
                hex::encode(actual)
            );
        }
    } else {
        // Older peer without checksum support — promote the partial anyway.
        std::fs::rename(&partial_path, &out_path)?;
        eprintln!("received: {name} ({size} bytes) [no integrity check]");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use seam_protocol::api::{Client, Server};
    use seam_protocol::handshake::IdentityKeypair;
    use tokio::time::{Duration, timeout};

    /// Drives two full HELLO..DONE rounds over one connection — the exact
    /// pattern `seam watch`'s persistent session relies on — and checks that
    /// `serve_connection` (without `--once`) stays up between them instead
    /// of tearing the connection down after the first round.
    #[tokio::test]
    async fn persistent_session_survives_multiple_rounds() {
        let server_id = IdentityKeypair::generate();
        let server_x25519 = server_id.x25519_public.to_bytes();
        let server_kem_pk = server_id.kem_pk.clone();

        let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let (server_conn, client_conn) = tokio::join!(
            async {
                timeout(Duration::from_secs(5), server.accept())
                    .await
                    .expect("accept timed out")
                    .expect("no connection")
            },
            async {
                let client_id = IdentityKeypair::generate();
                let mut client = Client::bind("127.0.0.1:0".parse().unwrap(), client_id)
                    .await
                    .unwrap();
                timeout(
                    Duration::from_secs(5),
                    client.connect(
                        server_addr,
                        &server_x25519,
                        &server_kem_pk,
                        Default::default(),
                    ),
                )
                .await
                .expect("connect timed out")
                .expect("connect failed")
            },
        );

        let dest = tempfile::tempdir().unwrap();
        let dest_path = dest.path().to_path_buf();
        let mut server_conn = server_conn;
        let server_task = tokio::spawn(async move {
            serve_connection(&mut server_conn, &dest_path, false, false).await
        });

        let src = tempfile::tempdir().unwrap();
        let mut client_conn = client_conn;
        let ctrl_sid = client_conn.open_stream().await;

        // Round 1.
        std::fs::write(src.path().join("a.txt"), b"round one").unwrap();
        let files = crate::copy::collect_files(src.path()).unwrap();
        crate::copy::push_files(
            &mut client_conn,
            ctrl_sid,
            src.path(),
            &files,
            false,
            false,
            1,
            false,
            None,
        )
        .await
        .expect("round 1 push failed");

        // Round 2 — same connection, same control stream, no reconnect.
        std::fs::write(src.path().join("b.txt"), b"round two").unwrap();
        let files = crate::copy::collect_files(src.path()).unwrap();
        crate::copy::push_files(
            &mut client_conn,
            ctrl_sid,
            src.path(),
            &files,
            false,
            false,
            1,
            false,
            None,
        )
        .await
        .expect("round 2 push failed");

        // Send BYE so the server's round loop sees a clean end-of-session
        // instead of waiting on an idle timeout (mirrors what `seam watch`'s
        // PersistentPush::close does on real shutdown).
        send_frame(&client_conn, ctrl_sid, &[proto::BYE])
            .await
            .unwrap();
        client_conn.close().await;

        timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server task timed out")
            .expect("server task panicked")
            .expect("serve_connection returned an error");

        assert_eq!(
            std::fs::read(dest.path().join("a.txt")).unwrap(),
            b"round one"
        );
        assert_eq!(
            std::fs::read(dest.path().join("b.txt")).unwrap(),
            b"round two"
        );
    }

    /// With `--once`, the receiver must stop after the first round even
    /// though the sender keeps the connection open for a second one —
    /// this is the pre-existing behavior every other `seam` command relies
    /// on and must not regress.
    #[tokio::test]
    async fn once_mode_stops_after_first_round() {
        let server_id = IdentityKeypair::generate();
        let server_x25519 = server_id.x25519_public.to_bytes();
        let server_kem_pk = server_id.kem_pk.clone();

        let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        let (server_conn, client_conn) = tokio::join!(
            async {
                timeout(Duration::from_secs(5), server.accept())
                    .await
                    .expect("accept timed out")
                    .expect("no connection")
            },
            async {
                let client_id = IdentityKeypair::generate();
                let mut client = Client::bind("127.0.0.1:0".parse().unwrap(), client_id)
                    .await
                    .unwrap();
                timeout(
                    Duration::from_secs(5),
                    client.connect(
                        server_addr,
                        &server_x25519,
                        &server_kem_pk,
                        Default::default(),
                    ),
                )
                .await
                .expect("connect timed out")
                .expect("connect failed")
            },
        );

        let dest = tempfile::tempdir().unwrap();
        let dest_path = dest.path().to_path_buf();
        let mut server_conn = server_conn;
        let server_task = tokio::spawn(async move {
            serve_connection(&mut server_conn, &dest_path, false, true).await
        });

        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"only round").unwrap();
        let mut client_conn = client_conn;
        let ctrl_sid = client_conn.open_stream().await;
        let files = crate::copy::collect_files(src.path()).unwrap();
        crate::copy::push_files(
            &mut client_conn,
            ctrl_sid,
            src.path(),
            &files,
            false,
            false,
            1,
            false,
            None,
        )
        .await
        .expect("push failed");

        // `--once` should have already returned after round one — no need
        // to close the client connection for the server task to finish.
        timeout(Duration::from_secs(5), server_task)
            .await
            .expect("server task timed out — --once did not stop after one round")
            .expect("server task panicked")
            .expect("serve_connection returned an error");

        assert_eq!(
            std::fs::read(dest.path().join("a.txt")).unwrap(),
            b"only round"
        );
    }

    /// Exercises the mechanics `seam cp --multipath` relies on: N independent,
    /// concurrently-accepted connections (mirroring `recv --multipath-count`)
    /// each round-robin-fed a distinct subset of files, converging on the
    /// same destination directory. Bypasses `connect::dial`/SSH bootstrap
    /// entirely (which touch real on-disk identity/known_hosts state) and
    /// drives `Client`/`Server` directly, like the tests above.
    #[tokio::test]
    async fn multipath_round_robin_delivers_all_files_across_independent_sessions() {
        const PATHS: usize = 3;

        let server_id = IdentityKeypair::generate();
        let server_x25519 = server_id.x25519_public.to_bytes();
        let server_kem_pk = server_id.kem_pk.clone();

        let mut server = Server::bind("127.0.0.1:0".parse().unwrap(), server_id)
            .await
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // Dial PATHS independent client connections concurrently — each is
        // its own full handshake, exactly like `dial_from` per local address.
        let mut dial_tasks = Vec::new();
        for _ in 0..PATHS {
            let server_kem_pk = server_kem_pk.clone();
            dial_tasks.push(tokio::spawn(async move {
                let client_id = IdentityKeypair::generate();
                let mut client = Client::bind("127.0.0.1:0".parse().unwrap(), client_id)
                    .await
                    .unwrap();
                timeout(
                    Duration::from_secs(5),
                    client.connect(
                        server_addr,
                        &server_x25519,
                        &server_kem_pk,
                        Default::default(),
                    ),
                )
                .await
                .expect("connect timed out")
                .expect("connect failed")
            }));
        }

        // Accept PATHS connections server-side (order doesn't need to match
        // dial order — files are self-describing, not path-indexed).
        let mut server_conns = Vec::with_capacity(PATHS);
        for _ in 0..PATHS {
            server_conns.push(
                timeout(Duration::from_secs(5), server.accept())
                    .await
                    .expect("accept timed out")
                    .expect("no connection"),
            );
        }

        let dest = tempfile::tempdir().unwrap();
        let mut server_tasks = Vec::with_capacity(PATHS);
        for mut conn in server_conns {
            let dest_path = dest.path().to_path_buf();
            server_tasks.push(tokio::spawn(async move {
                let r = serve_connection(&mut conn, &dest_path, false, true).await;
                conn.close().await;
                r
            }));
        }

        let src = tempfile::tempdir().unwrap();
        let all_files: Vec<String> = (0..PATHS * 2).map(|i| format!("file{i}.txt")).collect();
        for name in &all_files {
            std::fs::write(src.path().join(name), format!("contents of {name}")).unwrap();
        }
        let files = crate::copy::collect_files(src.path()).unwrap();

        // Round-robin bucket files across the PATHS dialed connections —
        // same scheme as `run_multipath_push`.
        let mut buckets: Vec<Vec<(String, std::fs::Metadata)>> =
            (0..PATHS).map(|_| Vec::new()).collect();
        for (i, file) in files.into_iter().enumerate() {
            buckets[i % PATHS].push(file);
        }

        let mut client_conns = Vec::with_capacity(PATHS);
        for task in dial_tasks {
            client_conns.push(task.await.unwrap());
        }

        let mut push_tasks = Vec::with_capacity(PATHS);
        for (mut conn, bucket) in client_conns.into_iter().zip(buckets) {
            let src_path = src.path().to_path_buf();
            push_tasks.push(tokio::spawn(async move {
                let ctrl_sid = conn.open_stream().await;
                let r = crate::copy::push_files(
                    &mut conn, ctrl_sid, &src_path, &bucket, false, false, 1, false, None,
                )
                .await;
                conn.close().await;
                r
            }));
        }
        for task in push_tasks {
            task.await.unwrap().expect("push failed");
        }
        for task in server_tasks {
            task.await
                .unwrap()
                .expect("serve_connection returned an error");
        }

        for name in &all_files {
            assert_eq!(
                std::fs::read(dest.path().join(name)).unwrap(),
                format!("contents of {name}").into_bytes(),
                "file {name} missing or corrupted after multipath delivery"
            );
        }
    }
}
