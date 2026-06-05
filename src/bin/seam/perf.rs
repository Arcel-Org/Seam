use anyhow::Result;
use clap::Args;
use fips204::traits::SerDes;

#[derive(Args)]
pub struct PerfArgs {}

pub fn run(_args: PerfArgs) -> Result<()> {
    run_bench()
}

pub fn run_bench() -> Result<()> {
    const ITERS: usize = 1000;

    eprintln!();
    eprintln!("  Seam Performance Benchmark");
    eprintln!("  {}", "─".repeat(51));

    let handshake_ns = bench_handshake(ITERS);
    let sign_ns = bench_mldsa_sign(ITERS);
    let verify_ns = bench_mldsa_verify(ITERS);
    let chacha_ns = bench_chacha_1400(ITERS);
    let aes_ns = bench_aes_1400(ITERS);
    let ratchet_ns = bench_ratchet_chain(ITERS);
    let fec_ns = bench_fec_encode(ITERS);

    let chacha_gbps = throughput_gbps(1400, chacha_ns);
    let aes_gbps = throughput_gbps(1400, aes_ns);

    eprintln!(
        "  {:<38} {}",
        "Handshake (Noise_XX + ML-KEM-768):",
        fmt_duration(handshake_ns)
    );
    eprintln!("  {:<38} {}", "ML-DSA-65 sign:", fmt_duration(sign_ns));
    eprintln!("  {:<38} {}", "ML-DSA-65 verify:", fmt_duration(verify_ns));
    eprintln!(
        "  {:<38} {}  →  {:.1} Gbps effective",
        "ChaCha20-Poly1305 (1400B):",
        fmt_duration(chacha_ns),
        chacha_gbps
    );
    eprintln!(
        "  {:<38} {}  →  {:.1} Gbps effective",
        "AES-256-GCM (1400B):",
        fmt_duration(aes_ns),
        aes_gbps
    );
    eprintln!(
        "  {:<38} {}",
        "Ratchet step (chain KDF):",
        fmt_duration(ratchet_ns)
    );
    eprintln!(
        "  {:<38} {}",
        "FEC encode k=8 r=2 (1400B×8):",
        fmt_duration(fec_ns)
    );
    eprintln!("  {}", "─".repeat(51));
    eprintln!("  All timings: median of {ITERS} iterations");
    eprintln!();

    Ok(())
}

fn throughput_gbps(payload_bytes: usize, median_ns: u64) -> f64 {
    if median_ns == 0 {
        return 0.0;
    }
    (payload_bytes as f64 * 8.0) / (median_ns as f64)
}

fn fmt_duration(ns: u64) -> String {
    if ns < 1_000 {
        format!("{ns} ns")
    } else if ns < 1_000_000 {
        let us = ns as f64 / 1_000.0;
        format!("{us:.1} µs")
    } else {
        let ms = ns as f64 / 1_000_000.0;
        format!("{ms:.1} ms")
    }
}

fn median_ns(mut samples: Vec<u64>) -> u64 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn bench_handshake(iters: usize) -> u64 {
    use seam_protocol::handshake::{
        IdentityKeypair,
        state::{ClientHandshake, ServerHandshake},
    };

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = std::time::Instant::now();

        let client_id = IdentityKeypair::generate();
        let server_id = IdentityKeypair::generate();
        let server_x25519: [u8; 32] = server_id.x25519_public.to_bytes();

        let mut client = ClientHandshake::new(&client_id, &server_x25519).unwrap();
        let mut server = ServerHandshake::new(&server_id).unwrap();

        let mut msg1 = Vec::new();
        client.write_msg1(&server_id.kem_pk, &mut msg1).unwrap();
        let agreed = server.read_msg1(&msg1).unwrap();

        let mut msg2 = Vec::new();
        server
            .write_msg2(&server_id.kem_pk, agreed, &mut msg2)
            .unwrap();
        let (server_kem_pk, agreed2) = client.read_msg2(&msg2).unwrap();

        let mut msg3 = Vec::new();
        let _cr = client
            .write_msg3_and_finish(&server_kem_pk, agreed2, &mut msg3)
            .unwrap();
        let _sr = server
            .read_msg3_and_finish(&server_id.kem_sk, agreed, &msg3)
            .unwrap();

        samples.push(t.elapsed().as_nanos() as u64);
    }
    median_ns(samples)
}

fn bench_mldsa_sign(iters: usize) -> u64 {
    use seam_protocol::handshake::IdentityKeypair;
    let id = IdentityKeypair::generate();
    let message = [0x42u8; 64];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = std::time::Instant::now();
        let _ = id.mldsa_sign(&message).unwrap();
        samples.push(t.elapsed().as_nanos() as u64);
    }
    median_ns(samples)
}

fn bench_mldsa_verify(iters: usize) -> u64 {
    use seam_protocol::handshake::{IdentityKeypair, MLDSA_PK_LEN, mldsa_verify};
    let id = IdentityKeypair::generate();
    let message = [0x42u8; 64];
    let sig = id.mldsa_sign(&message).unwrap();
    let pk_bytes: [u8; MLDSA_PK_LEN] = id.mldsa_pk.clone().into_bytes();
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = std::time::Instant::now();
        let _ = mldsa_verify(&pk_bytes, &message, &sig);
        samples.push(t.elapsed().as_nanos() as u64);
    }
    median_ns(samples)
}

fn bench_chacha_1400(iters: usize) -> u64 {
    use seam_protocol::packet::{HEADER_LEN, TAG_LEN};
    use seam_protocol::{PacketEncoder, PacketKeys, PktType};
    let secret = b"perf-bench-chacha-key-32-bytes-x";
    let enc = PacketEncoder::new(PacketKeys::derive_from_secret(secret), 1);
    let payload = vec![0x5Au8; 1400];
    let mut out = vec![0u8; HEADER_LEN + 1400 + TAG_LEN];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = std::time::Instant::now();
        enc.encode(PktType::Data, &payload, &mut out).unwrap();
        samples.push(t.elapsed().as_nanos() as u64);
    }
    median_ns(samples)
}

fn bench_aes_1400(iters: usize) -> u64 {
    use seam_protocol::packet::{HEADER_LEN, TAG_LEN};
    use seam_protocol::{CipherSuite, PacketEncoder, PacketKeys, PktType};
    let secret = b"perf-bench-aes256-key-32-bytes-y";
    let keys = PacketKeys::derive_from_secret_with_cipher(secret, CipherSuite::Aes256Gcm);
    let enc = PacketEncoder::new(keys, 1);
    let payload = vec![0x5Au8; 1400];
    let mut out = vec![0u8; HEADER_LEN + 1400 + TAG_LEN];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = std::time::Instant::now();
        enc.encode(PktType::Data, &payload, &mut out).unwrap();
        samples.push(t.elapsed().as_nanos() as u64);
    }
    median_ns(samples)
}

fn bench_ratchet_chain(iters: usize) -> u64 {
    use seam_protocol::crypto::ratchet::ratchet_step;
    let chain_key = [0x42u8; 32];
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = std::time::Instant::now();
        let _ = ratchet_step(&chain_key);
        samples.push(t.elapsed().as_nanos() as u64);
    }
    median_ns(samples)
}

fn bench_fec_encode(iters: usize) -> u64 {
    use seam_protocol::fec::codec::FecEncoder;
    let payload = vec![0xBBu8; 1400];
    let mut samples = Vec::with_capacity(iters);
    for i in 0..iters {
        let t = std::time::Instant::now();
        let mut enc = FecEncoder::new(i as u32, 8, 2);
        for _ in 0..8u8 {
            let _ = enc.push_source(&payload);
        }
        samples.push(t.elapsed().as_nanos() as u64);
    }
    median_ns(samples)
}
