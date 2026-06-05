use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use seam_protocol::fec::codec::FecEncoder;
use seam_protocol::packet::{HEADER_LEN, TAG_LEN};
use seam_protocol::{CipherSuite, PacketDecoder, PacketEncoder, PacketKeys, PktType};

const SECRET: &[u8] = b"bench-secret-key-32-bytes-padded";
const SECRET_AES: &[u8] = b"bench-aes-key-32-bytes-padded-xx";

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");

    for size in [64usize, 256, 512, 1400] {
        let payload = vec![0x5Au8; size];
        let wire_size = (HEADER_LEN + size + TAG_LEN) as u64;
        group.throughput(Throughput::Bytes(wire_size));

        group.bench_with_input(BenchmarkId::new("ChaCha20Poly1305", size), &size, |b, _| {
            let enc = PacketEncoder::new(PacketKeys::derive_from_secret(SECRET), 1);
            let mut out = vec![0u8; HEADER_LEN + size + TAG_LEN];
            b.iter(|| {
                enc.encode(PktType::Data, &payload, &mut out).unwrap();
            });
        });
    }
    group.finish();
}

fn bench_encrypt_1400(c: &mut Criterion) {
    let payload = vec![0x5Au8; 1400];
    let wire_size = (HEADER_LEN + 1400 + TAG_LEN) as u64;
    let enc = PacketEncoder::new(PacketKeys::derive_from_secret(SECRET), 1);
    let mut out = vec![0u8; HEADER_LEN + 1400 + TAG_LEN];

    let mut group = c.benchmark_group("encrypt_1400");
    group.throughput(Throughput::Bytes(wire_size));
    group.bench_function("ChaCha20Poly1305", |b| {
        b.iter(|| enc.encode(PktType::Data, &payload, &mut out).unwrap());
    });
    group.finish();
}

fn bench_encrypt_1400_aes(c: &mut Criterion) {
    let payload = vec![0x5Au8; 1400];
    let wire_size = (HEADER_LEN + 1400 + TAG_LEN) as u64;
    let keys = PacketKeys::derive_from_secret_with_cipher(SECRET_AES, CipherSuite::Aes256Gcm);
    let enc = PacketEncoder::new(keys, 1);
    let mut out = vec![0u8; HEADER_LEN + 1400 + TAG_LEN];

    let mut group = c.benchmark_group("encrypt_1400_aes");
    group.throughput(Throughput::Bytes(wire_size));
    group.bench_function("AES-256-GCM", |b| {
        b.iter(|| enc.encode(PktType::Data, &payload, &mut out).unwrap());
    });
    group.finish();
}

fn bench_decrypt_1400(c: &mut Criterion) {
    let payload = vec![0x5Au8; 1400];
    let wire_size = (HEADER_LEN + 1400 + TAG_LEN) as u64;
    let enc = PacketEncoder::new(PacketKeys::derive_from_secret(SECRET), 1);

    let mut group = c.benchmark_group("decrypt_1400");
    group.throughput(Throughput::Bytes(wire_size));
    group.bench_function("ChaCha20Poly1305", |b| {
        b.iter_batched(
            || {
                let mut pkt = vec![0u8; HEADER_LEN + 1400 + TAG_LEN];
                enc.encode(PktType::Data, &payload, &mut pkt).unwrap();
                pkt
            },
            |mut pkt| {
                let mut dec = PacketDecoder::new(PacketKeys::derive_from_secret(SECRET));
                let _ = dec.decode(&mut pkt).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_fec_encode_k8r2(c: &mut Criterion) {
    let payload = vec![0xBBu8; 1400];
    let mut group = c.benchmark_group("fec_encode_k8r2");
    group.throughput(Throughput::Bytes(1400 * 8));
    group.bench_function("k=8_r=2_1400B", |b| {
        b.iter(|| {
            let mut enc = FecEncoder::new(0, 8, 2);
            let mut repairs = None;
            for _ in 0..8u8 {
                repairs = enc.push_source(&payload);
            }
            std::hint::black_box(repairs)
        });
    });
    group.finish();
}

fn bench_fec_decode_k8r2(c: &mut Criterion) {
    use seam_protocol::fec::codec::{FecDecoder, FecRepairData};
    let payload = vec![0xBBu8; 1400];
    let mut group = c.benchmark_group("fec_decode_k8r2");
    group.throughput(Throughput::Bytes(1400 * 8));
    group.bench_function("k=8_r=2_1400B_recover1", |b| {
        b.iter_batched(
            || {
                let mut enc = FecEncoder::new(42, 8, 2);
                let mut sources: Vec<(u8, Vec<u8>)> = Vec::new();
                let mut repairs_out: Vec<FecRepairData> = Vec::new();
                for i in 0..8u8 {
                    let mut p = payload.clone();
                    p[0] = i;
                    if let Some(repairs) = enc.push_source(&p) {
                        repairs_out = repairs;
                    } else {
                        sources.push((i, p));
                    }
                }
                (sources, repairs_out)
            },
            |(sources, repairs)| {
                let mut dec = FecDecoder::new();
                // Feed 7 sources (drop index 0) + all repairs → trigger recovery
                for (i, data) in &sources {
                    if *i == 0 {
                        continue;
                    }
                    dec.add_source(42, *i, 8, 2, data);
                }
                for r in &repairs {
                    dec.add_repair(r);
                }
                std::hint::black_box(dec)
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");

    for size in [64usize, 256, 512, 1400] {
        let payload = vec![0x5Au8; size];
        let wire_size = (HEADER_LEN + size + TAG_LEN) as u64;
        group.throughput(Throughput::Bytes(wire_size));

        group.bench_with_input(BenchmarkId::new("ChaCha20Poly1305", size), &size, |b, _| {
            let enc = PacketEncoder::new(PacketKeys::derive_from_secret(SECRET), 1);
            b.iter_batched(
                || {
                    let mut pkt = vec![0u8; HEADER_LEN + size + TAG_LEN];
                    enc.encode(PktType::Data, &payload, &mut pkt).unwrap();
                    pkt
                },
                |mut pkt| {
                    let mut dec = PacketDecoder::new(PacketKeys::derive_from_secret(SECRET));
                    let _ = dec.decode(&mut pkt).unwrap();
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");
    let payload = vec![0xFFu8; 1400];
    group.throughput(Throughput::Bytes((HEADER_LEN + 1400 + TAG_LEN) as u64));

    group.bench_function("encode_decode_1400b", |b| {
        let enc = PacketEncoder::new(PacketKeys::derive_from_secret(SECRET), 1);
        b.iter_batched(
            || {
                let mut pkt = vec![0u8; HEADER_LEN + 1400 + TAG_LEN];
                enc.encode(PktType::Data, &payload, &mut pkt).unwrap();
                pkt
            },
            |mut pkt| {
                let mut dec = PacketDecoder::new(PacketKeys::derive_from_secret(SECRET));
                let _ = dec.decode(&mut pkt).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_key_derivation(c: &mut Criterion) {
    c.bench_function("PacketKeys::derive_from_secret", |b| {
        b.iter(|| PacketKeys::derive_from_secret(SECRET));
    });
}

criterion_group!(
    benches,
    bench_encode,
    bench_encrypt_1400,
    bench_encrypt_1400_aes,
    bench_decrypt_1400,
    bench_fec_encode_k8r2,
    bench_fec_decode_k8r2,
    bench_decode,
    bench_roundtrip,
    bench_key_derivation,
);
criterion_main!(benches);
