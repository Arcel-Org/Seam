use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use seam_protocol::packet::{HEADER_LEN, TAG_LEN};
use seam_protocol::{PacketDecoder, PacketEncoder, PacketKeys, PktType};

const SECRET: &[u8] = b"bench-secret-key-32-bytes-padded";

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
    bench_decode,
    bench_roundtrip,
    bench_key_derivation
);
criterion_main!(benches);
