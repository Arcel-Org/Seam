use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use seam_protocol::fec::gf;
use seam_protocol::fec::{FecDecoder, FecEncoder};

fn make_sources(k: u8, size: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| (0..size).map(|j| i.wrapping_add(j as u8)).collect())
        .collect()
}

fn bench_gf_mul_slice(c: &mut Criterion) {
    let mut group = c.benchmark_group("gf/mul_add_slice");

    for size in [64usize, 256, 1024, 4096] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("scalar=0x17", size), &size, |b, &sz| {
            let mut dst = vec![0u8; sz];
            let src = vec![0xABu8; sz];
            b.iter(|| gf::mul_add_slice(&mut dst, &src, 0x17));
        });
        group.bench_with_input(BenchmarkId::new("scalar=1 (xor)", size), &size, |b, &sz| {
            let mut dst = vec![0u8; sz];
            let src = vec![0xABu8; sz];
            b.iter(|| gf::mul_add_slice(&mut dst, &src, 1));
        });
    }
    group.finish();
}

fn bench_fec_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec/encode");

    for (k, r, size) in [(4u8, 2u8, 1400usize), (8, 2, 1400), (10, 3, 1400)] {
        let label = format!("k{k}r{r}_{size}B");
        let total_bytes = (k as u64 + r as u64) * size as u64;
        group.throughput(Throughput::Bytes(total_bytes));

        group.bench_with_input(
            BenchmarkId::new("encode", &label),
            &(k, r, size),
            |b, &(k, r, size)| {
                let sources = make_sources(k, size);
                b.iter(|| {
                    let mut enc = FecEncoder::new(0, k, r);
                    for src in &sources {
                        enc.push_source(src);
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_fec_decode_no_loss(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec/decode_no_loss");
    let k = 8u8;
    let r = 2u8;
    let size = 1400usize;
    let sources = make_sources(k, size);
    let total = k as u64 * size as u64;
    group.throughput(Throughput::Bytes(total));

    group.bench_function("k8r2_1400B", |b| {
        let mut enc = FecEncoder::new(0, k, r);
        for src in &sources {
            enc.push_source(src);
        }
        b.iter(|| {
            let mut dec = FecDecoder::new();
            for (i, src) in sources.iter().enumerate() {
                dec.add_source(0, i as u8, k, r, src);
            }
        });
    });
    group.finish();
}

fn bench_fec_recover_1_loss(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec/recover_1_loss");

    for (k, r, size) in [(4u8, 1u8, 1400usize), (8, 2, 1400), (10, 2, 1400)] {
        let label = format!("k{k}r{r}_{size}B");
        group.throughput(Throughput::Bytes(k as u64 * size as u64));

        group.bench_with_input(
            BenchmarkId::new("recover", &label),
            &(k, r, size),
            |b, &(k, r, size)| {
                let sources = make_sources(k, size);
                let mut enc = FecEncoder::new(0, k, r);
                for src in &sources {
                    enc.push_source(src);
                }
                let mut enc2 = FecEncoder::new(0, k, r);
                let repairs = {
                    let mut rs = None;
                    for src in &sources {
                        rs = enc2.push_source(src);
                    }
                    rs.unwrap()
                };

                b.iter(|| {
                    let mut dec = FecDecoder::new();
                    // Add all sources except index 0
                    for i in 1..k as usize {
                        dec.add_source(0, i as u8, k, r, &sources[i]);
                    }
                    // Recover using first repair
                    dec.add_repair(&repairs[0])
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_gf_mul_slice,
    bench_fec_encode,
    bench_fec_decode_no_loss,
    bench_fec_recover_1_loss
);
criterion_main!(benches);
