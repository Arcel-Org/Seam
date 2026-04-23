use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use apex_protocol::{PacketDecoder, PacketEncoder, PacketKeys};
use apex_protocol::session::{Session, stream::{PRIORITY_DEFAULT, PRIORITY_HIGH, PRIORITY_LOW}};
use apex_protocol::transport::bbr::Bbr;
use apex_protocol::transport::cc::{CongestionControl, Cubic};
use apex_protocol::transport::pacer::Pacer;
use apex_protocol::transport::pool::BufferPool;
use apex_protocol::session::rack::RackTracker;

const SECRET: &[u8] = b"session-bench-key-32-bytes-exact";
const SESSION_ID: u64 = 0xDEADBEEF_CAFEBABE;

fn make_session() -> Session {
    let enc = PacketEncoder::new(PacketKeys::derive_from_secret(SECRET), SESSION_ID);
    let dec = PacketDecoder::new(PacketKeys::derive_from_secret(SECRET));
    Session::new(SESSION_ID, enc, dec)
}

fn bench_stream_flush(c: &mut Criterion) {
    let mut group = c.benchmark_group("session/flush");

    for size in [256usize, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("1_stream", size), &size, |b, &sz| {
            b.iter(|| {
                let mut sess = make_session();
                let sid = sess.open_stream();
                sess.send(sid, &vec![0xABu8; sz]).unwrap();
                sess.flush().unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("4_streams_equal_priority", size), &size, |b, &sz| {
            b.iter(|| {
                let mut sess = make_session();
                for _ in 0..4 {
                    let sid = sess.open_stream();
                    sess.send(sid, &vec![0xABu8; sz / 4]).unwrap();
                }
                sess.flush().unwrap()
            });
        });

        group.bench_with_input(BenchmarkId::new("4_streams_mixed_priority", size), &size, |b, &sz| {
            b.iter(|| {
                let mut sess = make_session();
                // One high-priority stream + three low-priority
                let high = sess.open_stream_with_priority(PRIORITY_HIGH);
                sess.send(high, &vec![0xABu8; sz / 4]).unwrap();
                for _ in 0..3 {
                    let sid = sess.open_stream_with_priority(PRIORITY_LOW);
                    sess.send(sid, &vec![0xABu8; sz / 4]).unwrap();
                }
                sess.flush().unwrap()
            });
        });
    }
    group.finish();
}

fn bench_stream_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("session/receive_and_read");

    for size in [1024usize, 8192] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("roundtrip", size), &size, |b, &sz| {
            b.iter(|| {
                // Sender side
                let mut sender = make_session();
                let sid = sender.open_stream();
                sender.send(sid, &vec![0xABu8; sz]).unwrap();
                let packets = sender.flush().unwrap();

                // Receiver side
                let mut receiver = make_session();
                for mut pkt in packets {
                    let _ = receiver.receive_packet(&mut pkt);
                }
                let mut out = Vec::with_capacity(sz);
                receiver.read(1, &mut out, sz).ok()
            });
        });
    }
    group.finish();
}

fn bench_congestion_controllers(c: &mut Criterion) {
    let mut group = c.benchmark_group("cc/decision");

    group.bench_function("Cubic::on_ack", |b| {
        let mut cc = Cubic::new();
        b.iter(|| {
            cc.on_send(1400);
            cc.on_ack(1400, std::time::Duration::from_millis(10));
        });
    });

    group.bench_function("Cubic::on_loss", |b| {
        let mut cc = Cubic::new();
        b.iter(|| cc.on_loss());
    });

    group.bench_function("BBR::on_ack", |b| {
        let mut cc = Bbr::new();
        b.iter(|| {
            cc.on_send(1400);
            cc.on_ack(1400, std::time::Duration::from_millis(10));
        });
    });

    group.bench_function("BBR::on_loss", |b| {
        let mut cc = Bbr::new();
        b.iter(|| cc.on_loss());
    });

    group.finish();
}

fn bench_rack(c: &mut Criterion) {
    let mut group = c.benchmark_group("rack");

    group.bench_function("on_sent_on_ack_pair", |b| {
        let mut r = RackTracker::new();
        let mut pn = 0u64;
        b.iter(|| {
            r.on_sent(pn, bytes::Bytes::from_static(b"x"), 1400);
            let _ = r.on_ack(pn);
            pn += 1;
        });
    });

    group.finish();
}

fn bench_buffer_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool");

    group.bench_function("acquire_release_1500B", |b| {
        let pool = BufferPool::new(1500, 64);
        b.iter(|| {
            let buf = pool.acquire();
            pool.release(buf);
        });
    });

    group.bench_function("raw_Vec_allocate_1500B", |b| {
        b.iter(|| {
            let v: Vec<u8> = Vec::with_capacity(1500);
            std::hint::black_box(v);
        });
    });

    group.finish();
}

fn bench_datagram_queue(c: &mut Criterion) {
    use apex_protocol::session::datagram::DatagramQueue;
    use bytes::Bytes;
    let mut group = c.benchmark_group("datagram_queue");

    group.bench_function("send_poll_1200B", |b| {
        let mut q = DatagramQueue::new();
        let payload = Bytes::from(vec![0xAAu8; 1200]);
        b.iter(|| {
            q.send(payload.clone()).unwrap();
            q.poll_send()
        });
    });

    group.finish();
}

fn bench_pacer(c: &mut Criterion) {
    let mut group = c.benchmark_group("pacer");

    group.bench_function("available_+_consume", |b| {
        let mut p = Pacer::new();
        p.update_rate(10_000_000, std::time::Duration::from_millis(10));
        b.iter(|| {
            let _ = p.available();
            p.consume(1400);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_stream_flush,
    bench_stream_read,
    bench_congestion_controllers,
    bench_pacer,
    bench_rack,
    bench_buffer_pool,
    bench_datagram_queue,
);
criterion_main!(benches);
