use criterion::{Criterion, criterion_group, criterion_main};
use fips204::traits::SerDes;
use seam_protocol::crypto::keys::PacketKeys;
use seam_protocol::handshake::{
    CookieFactory, IdentityKeypair, MLDSA_PK_LEN, mldsa_verify,
    state::{ClientHandshake, ServerHandshake},
};

fn bench_keypair_gen(c: &mut Criterion) {
    c.bench_function("IdentityKeypair::generate", |b| {
        b.iter(IdentityKeypair::generate);
    });
}

fn bench_hybrid_keygen(c: &mut Criterion) {
    // Times the combined X25519 + ML-KEM-768 keypair generation (the post-quantum
    // hybrid keygen cost relevant to handshake initiation).
    c.bench_function("hybrid_keygen_X25519+ML-KEM-768", |b| {
        b.iter(IdentityKeypair::generate);
    });
}

fn bench_key_derivation(c: &mut Criterion) {
    let secret = [0x42u8; 32];
    c.bench_function("PacketKeys::derive_from_secret", |b| {
        b.iter(|| PacketKeys::derive_from_secret(&secret));
    });
}

fn bench_cookie(c: &mut Criterion) {
    let factory = CookieFactory::new([0xABu8; 32]);
    let addr = b"127.0.0.1:54321";

    c.bench_function("CookieFactory::generate", |b| {
        b.iter(|| factory.generate(addr));
    });

    let cookie = factory.generate(addr);
    c.bench_function("CookieFactory::verify", |b| {
        b.iter(|| factory.verify(addr, &cookie));
    });
}

fn bench_full_handshake(c: &mut Criterion) {
    c.bench_function("full_handshake_XX_ML-KEM768", |b| {
        b.iter(|| {
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
            let _client_result = client
                .write_msg3_and_finish(&server_kem_pk, agreed2, &mut msg3)
                .unwrap();
            let _server_result = server
                .read_msg3_and_finish(&server_id.kem_sk, agreed, &msg3)
                .unwrap();
        });
    });
}

fn bench_noise_xx_handshake(c: &mut Criterion) {
    c.bench_function("noise_xx_handshake_roundtrip", |b| {
        b.iter(|| {
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
        });
    });
}

fn bench_identity_sign(c: &mut Criterion) {
    let id = IdentityKeypair::generate();
    let message = [0x42u8; 64];
    c.bench_function("ML-DSA-65_sign", |b| {
        b.iter(|| id.mldsa_sign(&message).unwrap());
    });
}

fn bench_identity_verify(c: &mut Criterion) {
    let id = IdentityKeypair::generate();
    let message = [0x42u8; 64];
    let sig = id.mldsa_sign(&message).unwrap();
    let pk_bytes: [u8; MLDSA_PK_LEN] = id.mldsa_pk.clone().into_bytes();
    c.bench_function("ML-DSA-65_verify", |b| {
        b.iter(|| mldsa_verify(&pk_bytes, &message, &sig));
    });
}

fn bench_mldsa_fingerprint(c: &mut Criterion) {
    let id = IdentityKeypair::generate();
    c.bench_function("ML-DSA-65_fingerprint_sha256", |b| {
        b.iter(|| id.mldsa_fingerprint());
    });
}

criterion_group!(
    benches,
    bench_keypair_gen,
    bench_hybrid_keygen,
    bench_key_derivation,
    bench_cookie,
    bench_full_handshake,
    bench_noise_xx_handshake,
    bench_identity_sign,
    bench_identity_verify,
    bench_mldsa_fingerprint,
);
criterion_main!(benches);
