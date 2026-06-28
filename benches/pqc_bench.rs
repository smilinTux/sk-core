//! Criterion micro-benchmarks for the sk-pqc hybrid (X25519 + ML-KEM-768) core.
//!
//! Covers the four hot operations on the SK confidentiality path:
//!   * `keygen`               — `kem::hybrid_keypair()`  (X25519 + ML-KEM-768 keygen)
//!   * `hybrid_encap`         — `kem::hybrid_encap(pk)`  (sender side)
//!   * `hybrid_decap`         — `kem::hybrid_decap(ct, sk)` (receiver side)
//!   * `derive_dm_message_key`— `ratchet::derive_dm_message_key(...)` (per-message HKDF)
//!
//! Hybrid = either-leg security: the shared secret stays safe as long as *one*
//! of X25519 or ML-KEM-768 (FIPS 203) holds. These numbers are wall-clock
//! medians on the .41 build host; see the report for stddev.
//!
//! Run with: `cargo bench --bench pqc_bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sk_pqc::{kem, ratchet};

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| {
        b.iter(|| {
            let kp = kem::hybrid_keypair();
            black_box(kp);
        });
    });
}

fn bench_hybrid_encap(c: &mut Criterion) {
    let kp = kem::hybrid_keypair();
    let pk = kp.public_key.clone();
    c.bench_function("hybrid_encap", |b| {
        b.iter(|| {
            let (ct, ss) = kem::hybrid_encap(black_box(&pk)).expect("encap");
            black_box((ct, ss));
        });
    });
}

fn bench_hybrid_decap(c: &mut Criterion) {
    let kp = kem::hybrid_keypair();
    let sk = kp.private_key.clone();
    let (ct, _ss) = kem::hybrid_encap(&kp.public_key).expect("encap");
    c.bench_function("hybrid_decap", |b| {
        b.iter(|| {
            let ss = kem::hybrid_decap(black_box(&ct), black_box(&sk)).expect("decap");
            black_box(ss);
        });
    });
}

fn bench_derive_dm_message_key(c: &mut Criterion) {
    let epoch_secret = ratchet::new_epoch_secret();
    c.bench_function("derive_dm_message_key", |b| {
        b.iter(|| {
            let k = ratchet::derive_dm_message_key(
                black_box(&epoch_secret),
                black_box(7u64),
                black_box(42u64),
            )
            .expect("derive");
            black_box(k);
        });
    });
}

criterion_group!(
    benches,
    bench_keygen,
    bench_hybrid_encap,
    bench_hybrid_decap,
    bench_derive_dm_message_key
);
criterion_main!(benches);
