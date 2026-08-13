// ─────────────────────────────────────────────────────────────
// ZEPHYR · criterion: Groth16 backend
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Prove/verify latency for the arkworks Groth16 backend on a tiny
//! two-constraint circuit. These feed the README performance table
//! (micro-benchmarks, not extrapolated throughput claims).
//!
//! This bench requires the `groth16` feature (`cargo bench --features
//! groth16 --bench groth16`); it is skipped by default builds.

use criterion::{criterion_group, criterion_main, Criterion};
use zephyr_zk::backends::groth16::Groth16Backend;
use zephyr_zk::circuit::Circuit;
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;

/// `z = x·y`, all three public — the smallest R1CS that exercises a
/// real multiplication plus the input/output wiring.
fn product_pair() -> (Circuit<Fp>, Vec<Fp>) {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness_named("x");
    let y = b.witness_named("y");
    let z = b.mul(x, y, "x·y");
    b.assert_public(x);
    b.assert_public(y);
    b.assert_public(z);
    let circuit = b.build("bench-g16-product");

    let w = circuit
        .solve_witness(&[(x, Fp::from(3u64)), (y, Fp::from(11u64))])
        .unwrap();
    (circuit, w)
}

fn bench_prove(c: &mut Criterion) {
    let (circuit, w) = product_pair();
    let backend = Groth16Backend::setup(&circuit, b"zephyr.bench.g16").unwrap();

    let mut group = c.benchmark_group("groth16");
    group.bench_function("prove-2constraints", |b| {
        b.iter(|| backend.prove(&circuit, &w).unwrap())
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let (circuit, w) = product_pair();
    let backend = Groth16Backend::setup(&circuit, b"zephyr.bench.g16").unwrap();
    let proof = backend.prove(&circuit, &w).unwrap();
    let (public, _) = circuit.split_witness(&w).unwrap();

    let mut group = c.benchmark_group("groth16");
    group.bench_function("verify-2constraints", |b| {
        b.iter(|| backend.verify(&circuit, &public, &proof).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);
