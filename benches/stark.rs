// ─────────────────────────────────────────────────────────────
// ZEPHYR · criterion: STARK backend
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Prove/verify latency for the transparent STARK on small circuits.
//! These feed the README performance table (micro-benchmarks, not
//! extrapolated throughput claims).

use criterion::{criterion_group, criterion_main, Criterion};
use zephyr_zk::backends::stark::StarkBackend;
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::range::range_check;

fn range_pair(value: u64) -> (zephyr_zk::circuit::Circuit<Fp>, Vec<Fp>) {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness();
    let rc = range_check(&mut b, x, 8);
    let circuit = b.build("bench-stark-range8");
    let mut partial = vec![(rc.value, Fp::from(value))];
    for (i, &bit) in rc.bits.iter().enumerate() {
        partial.push((bit, Fp::from(((value >> i) & 1) as u64)));
    }
    (circuit, circuit.solve_witness(&partial).unwrap())
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("stark/prove");
    group.bench_function("range8", |b| {
        b.iter(|| {
            let (circuit, w) = range_pair(42);
            StarkBackend::new().prove(&circuit, &w).unwrap()
        })
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let (circuit, w) = range_pair(42);
    let backend = StarkBackend::new();
    let proof = backend.prove(&circuit, &w).unwrap();
    let (public, _) = circuit.split_witness(&w).unwrap();

    let mut group = c.benchmark_group("stark/verify");
    group.bench_function("range8", |b| {
        b.iter(|| backend.verify(&circuit, &public, &proof).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);
