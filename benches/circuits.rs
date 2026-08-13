// ─────────────────────────────────────────────────────────────
// ZEPHYR · criterion: circuit construction
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Micro-benchmarks for the DSL and gadget layers.
//!
//! Run with `cargo bench --bench circuits`. The numbers reported in
//! the README's performance table are produced by these groups.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::merkle::assert_path;
use zephyr_zk::gadgets::range::range_check;

fn bench_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("range");
    for bits in [8usize, 16, 32, 64] {
        group.bench_function(format!("{bits}-bits"), |b| {
            b.iter_batched(
                || {
                    let mut builder = CircuitBuilder::<Fp>::new();
                    let x = builder.witness();
                    range_check(&mut builder, x, bits as u32);
                    let circuit = builder.build("bench-range");
                    (circuit, x)
                },
                |(circuit, x)| {
                    let w = circuit.solve_witness(&[(x, Fp::from(12345u64))]).unwrap();
                    assert!(circuit.check_witness(&w).unwrap());
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_merkle(b: &mut Criterion) {
    let mut group = b.benchmark_group("merkle");
    for height in [8usize, 16, 24] {
        group.bench_function(format!("height-{height}"), |bench| {
            bench.iter_batched(
                || {
                    let mut builder = CircuitBuilder::<Fp>::new();
                    let leaf = builder.witness();
                    let root = builder.witness();
                    let siblings: Vec<usize> = (0..height).map(|_| builder.witness()).collect();
                    let bits: Vec<usize> = (0..height).map(|_| builder.witness()).collect();
                    assert_path(&mut builder, root, leaf, &siblings, &bits);
                    builder.build("bench-merkle")
                },
                |circuit| {
                    assert!(circuit.num_constraints() > 0);
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_witness_solve(c: &mut Criterion) {
    c.bench_function("solve-constant-chain-1k", |b| {
        b.iter_batched(
            || {
                let mut builder = CircuitBuilder::<Fp>::new();
                let mut acc = builder.constant(Fp::from(0u64));
                for i in 0..1024 {
                    acc = builder.add_scaled(acc, builder.constant(Fp::from(i as u64)), Fp::from(1u64), "chain");
                }
                builder.build("bench-chain")
            },
            |circuit| {
                let w = circuit.solve_witness(&[]).unwrap();
                assert!(circuit.check_witness(&w).unwrap());
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_range, bench_merkle, bench_witness_solve);
criterion_main!(benches);
