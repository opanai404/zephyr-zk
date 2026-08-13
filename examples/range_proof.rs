// ─────────────────────────────────────────────────────────────
// ZEPHYR · example: range + square proof under both backends
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! A complete workflow: author a circuit, solve a witness, prove it
//! under the STARK backend, and verify.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --example range_proof
//! ```

use zephyr_zk::backends::prove_and_verify;
use zephyr_zk::backends::stark::StarkBackend;
use zephyr_zk::circuit::Circuit;
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::range::{range16, RangeChecked};

fn main() {
    // The circuit: "I know a 16-bit secret x whose square is public."
    let (circuit, witness, x_handle) = build_square16(1234);
    println!("circuit: {}", circuit.name());
    println!("  variables:      {}", circuit.num_variables());
    println!("  constraints:    {}", circuit.constraints().len());
    println!("  public inputs:  {}", circuit.num_public_inputs());

    let backend = StarkBackend::new();
    let proof = backend.prove(&circuit, &witness).expect("prove");
    println!("  proof bytes:    {}", proof.bytes.len());
    println!("  public value y: {}", witness[x_handle] * witness[x_handle]);

    let (public, _) = circuit.split_witness(&witness).unwrap();
    let ok = backend.verify(&circuit, &public, &proof).expect("verify");
    assert!(ok, "verifier rejected a valid proof");
    println!("  verified:       ✓");

    // The one-shot helper does prove + verify in a single call.
    let quick = prove_and_verify(&backend, &backend, &circuit, &witness).unwrap();
    assert!(quick);
    println!("  prove+verify:   ✓");
}

/// `y = x²` with `0 <= x < 2^16`, `y` public.
fn build_square16(x_value: u64) -> (Circuit<Fp>, Vec<Fp>, usize) {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness_named("secret.x");
    let rc: RangeChecked<Fp> = range16(&mut b, x);
    let y = b.mul(x, x, "secret.x²");
    b.assert_public(y);
    let circuit = b.build("square16");

    let mut partial = vec![(x, Fp::from(x_value))];
    for (i, &bit) in rc.bits.iter().enumerate() {
        partial.push((bit, Fp::from(((x_value >> i) & 1) as u64)));
    }
    let witness = circuit.solve_witness(&partial).expect("x < 2^16");
    (circuit, witness, x)
}
