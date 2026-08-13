// ─────────────────────────────────────────────────────────────
// ZEPHYR · integration: STARK backend
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Prove and verify small circuits under the transparent STARK.

use zephyr_zk::backends::stark::StarkBackend;
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::range::range_check;

fn range_circuit(value: u64) -> (zephyr_zk::circuit::Circuit<Fp>, Vec<Fp>) {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness();
    let rc = range_check(&mut b, x, 8);
    let y = b.mul(x, b.constant(Fp::from(7u64)), "x·7");
    b.assert_public(y);
    let circuit = b.build("stark-mul7");

    let mut partial = vec![(rc.value, Fp::from(value))];
    for (i, &bit) in rc.bits.iter().enumerate() {
        partial.push((bit, Fp::from(((value >> i) & 1) as u64)));
    }
    (circuit, circuit.solve_witness(&partial).unwrap())
}

#[test]
fn prove_verify_round_trip() {
    let (circuit, w) = range_circuit(6);
    let backend = StarkBackend::new();
    let proof = backend.prove(&circuit, &w).unwrap();
    let (public, _) = circuit.split_witness(&w).unwrap();
    assert_eq!(public, vec![Fp::from(42u64)]);
    assert!(backend.verify(&circuit, &public, &proof).unwrap());
}

#[test]
fn tampered_public_input_rejected() {
    let (circuit, w) = range_circuit(6);
    let backend = StarkBackend::new();
    let proof = backend.prove(&circuit, &w).unwrap();
    let bad = vec![Fp::from(43u64)];
    assert!(!backend.verify(&circuit, &bad, &proof).unwrap());
}

#[test]
fn invalid_witness_rejected_at_prove_time() {
    let (circuit, mut w) = range_circuit(6);
    w[1] = Fp::from(300u64); // violates the range check
    let backend = StarkBackend::new();
    assert!(backend.prove(&circuit, &w).is_err());
}

#[test]
fn prove_and_verify_helper() {
    use zephyr_zk::backends::prove_and_verify;
    let (circuit, w) = range_circuit(9);
    let backend = StarkBackend::new();
    assert!(prove_and_verify(&backend, &backend, &circuit, &w).unwrap());
}
