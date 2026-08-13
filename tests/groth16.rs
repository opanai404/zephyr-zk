// ─────────────────────────────────────────────────────────────
// ZEPHYR · integration: Groth16 backend
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Pairing-based proofs via the arkworks Groth16 backend.

#![cfg(feature = "groth16")]

use zephyr_zk::backends::groth16::{Groth16Backend, Groth16Verifier};
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;

/// `z = x·y` with all three public.
fn product_circuit() -> (zephyr_zk::circuit::Circuit<Fp>, Vec<Fp>) {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness_named("x");
    let y = b.witness_named("y");
    let z = b.mul(x, y, "x·y");
    b.assert_public(x);
    b.assert_public(y);
    b.assert_public(z);
    let circuit = b.build("product");

    let w = circuit
        .solve_witness(&[(x, Fp::from(3u64)), (y, Fp::from(11u64))])
        .unwrap();
    (circuit, w)
}

#[test]
fn setup_prove_verify_round_trip() {
    let (circuit, w) = product_circuit();
    let backend = Groth16Backend::setup(&circuit, b"zephyr.integration.g16").unwrap();
    let proof = backend.prove(&circuit, &w).unwrap();
    let (public, _) = circuit.split_witness(&w).unwrap();
    assert_eq!(public, vec![Fp::from(3u64), Fp::from(11u64), Fp::from(33u64)]);
    assert!(backend.verify(&circuit, &public, &proof).unwrap());
}

#[test]
fn verifier_only_handle_accepts_same_proof() {
    let (circuit, w) = product_circuit();
    let backend = Groth16Backend::setup(&circuit, b"zephyr.integration.g16").unwrap();
    let proof = backend.prove(&circuit, &w).unwrap();
    let (public, _) = circuit.split_witness(&w).unwrap();

    let vk_bytes = backend.vk_bytes().unwrap();
    let verifier = Groth16Verifier::from_vk_bytes(&vk_bytes, circuit.name()).unwrap();
    assert!(verifier.verify(&circuit, &public, &proof).unwrap());
}

#[test]
fn corrupted_proof_bytes_fail() {
    let (circuit, w) = product_circuit();
    let backend = Groth16Backend::setup(&circuit, b"zephyr.integration.g16").unwrap();
    let mut proof = backend.prove(&circuit, &w).unwrap();
    // Flip a byte in the Groth16 payload.
    let last = proof.bytes.len() - 1;
    proof.bytes[last] ^= 0xFF;
    let (public, _) = circuit.split_witness(&w).unwrap();
    assert!(matches!(
        backend.verify(&circuit, &public, &proof),
        Err(zephyr_zk::error::Error::InvalidProof(_))
    ));
}
