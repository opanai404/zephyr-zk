// ─────────────────────────────────────────────────────────────
// ZEPHYR · integration: Poseidon hash gadget
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! The hash gadget must agree with the native reference permutation.

use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::poseidon::{hash_pair, native_permute};

use ark_ff::Zero;

fn hash_native(a: Fp, b: Fp) -> Fp {
    native_permute([a, b, Fp::ZERO])[0]
}

#[test]
fn hash_pair_matches_native() {
    let mut b = CircuitBuilder::<Fp>::new();
    let a = b.witness_named("a");
    let bv = b.witness_named("b");
    let out = hash_pair(&mut b, a, bv);
    b.assert_public(out);
    let circuit = b.build("poseidon2");

    let (a_val, b_val) = (Fp::from(12345u64), Fp::from(67890u64));
    let expected = hash_native(a_val, b_val);

    let w = circuit.solve_witness(&[(a, a_val), (bv, b_val)]).unwrap();
    assert!(circuit.check_witness(&w).unwrap());
    assert_eq!(w[out], expected);
}

#[test]
fn hash_is_sensitive_to_input_order() {
    // H(a, b) != H(b, a) for a != b.
    let (a_val, b_val) = (Fp::from(1u64), Fp::from(2u64));
    assert_ne!(hash_native(a_val, b_val), hash_native(b_val, a_val));
}

#[test]
fn permutation_has_no_fixed_point_on_random_input() {
    let state = [Fp::from(99u64), Fp::from(100u64), Fp::from(101u64)];
    let out = native_permute(state);
    assert_ne!(out, state);
}
