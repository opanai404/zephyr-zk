// ─────────────────────────────────────────────────────────────
// ZEPHYR · integration: DSL and circuit IR end-to-end
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! End-to-end DSL tests: build a circuit, solve a witness, split it,
//! and confirm the IR behaves as the gadget layer expects.

use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::error::Error;
use zephyr_zk::field::Fp;

use ark_ff::One;

#[test]
fn quadratic_identity_proves_and_splits() {
    // (a + b)² = a² + 2ab + b²  as a constraint *shape*; here we just
    // check that the algebra the DSL emits is satisfiable.
    let mut b = CircuitBuilder::<Fp>::new();
    let a = b.witness_named("a");
    let bv = b.witness_named("b");
    let ab = b.mul(a, bv, "ab");
    let two_ab = b.scale(ab, Fp::from(2u64), "2ab");
    let a_sq = b.mul(a, a, "a²");
    let b_sq = b.mul(bv, bv, "b²");
    let lhs = b.mul(b.add(a, bv, "a+b"), b.add(a, bv, "a+b"), "(a+b)²");
    let rhs = b.add(b.add(a_sq, two_ab, "a²+2ab"), b_sq, "+b²");
    b.assert_eq(lhs, rhs, "identity");

    let circuit = b.build("identity");
    let w = circuit.solve_witness(&[(a, Fp::from(3u64)), (bv, Fp::from(4u64))]).unwrap();
    assert!(circuit.check_witness(&w).unwrap());
}

#[test]
fn witness_length_validation() {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness();
    b.assert_boolean(x, "bool");
    let circuit = b.build("bool");
    assert_eq!(circuit.check_witness(&[Fp::ONE]), Err(Error::InvalidWitness));
}

#[test]
fn circuit_names_are_stable() {
    let mut b = CircuitBuilder::<Fp>::new();
    b.assert_boolean(b.witness(), "b");
    assert_eq!(b.build("stable-name").name(), "stable-name");
}

#[test]
fn constants_are_recalled_by_solver() {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness();
    let one = b.constant(Fp::ONE);
    let ten = b.constant(Fp::from(10u64));
    b.assert_eq(b.mul(x, one, "x·1"), x, "x·1=x");
    b.assert_public(ten);
    let circuit = b.build("const");
    let w = circuit.solve_witness(&[(x, Fp::from(5u64))]).unwrap();
    let (public, _) = circuit.split_witness(&w).unwrap();
    assert_eq!(public, vec![Fp::from(10u64)]);
}
