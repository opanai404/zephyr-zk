// ─────────────────────────────────────────────────────────────
// ZEPHYR · integration: elliptic-curve gadget
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Point arithmetic and scalar multiplication constraints.

use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::ec::{add, assert_on_curve, default_curve, double, scalar_mul, Point};

use ark_ff::Field;

/// The (1, 2) base point on y² = x³ + 3.
fn base(b: &mut CircuitBuilder<Fp>) -> Point {
    Point {
        x: b.constant(Fp::from(1u64)),
        y: b.constant(Fp::from(2u64)),
    }
}

#[test]
fn doubling_satisfies_curve_equation() {
    let mut b = CircuitBuilder::<Fp>::new();
    let p = base(&mut b);
    assert_on_curve(&mut b, default_curve(), p, "base");
    let two_p = double(&mut b, default_curve(), p, "2p").unwrap();
    assert_on_curve(&mut b, default_curve(), two_p, "2p");

    let circuit = b.build("ec-double");
    let w = circuit.solve_witness(&[]).unwrap();
    assert!(circuit.check_witness(&w).unwrap());
}

#[test]
fn addition_associativity_shape() {
    // (P + P) + P == P + (P + P): both sides must be buildable and
    // satisfiable with the same witness solver.
    let mut b = CircuitBuilder::<Fp>::new();
    let p = base(&mut b);

    let two_p = double(&mut b, default_curve(), p, "2p").unwrap();
    let left = add(&mut b, default_curve(), two_p, p, "2p+p").unwrap();

    let two_p_again = double(&mut b, default_curve(), p, "2p").unwrap();
    let right = add(&mut b, default_curve(), p, two_p_again, "p+2p").unwrap();

    b.assert_eq(left.x, right.x, "assoc.x");
    b.assert_eq(left.y, right.y, "assoc.y");

    let circuit = b.build("ec-assoc");
    let w = circuit.solve_witness(&[]).unwrap();
    assert!(circuit.check_witness(&w).unwrap());
}

#[test]
fn scalar_mul_builds_with_public_output() {
    let mut b = CircuitBuilder::<Fp>::new();
    let k = b.witness_named("k");
    let p = base(&mut b);
    let q = scalar_mul(&mut b, default_curve(), k, p, 8, "k·P").unwrap();
    b.assert_public(q.x);

    let circuit = b.build("ec-mul8");
    assert_eq!(circuit.max_degree(), 2);
    assert!(circuit.num_variables() > 8);
}

#[test]
fn inverted_field_is_checked() {
    let mut b = CircuitBuilder::<Fp>::new();
    let z = b.constant(Fp::from(5u64));
    let zi = zephyr_zk::gadgets::ec::invert(&mut b, z, "z");
    let circuit = b.build("inverse");
    let w = circuit.solve_witness(&[(zi, Fp::from(5u64).inverse().unwrap())]).unwrap();
    assert!(circuit.check_witness(&w).unwrap());
    // A bogus inverse must be rejected.
    assert!(circuit.solve_witness(&[(zi, Fp::from(7u64))]).is_none());
}
