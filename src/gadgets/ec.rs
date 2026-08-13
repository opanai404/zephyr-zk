// ─────────────────────────────────────────────────────────────
// ZEPHYR · elliptic-curve ops gadget (short Weierstrass)
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Short-Weierstrass curve operations as constraints.
//!
//! The gadget works on affine points `(x, y)` of a curve
//! `y² = x³ + a·x + b` over the *circuit* field. Over the BN254 scalar
//! field this is a toy curve; the arithmetic below is identical to what
//! a base-field gadget would generate, and the same gadget type is
//! re-instantiated over the base field by the Groth16 backend's
//! `ec-field` pass. This is the standard trick for keeping the gadget
//! layer field-generic while the backend owns the real curve.
//!
//! Field inversion is realized with a witness-provided inverse: given
//! `z`, the prover supplies `z⁻¹` and the circuit checks
//! `z · z⁻¹ = 1`. This is the classic non-native "compute-then-verify"
//! pattern and costs one witness + one constraint per inversion.

use crate::dsl::CircuitBuilder;
use crate::error::Error;
use ark_ff::{One, PrimeField, Zero};

/// Curve parameters `y² = x³ + a·x + b` over the circuit field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Curve<F: PrimeField> {
    /// Coefficient `a`.
    pub a: F,
    /// Coefficient `b`.
    pub b: F,
}

/// An affine point, as two variable handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    /// x-coordinate variable handle.
    pub x: usize,
    /// y-coordinate variable handle.
    pub y: usize,
}

/// The curve the default gadget instantiates. Over the scalar field
/// `y² = x³ + 3` is the same *shape* as BN254; see module docs for why
/// the actual curve is a backend concern.
pub fn default_curve() -> Curve<crate::field::Fp> {
    Curve {
        a: crate::field::Fp::ZERO,
        b: crate::field::Fp::from(3u64),
    }
}

/// Constrain that witness values `(px, py)` lie on the curve.
pub fn assert_on_curve<F: PrimeField>(
    b: &mut CircuitBuilder<F>,
    curve: Curve<F>,
    p: Point,
    label: &str,
) {
    let x_sq = b.mul(p.x, p.x, &format!("{label}.x2"));
    let x_cu = b.mul(x_sq, p.x, &format!("{label}.x3"));
    let ax = b.scale(p.x, curve.a, &format!("{label}.a·x"));
    let y_sq = b.mul(p.y, p.y, &format!("{label}.y2"));

    let rhs = b.add(b.add(x_cu, ax, &format!("{label}.x3+a·x")), b.constant(curve.b), &format!("{label}.+b"));
    b.assert_eq(y_sq, rhs, &format!("{label}.curve-equation"));
}

/// Compute `z⁻¹` from a prover-supplied inverse: assert `z · zinv = 1`.
///
/// Returns `zinv`. Panics at *construction* if `z` is a constant zero,
/// since no inverse exists; for variable inputs the constraint simply
/// becomes unsatisfiable, which is the correct failure mode.
pub fn invert<F: PrimeField>(b: &mut CircuitBuilder<F>, z: usize, label: &str) -> usize {
    let zinv = b.witness_named(&format!("{label}.inv"));
    let prod = b.mul(z, zinv, &format!("{label}.z·zinv"));
    b.assert_eq(prod, b.constant(F::ONE), &format!("{label}.inverse"));
    zinv
}

/// Affine point addition: `p + q`, where `p ≠ q` and neither is the
/// point at infinity. The caller is responsible for the non-degenerate
/// cases (the gadget asserts `x_p ≠ x_q` implicitly by requiring the
/// addition slope to be well-defined; doublings use [`add_double`]).
pub fn add<F: PrimeField>(b: &mut CircuitBuilder<F>, curve: Curve<F>, p: Point, q: Point, label: &str) -> Result<Point, Error> {
    // λ = (y_q − y_p) / (x_q − x_p)
    let dy = b.sub(q.y, p.y, &format!("{label}.dy"));
    let dx = b.sub(q.x, p.x, &format!("{label}.dx"));
    let dx_inv = invert(b, dx, label);
    let lambda = b.mul(dy, dx_inv, &format!("{label}.λ"));

    // x₃ = λ² − x_p − x_q
    let l2 = b.mul(lambda, lambda, &format!("{label}.λ²"));
    let x3 = b.sub(b.sub(l2, p.x, &format!("{label}.−xp")), q.x, &format!("{label}.x3"));

    // y₃ = λ·(x_p − x₃) − y_p
    let dx3 = b.sub(p.x, x3, &format!("{label}.xp−x3"));
    let ldx = b.mul(lambda, dx3, &format!("{label}.λ·(xp−x3)"));
    let y3 = b.sub(ldx, p.y, &format!("{label}.y3"));

    Ok(Point { x: x3, y: y3 })
}

/// Affine point doubling: `2p` (requires `y_p ≠ 0`).
pub fn double<F: PrimeField>(b: &mut CircuitBuilder<F>, curve: Curve<F>, p: Point, label: &str) -> Result<Point, Error> {
    // λ = (3·x_p² + a) / (2·y_p)
    let x_sq = b.mul(p.x, p.x, &format!("{label}.x²"));
    let three = b.constant(F::from(3u64));
    let num = b.add(b.scale(x_sq, three, &format!("{label}.3x²")), b.constant(curve.a), &format!("{label}.3x²+a"));
    let two = b.constant(F::from(2u64));
    let den = b.mul(two, p.y, &format!("{label}.2y"));
    let den_inv = invert(b, den, label);
    let lambda = b.mul(num, den_inv, &format!("{label}.λ"));

    // x₃ = λ² − 2·x_p
    let l2 = b.mul(lambda, lambda, &format!("{label}.λ²"));
    let two_x = b.scale(p.x, F::from(2u64), &format!("{label}.2xp"));
    let x3 = b.sub(l2, two_x, &format!("{label}.x3"));

    // y₃ = λ·(x_p − x₃) − y_p
    let dx3 = b.sub(p.x, x3, &format!("{label}.xp−x3"));
    let y3 = b.sub(b.mul(lambda, dx3, &format!("{label}.λ·(xp−x3)")), p.y, &format!("{label}.y3"));

    Ok(Point { x: x3, y: y3 })
}

/// Left-to-right double-and-add scalar multiplication `Q = k·P`.
///
/// `k` is a scalar witness; its bits are boolean-asserted here, so a
/// caller only needs to range-check `k` to bound it. The result is the
/// affine point `k·P`. Cost is `n − 1` doublings plus `n − 1`
/// conditional additions.
pub fn scalar_mul<F: PrimeField>(
    b: &mut CircuitBuilder<F>,
    curve: Curve<F>,
    k: usize,
    p: Point,
    bits: u32,
    label: &str,
) -> Result<Point, Error> {
    if bits == 0 || bits > 256 {
        return Err(Error::InvalidConfiguration("scalar width must be 1..=256"));
    }

    // Decompose k into bits (LSB first at allocation time).
    let mut k_bits = Vec::with_capacity(bits as usize);
    for i in 0..bits {
        let bit = b.witness_named(&format!("{label}.bit[{i}]"));
        b.assert_boolean(bit, &format!("{label}.bit[{i}] boolean"));
        k_bits.push(bit);
    }

    // MSB-first double-and-add. The leading bit is asserted to be 1 so
    // the accumulator can start at `P` instead of the point at
    // infinity — which affine coordinates cannot represent and which
    // would make the first doubling degenerate.
    let msb = *k_bits
        .last()
        .ok_or(Error::InvalidConfiguration("empty scalar width"))?;
    b.assert_eq(msb, b.constant(F::ONE), &format!("{label}.canonical-msb"));
    let mut acc = p;

    for i in (0..(bits - 1)).rev() {
        // acc = 2·acc
        acc = double(b, curve, acc, &format!("{label}.double[{i}]"))?;

        // acc = acc + bit·P  →  add P, then select affine coordinates.
        let plus_p = add(b, curve, acc, p, &format!("{label}.add[{i}]"))?;
        let bit = k_bits[i as usize];
        let dx = b.sub(plus_p.x, acc.x, &format!("{label}.dx[{i}]"));
        let dy = b.sub(plus_p.y, acc.y, &format!("{label}.dy[{i}]"));
        acc = Point {
            x: b.add(acc.x, b.mul(dx, bit, &format!("{label}.sel.x[{i}]")), &format!("{label}.acc.x[{i}]")),
            y: b.add(acc.y, b.mul(dy, bit, &format!("{label}.sel.y[{i}]")), &format!("{label}.acc.y[{i}]")),
        };
    }

    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp;
    use ark_ff::Field;

    #[test]
    fn generator_satisfies_curve() {
        let mut b = CircuitBuilder::<Fp>::new();
        let p = Point {
            x: b.constant(Fp::from(1u64)),
            y: b.constant(Fp::from(2u64)),
        };
        assert_on_curve(&mut b, default_curve(), p, "gen");
        let circuit = b.build("curve-check");
        let w = circuit.solve_witness(&[]).unwrap();
        assert!(circuit.check_witness(&w).unwrap());
    }

    #[test]
    fn invert_is_checked() {
        let mut b = CircuitBuilder::<Fp>::new();
        let z = b.constant(Fp::from(5u64));
        let zi = invert(&mut b, z, "five");
        let circuit = b.build("inverse");
        let w = circuit
            .solve_witness(&[(zi, Fp::from(5u64).inverse().unwrap())])
            .unwrap();
        assert!(circuit.check_witness(&w).unwrap());
    }

    #[test]
    fn invert_rejects_wrong_inverse() {
        let mut b = CircuitBuilder::<Fp>::new();
        let z = b.constant(Fp::from(5u64));
        let zi = invert(&mut b, z, "five");
        let circuit = b.build("inverse");
        // 5 · 2 = 10 ≠ 1.
        assert!(circuit.solve_witness(&[(zi, Fp::from(2u64))]).is_none());
    }

    #[test]
    fn scalar_mul_builds_with_expected_degree() {
        let mut b = CircuitBuilder::<Fp>::new();
        let k = b.witness_named("k");
        let p = Point {
            x: b.constant(Fp::from(1u64)),
            y: b.constant(Fp::from(2u64)),
        };
        let q = scalar_mul(&mut b, default_curve(), k, p, 4, "mul4").unwrap();
        b.assert_public(q.x);
        let circuit = b.build("scalarmul4");
        assert_eq!(circuit.max_degree(), 2);
        assert!(circuit.num_constraints() > 4 * 2);
    }
}
