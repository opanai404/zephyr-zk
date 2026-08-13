// ─────────────────────────────────────────────────────────────
// ZEPHYR · declarative constraint DSL
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! The declarative circuit DSL.
//!
//! [`CircuitBuilder`] is the primary authoring surface. It owns a
//! growing set of variables and constraints; witness values are
//! assigned *by index* at prove time, which keeps the builder pure and
//! lets a single circuit description be reused across backends.
//!
//! ```no_run
//! use zephyr_zk::dsl::CircuitBuilder;
//! use zephyr_zk::field::Fp;
//! use zephyr_zk::gadgets::range::range_check;
//!
//! let mut b = CircuitBuilder::<Fp>::new();
//! let a = b.witness();
//! let b_val = b.constant(Fp::from(5u64));
//! let c = b.mul(a, b_val, "a*5");
//! range_check(&mut b, c, 8);      // enforce c < 2^8
//! b.assert_public(c);             // expose the product
//! let circuit = b.build("mul5");
//! # let _ = circuit;
//! ```
//!
//! All arithmetic is linear or bilinear; anything else (bit
//! decomposition, hashing, field inversion) lives in the gadget layer
//! on top of this builder.

use crate::circuit::{Circuit, CircuitBuilderState, Constraint, ONE};
use crate::error::Error;
use ark_ff::{One, PrimeField, Zero};

/// Mutable circuit assembly context.
///
/// Variables are plain `usize` handles. The builder never reads witness
/// values, so it is safe to clone and reuse; assignment happens once,
/// at proof time, against a dense witness vector.
#[derive(Debug, Clone, Default)]
pub struct CircuitBuilder<F: PrimeField> {
    state: CircuitBuilderState<F>,
}

impl<F: PrimeField> CircuitBuilder<F> {
    /// A fresh, empty builder with only the constant-one variable.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate an unconstrained witness variable.
    pub fn witness(&mut self) -> usize {
        self.state.alloc()
    }

    /// Allocate a witness variable and bind it to a label.
    pub fn witness_named(&mut self, name: &str) -> usize {
        let v = self.state.alloc();
        self.state.bind(name, v);
        v
    }

    /// Bind a label to an existing variable.
    pub fn bind(&mut self, name: &str, var: usize) -> &mut Self {
        self.state.bind(name, var);
        self
    }

    /// A constant variable holding `value`.
    pub fn constant(&mut self, value: F) -> usize {
        // The constant-one variable is a special case; any other
        // constant is a fresh variable constrained to equal its value.
        if value.is_one() {
            return ONE;
        }
        let v = self.state.alloc();
        self.state.set_constant(v, value);
        // 1 * x = value  →  x - value = 0 via the R1CS shape.
        let one = F::ONE;
        self.state.push(
            Constraint {
                a: vec![(ONE, one)],
                b: vec![(v, one)],
                c: vec![(ONE, value)],
                id: 0,
                label: None,
            },
            Some("const"),
        );
        v
    }

    /// Linearly combine two variables with a coefficient: `x + k·y`.
    pub fn add_scaled(&mut self, x: usize, y: usize, k: F, label: &str) -> usize {
        let out = self.state.alloc();
        let one = F::ONE;
        self.state.push(
            Constraint {
                a: vec![(ONE, one)],
                b: vec![(out, one)],
                c: vec![(x, one), (y, k)],
                id: 0,
                label: None,
            },
            Some(label),
        );
        out
    }

    /// `x + y`.
    pub fn add(&mut self, x: usize, y: usize, label: &str) -> usize {
        self.add_scaled(x, y, F::ONE, label)
    }

    /// `x - y`.
    pub fn sub(&mut self, x: usize, y: usize, label: &str) -> usize {
        self.add_scaled(x, y, -F::ONE, label)
    }

    /// `x * y` (the atomic R1CS product).
    pub fn mul(&mut self, x: usize, y: usize, label: &str) -> usize {
        let out = self.state.alloc();
        let one = F::ONE;
        self.state.push(
            Constraint {
                a: vec![(x, one)],
                b: vec![(y, one)],
                c: vec![(out, one)],
                id: 0,
                label: None,
            },
            Some(label),
        );
        out
    }

    /// `k * x` via a single multiplication constraint.
    pub fn scale(&mut self, x: usize, k: F, label: &str) -> usize {
        let c = self.constant(k);
        self.mul(x, c, label)
    }

    /// Constrain `x` to equal `y`.
    pub fn assert_eq(&mut self, x: usize, y: usize, label: &str) {
        let one = F::ONE;
        self.state.push(
            Constraint {
                a: vec![(x, one)],
                b: vec![(ONE, one)],
                c: vec![(y, one)],
                id: 0,
                label: None,
            },
            Some(label),
        );
    }

    /// Constrain `x` to be zero. Implemented as `x * 1 = 0`.
    pub fn assert_zero(&mut self, x: usize, label: &str) {
        self.assert_eq(x, self.constant(F::ZERO), label);
    }

    /// Assert that `x` is a boolean (either 0 or 1) via `x·(x−1) = 0`.
    pub fn assert_boolean(&mut self, x: usize, label: &str) {
        let one = F::ONE;
        // x·(x − 1) = 0
        let minus_one = self.constant(-F::ONE);
        let x_minus_1 = self.add_scaled(x, minus_one, F::ONE, "x-1");
        self.state.push(
            Constraint {
                a: vec![(x, one)],
                b: vec![(x_minus_1, one)],
                c: vec![(ONE, F::ZERO)],
                id: 0,
                label: None,
            },
            Some(label),
        );
    }

    /// Mark a variable as a public input (verifier-visible).
    pub fn assert_public(&mut self, x: usize) {
        if !self.state.public_inputs.contains(&x) {
            self.state.public_inputs.push(x);
        }
    }

    /// Total constraint count so far.
    pub fn num_constraints(&self) -> usize {
        self.state.constraints.len()
    }

    /// Number of allocated variables including the constant-one slot.
    pub fn num_variables(&self) -> usize {
        self.state.num_variables
    }

    /// Consume the builder into an immutable, named circuit.
    pub fn build(self, name: &str) -> Circuit<F> {
        self.state.into_circuit(name)
    }

    /// Build, then panic-verify that a candidate witness satisfies it.
    ///
    /// Useful in tests and examples where failure is a bug, not a
    /// runtime branch.
    pub fn build_checked(self, name: &str, witness: &[F]) -> Result<Circuit<F>, Error> {
        let circuit = self.build(name);
        circuit.check_witness(witness)?;
        Ok(circuit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp;

    #[test]
    fn linear_algebra_satisfies() {
        // c = 2*a + 3*b, all public.
        let mut b = CircuitBuilder::<Fp>::new();
        let a = b.witness_named("a");
        let bv = b.witness_named("b");
        let c = b.add_scaled(b.scale(a, Fp::from(2u64), "2a"), b.scale(bv, Fp::from(3u64), "3b"), Fp::ONE, "c");
        b.assert_public(c);
        let circuit = b.build("linear");
        let w = circuit.solve_witness(&[(a, Fp::from(4u64)), (bv, Fp::from(5u64))]).unwrap();
        assert!(circuit.check_witness(&w).unwrap());
        assert_eq!(w[c], Fp::from(23u64)); // 2·4 + 3·5
    }

    #[test]
    fn boolean_constraint_rejects_two() {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness();
        b.assert_boolean(x, "bool");
        let circuit = b.build("bool");
        assert!(circuit.solve_witness(&[(x, Fp::from(1u64))]).is_some());
        // x = 2 fails the x·(x−1) = 0 constraint.
        assert!(circuit.solve_witness(&[(x, Fp::from(2u64))]).is_none());
    }

    #[test]
    fn constants_are_canonical() {
        let mut b = CircuitBuilder::<Fp>::new();
        let one = b.constant(Fp::ONE);
        let seven = b.constant(Fp::from(7u64));
        assert_eq!(one, ONE);
        let circuit = b.build("consts");
        let w = circuit.solve_witness(&[]).unwrap();
        assert!(circuit.check_witness(&w).unwrap());
        assert_eq!(w[seven], Fp::from(7u64));
        assert_eq!(circuit.constant_value(seven), Some(Fp::from(7u64)));
    }
}
