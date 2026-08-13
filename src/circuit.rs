// ─────────────────────────────────────────────────────────────
// ZEPHYR · circuit IR (R1CS)
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! The circuit intermediate representation.
//!
//! A [`Circuit`] is a rank-1 constraint system over a [`PrimeField`]:
//! a list of [`Constraint`]s of the form
//!
//! ```text
//!   (Σ aᵢ·xᵢ) · (Σ bᵢ·xᵢ) = (Σ cᵢ·xᵢ)
//! ```
//!
//! where `x₀` is the constant-one variable. This is the same shape
//! that the Groth16 R1CS backend consumes directly, and it is what the
//! STARK backend lifts into a low-degree polynomial AIR.
//!
//! The IR is deliberately *backend-agnostic*: gadgets and the DSL
//! produce [`Circuit`]s, and only [`crate::backends`] decides how a
//! circuit is proven.

use crate::error::Error;
use ark_ff::{Field, One, PrimeField, Zero};
use ark_std::collections::BTreeMap;

/// The reserved variable holding the constant `1` in every circuit.
pub const ONE: usize = 0;

/// A variable handle: the index of a cell in the witness assignment.
pub type Variable = usize;

/// A complete witness: one field element per variable.
pub type Witness<F> = Vec<F>;

/// A dense rank-1 constraint: `(a·x) * (b·x) = (c·x)`.
///
/// Terms are stored as sparse `(variable, coefficient)` pairs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint<F: PrimeField> {
    /// Left-hand linear combination.
    pub a: Vec<(usize, F)>,
    /// Right-hand linear combination.
    pub b: Vec<(usize, F)>,
    /// Output linear combination.
    pub c: Vec<(usize, F)>,
    /// Zero-indexed constraint number, for error reporting.
    pub id: usize,
    /// Human-readable label, propagated from the DSL.
    pub label: Option<Box<str>>,
}

impl<F: PrimeField> Constraint<F> {
    /// Evaluate the constraint against a witness.
    ///
    /// Returns `Ok(true)` when `(a·x)*(b·x) == (c·x)`.
    pub fn eval(&self, witness: &[F]) -> Result<bool, Error> {
        let a = Self::dot(&self.a, witness)?;
        let b = Self::dot(&self.b, witness)?;
        let c = Self::dot(&self.c, witness)?;
        Ok(a * b == c)
    }

    fn dot(terms: &[(usize, F)], witness: &[F]) -> Result<F, Error> {
        let mut acc = F::ZERO;
        for (var, coef) in terms {
            let val = witness
                .get(*var)
                .ok_or(Error::UnknownVariable { id: *var })?;
            acc += *coef * *val;
        }
        Ok(acc)
    }

    /// Algebraic degree of the constraint (2 for the product side).
    pub fn degree(&self) -> u32 {
        2
    }
}

/// A complete rank-1 constraint system.
#[derive(Debug, Clone)]
pub struct Circuit<F: PrimeField> {
    constraints: Vec<Constraint<F>>,
    num_variables: usize,
    public_inputs: Vec<usize>,
    name: Box<str>,
    /// Map from human label to variable id, kept for debugging tooling.
    symbols: BTreeMap<Box<str>, usize>,
    /// Variables that are known constants (introduced by `constant`).
    /// Filled in automatically by [`Circuit::complete_witness`].
    constants: BTreeMap<usize, F>,
}

impl<F: PrimeField> Circuit<F> {
    /// Name this circuit. Names should be stable across runs; they seed
    /// deterministic setup material in the backends.
    pub fn named(mut self, name: impl Into<String>) -> Self {
        self.name = name.into().into_boxed_str();
        self
    }

    /// The constraint list, in definition order.
    pub fn constraints(&self) -> &[Constraint<F>] {
        &self.constraints
    }

    /// Total variable count, including the constant-one variable.
    pub fn num_variables(&self) -> usize {
        self.num_variables
    }

    /// Variables marked public, in declaration order.
    pub fn public_inputs(&self) -> &[usize] {
        &self.public_inputs
    }

    /// Number of public inputs (the first `public_inputs().len()`
    /// entries of a witness are the verifier-visible portion).
    pub fn num_public_inputs(&self) -> usize {
        self.public_inputs.len()
    }

    /// Circuit name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The maximum algebraic degree of any constraint.
    pub fn max_degree(&self) -> u32 {
        self.constraints.iter().map(Constraint::degree).max().unwrap_or(0)
    }

    /// Check whether `witness` satisfies every constraint.
    ///
    /// The witness is a complete assignment over all variables; public
    /// inputs occupy the first `num_public_inputs()` slots and must
    /// match what the verifier will later supply.
    pub fn check_witness(&self, witness: &[F]) -> Result<bool, Error> {
        if witness.len() != self.num_variables {
            return Err(Error::InvalidWitness);
        }
        for c in &self.constraints {
            if !c.eval(witness)? {
                return Err(Error::UnsatisfiedConstraint { constraint: c.id });
            }
        }
        Ok(true)
    }

    /// Validate that a *public input vector* has the right shape for
    /// this circuit and is consistent with `witness`'s public slots.
    pub fn check_public_inputs(&self, public: &[F], witness: &[F]) -> Result<bool, Error> {
        if public.len() != self.public_inputs.len() {
            return Err(Error::PublicInputMismatch {
                expected: self.public_inputs.len(),
                got: public.len(),
            });
        }
        Ok(public
            .iter()
            .zip(self.public_inputs.iter())
            .all(|(expected, var)| witness.get(*var) == Some(expected)))
    }

    /// Split a full witness into `(public, private)`.
    pub fn split_witness(&self, witness: &[F]) -> Result<(Vec<F>, Vec<F>), Error> {
        if witness.len() != self.num_variables {
            return Err(Error::InvalidWitness);
        }
        let mut public = Vec::with_capacity(self.public_inputs.len());
        let mut private = Vec::with_capacity(self.num_variables);
        for (i, v) in witness.iter().enumerate() {
            if self.public_inputs.contains(&i) {
                public.push(*v);
            } else {
                private.push(*v);
            }
        }
        Ok((public, private))
    }

    /// Complete a partial witness assignment by filling every constant
    /// register with its known value.
    ///
    /// Unassigned non-constant variables are zero-filled. Returns
    /// `None` if the partial assignment overrides a constant with a
    /// conflicting value. This is the primary helper for tests,
    /// examples, and prover tooling that does not want to track the
    /// builder's internal constant variables by hand.
    pub fn complete_witness(&self, partial: &[(usize, F)]) -> Option<Vec<F>> {
        let mut w = vec![F::ZERO; self.num_variables];
        w[ONE] = F::ONE;
        for (var, val) in &self.constants {
            w[*var] = *val;
        }
        for (var, val) in partial {
            match self.constants.get(var) {
                Some(c) if c != val => return None,
                _ => w[*var] = *val,
            }
        }
        Some(w)
    }

    /// The known constant value of a variable, if any.
    pub fn constant_value(&self, var: usize) -> Option<F> {
        self.constants.get(&var).copied()
    }

    /// Solve for a complete witness from a partial assignment.
    ///
    /// The DSL emits constraints in dataflow order, so each constraint
    /// has at most one "output" variable that is not yet determined;
    /// this solver walks the constraint list and discharges every
    /// constraint in turn, much like a circom-style witness
    /// calculator. Constants are pre-filled, and a partial assignment
    /// that contradicts a constant makes the solver return `None`.
    ///
    /// This is the entry point used by the test harness, the example
    /// programs, and the prover tooling when a backend can consume a
    /// witness directly.
    pub fn solve_witness(&self, partial: &[(usize, F)]) -> Option<Vec<F>> {
        // `None` marks a not-yet-assigned variable, so a variable that
        // legitimately holds ZERO is still "known".
        let mut w: Vec<Option<F>> = vec![None; self.num_variables];
        w[ONE] = Some(F::ONE);
        for (var, val) in &self.constants {
            w[*var] = Some(*val);
        }
        for (var, val) in partial {
            match w[*var] {
                Some(c) if c != *val => return None,
                _ => w[*var] = Some(*val),
            }
        }

        for c in &self.constraints {
            let (a_known, a_unknown) = Self::split(&c.a, &w);
            let (b_known, b_unknown) = Self::split(&c.b, &w);
            let (c_known, c_unknown) = Self::split(&c.c, &w);

            match (a_unknown.len(), b_unknown.len(), c_unknown.len()) {
                (0, 0, 0) => {
                    // Pure check: a·b == c.
                    if a_known * b_known != c_known {
                        return None;
                    }
                }
                (0, 1, 0) => {
                    // out = c / a  (b side).
                    if a_known.is_zero() {
                        return None;
                    }
                    let (u, k) = b_unknown[0];
                    w[u] = Some((c_known / a_known - b_known) / k);
                }
                (1, 0, 0) => {
                    // out = c / b  (a side).
                    if b_known.is_zero() {
                        return None;
                    }
                    let (u, k) = a_unknown[0];
                    w[u] = Some((c_known / b_known - a_known) / k);
                }
                (0, 0, 1) => {
                    // out = (a·b − c_known) / k  (c side).
                    let (u, k) = c_unknown[0];
                    w[u] = Some((a_known * b_known - c_known) / k);
                }
                _ => {
                    // Under-determined at this step; not a dataflow
                    // circuit as emitted by the DSL.
                    return None;
                }
            }
        }

        Some(w.into_iter().map(|o| o.unwrap_or(F::ZERO)).collect())
    }

    /// Split a linear combination into `(known_sum, [(unknown_var, coeff)])`.
    fn split(terms: &[(usize, F)], w: &[Option<F>]) -> (F, Vec<(usize, F)>) {
        let mut known = F::ZERO;
        let mut unknown = Vec::new();
        for (var, coef) in terms {
            if coef.is_zero() {
                continue;
            }
            match w.get(*var).and_then(|o| *o) {
                Some(v) => known += *coef * v,
                None => unknown.push((*var, *coef)),
            }
        }
        (known, unknown)
    }
}

/// Builder-side accumulator; produced by [`crate::dsl::CircuitBuilder`].
#[doc(hidden)]
#[derive(Debug, Clone)]
pub struct CircuitBuilderState<F: PrimeField> {
    pub constraints: Vec<Constraint<F>>,
    pub num_variables: usize,
    pub public_inputs: Vec<usize>,
    pub symbols: BTreeMap<Box<str>, usize>,
    pub constants: BTreeMap<usize, F>,
}

impl<F: PrimeField> Default for CircuitBuilderState<F> {
    fn default() -> Self {
        Self {
            constraints: Vec::new(),
            // variable 0 is the reserved constant one.
            num_variables: 1,
            public_inputs: Vec::new(),
            symbols: BTreeMap::new(),
            constants: BTreeMap::new(),
        }
    }
}

impl<F: PrimeField> CircuitBuilderState<F> {
    /// Allocate a fresh variable and return its index.
    pub fn alloc(&mut self) -> usize {
        let id = self.num_variables;
        self.num_variables += 1;
        id
    }

    /// Register a symbol→variable mapping (last write wins).
    pub fn bind(&mut self, name: &str, var: usize) {
        self.symbols.insert(name.into(), var);
    }

    /// Record that `var` is a constant holding `value`.
    pub fn set_constant(&mut self, var: usize, value: F) {
        self.constants.insert(var, value);
    }

    /// Push a constraint, assigning its id.
    pub fn push(&mut self, mut c: Constraint<F>, label: Option<&str>) {
        c.id = self.constraints.len();
        c.label = label.map(Into::into);
        self.constraints.push(c);
    }

    /// Finalize into an immutable circuit.
    pub fn into_circuit(self, name: &str) -> Circuit<F> {
        let mut constants = self.constants;
        constants.insert(ONE, F::ONE);
        Circuit {
            constraints: self.constraints,
            num_variables: self.num_variables,
            public_inputs: self.public_inputs,
            name: name.into(),
            symbols: self.symbols,
            constants,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp;

    fn two_variable_product() -> (Circuit<Fp>, Vec<Fp>) {
        // x1 * x2 = x3, with x3 public.
        let mut state = CircuitBuilderState::default();
        let x1 = state.alloc();
        let x2 = state.alloc();
        let x3 = state.alloc();
        let one = Fp::ONE;
        state.push(
            Constraint {
                a: vec![(x1, one)],
                b: vec![(x2, one)],
                c: vec![(x3, one)],
                id: 0,
                label: None,
            },
            Some("mul"),
        );
        state.public_inputs.push(x3);
        let circuit = state.into_circuit("mul2");
        let witness = circuit.solve_witness(&[(x1, Fp::from(3u64)), (x2, Fp::from(4u64))]).unwrap();
        (circuit, witness)
    }

    #[test]
    fn constraint_eval_satisfied() {
        let (c, w) = two_variable_product();
        assert!(c.check_witness(&w).unwrap());
        assert_eq!(c.solve_witness(&[(1, Fp::from(3u64))]), None, "under-determined");
    }

    #[test]
    fn constraint_eval_unsatisfied() {
        let (c, w) = two_variable_product();
        let mut bad = w.clone();
        bad[3] = Fp::from(13u64);
        assert_eq!(c.check_witness(&bad), Err(Error::UnsatisfiedConstraint { constraint: 0 }));
    }

    #[test]
    fn public_input_split() {
        let (c, w) = two_variable_product();
        let (public, private) = c.split_witness(&w).unwrap();
        assert_eq!(public, vec![Fp::from(12u64)]);
        assert_eq!(private.len(), c.num_variables() - 1);
    }

    #[test]
    fn witness_length_mismatch() {
        let (c, _) = two_variable_product();
        assert_eq!(c.check_witness(&[Fp::ONE]), Err(Error::InvalidWitness));
    }

    #[test]
    fn solver_rejects_contradictory_constants() {
        let mut b = crate::dsl::CircuitBuilder::<Fp>::new();
        let _seven = b.constant(Fp::from(7u64));
        let circuit = b.build("c");
        assert!(circuit.solve_witness(&[]).is_some());
        assert_eq!(circuit.solve_witness(&[(1, Fp::from(9u64))]), None);
    }
}
