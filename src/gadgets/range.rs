// ─────────────────────────────────────────────────────────────
// ZEPHYR · range gadget (binary decomposition)
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Tight range checks.
//!
//! `range_check(x, n)` constrains `x < 2^n` by decomposing `x` into
//! `n` boolean bits and re-assembling them. Every bit is asserted
//! boolean (so `b·(b−1) = 0`), and the weighted sum is forced to equal
//! `x`. The result is `3n + 1` R1CS constraints for `n` bits — the
//! canonical textbook construction, no table lookups, no big-integer
//! arithmetic on the field.

use crate::dsl::CircuitBuilder;
use ark_ff::{Field, One, Zero};

/// The result of a successful range check.
///
/// `value` is the handle of the (reconstructed) value, equal to the
/// input by construction. `bits` are the handles of the individual
/// decomposition bits, `bits[i]` carrying weight `2^i`, so that a
/// witness generator can supply the bit values explicitly.
#[derive(Debug, Clone)]
pub struct RangeChecked<F: ark_ff::PrimeField> {
    /// Handle of the reassembled value (`== input`).
    pub value: usize,
    /// Handles of the boolean bits, LSB first.
    pub bits: Vec<usize>,
    /// Phantom: the builder is typed but the handles are just indices.
    pub _marker: std::marker::PhantomData<F>,
}

/// Constrain `x < 2^bits` by binary decomposition.
///
/// Returns the reconstructed value and the bit handles, so callers can
/// chain further constraints on the bits or supply them as part of a
/// witness.
pub fn range_check<F: ark_ff::PrimeField>(b: &mut CircuitBuilder<F>, x: usize, bits: u32) -> RangeChecked<F> {
    assert!(bits > 0, "range width must be positive");
    assert!(bits < 256, "range width must fit in the field");

    let mut acc = b.constant(F::ZERO);
    let mut weight = F::ONE;
    let mut bit_handles = Vec::with_capacity(bits as usize);

    for i in 0..bits {
        let bit = b.witness_named(&format!("range[{x}].bit[{i}]"));
        b.assert_boolean(bit, &format!("bit {i} is boolean"));
        bit_handles.push(bit);
        let weighted = b.scale(bit, weight, &format!("bit {i} * 2^{i}"));
        acc = b.add(acc, weighted, &format!("partial sum up to bit {i}"));
        weight = weight.double();
    }

    b.assert_eq(acc, x, "decomposition reassembles to x");
    RangeChecked {
        value: x,
        bits: bit_handles,
        _marker: std::marker::PhantomData,
    }
}

/// Constrain `0 <= x < 2^16`, the most common web-facing range.
///
/// Provided as a convenience; it is exactly [`range_check`] with a
/// `bits` of 16.
pub fn range16<F: ark_ff::PrimeField>(b: &mut CircuitBuilder<F>, x: usize) -> RangeChecked<F> {
    range_check(b, x, 16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::Fp;

    /// Build the partial assignment for a range check: `x` and its
    /// `bits` LSB-first decomposition.
    fn partial_for(rc: &RangeChecked<Fp>, x: u64) -> Vec<(usize, Fp)> {
        let mut partial = vec![(rc.value, Fp::from(x))];
        for (i, &bit) in rc.bits.iter().enumerate() {
            partial.push((bit, Fp::from(((x >> i) & 1) as u64)));
        }
        partial
    }

    #[test]
    fn range_check_accepts_in_bounds() {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness();
        let rc = range_check(&mut b, x, 8);
        let circuit = b.build("range8");

        // 255 is the largest valid 8-bit value.
        let w = circuit.solve_witness(&partial_for(&rc, 255)).unwrap();
        assert!(circuit.check_witness(&w).unwrap());
    }

    #[test]
    fn range_check_rejects_overflow() {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness();
        let rc = range_check(&mut b, x, 8);
        let circuit = b.build("range8");

        // 256 cannot be represented in 8 bits: the reassembly check
        // compares the reconstructed value (0) against x (256).
        assert!(circuit.solve_witness(&partial_for(&rc, 256)).is_none());
    }

    #[test]
    fn range_check_rejects_non_boolean_bit() {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness();
        let rc = range_check(&mut b, x, 4);
        let circuit = b.build("range4");

        // x = 3 with a liar bit: bit1 = 2 instead of 1.
        let mut partial = vec![(rc.value, Fp::from(3u64))];
        for (i, &bit) in rc.bits.iter().enumerate() {
            let v = ((3u64 >> i) & 1) as u64;
            partial.push((bit, Fp::from(if i == 1 { v + 1 } else { v })));
        }
        assert!(circuit.solve_witness(&partial).is_none());
    }

    #[test]
    fn range_check_constraint_count() {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness();
        range_check(&mut b, x, 16);
        // Per bit: 3 (boolean) + 2 (scale) + 1 (add); the first bit's
        // weight is 1 so its scale collapses to a single multiply;
        // one final reassembly check.
        assert_eq!(b.num_constraints(), 5 + 15 * 6 + 1);
    }
}
