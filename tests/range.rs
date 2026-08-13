// ─────────────────────────────────────────────────────────────
// ZEPHYR · integration: range gadget + proptest
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Property tests for the range gadget: every value `0 <= v < 2^n`
//! must satisfy the circuit, and every `v >= 2^n` must not.

use proptest::prelude::*;
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::range::range_check;

fn partial_for(value: u64, rc_value: usize, bits: &[usize]) -> Vec<(usize, Fp)> {
    let mut partial = vec![(rc_value, Fp::from(value))];
    for (i, &bit) in bits.iter().enumerate() {
        partial.push((bit, Fp::from(((value >> i) & 1) as u64)));
    }
    partial
}

proptest! {
    #[test]
    fn in_bounds_values_satisfy(v in 0u64..(1 << 8)) {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness();
        let rc = range_check(&mut b, x, 8);
        let circuit = b.build("prop-range8");
        let w = circuit.solve_witness(&partial_for(v, rc.value, &rc.bits)).unwrap();
        prop_assert!(circuit.check_witness(&w).unwrap());
    }

    #[test]
    fn out_of_bounds_values_are_rejected(v in (1u64 << 8)..(1 << 20)) {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness();
        let rc = range_check(&mut b, x, 8);
        let circuit = b.build("prop-range8");
        // Bits of v beyond 8 are silently dropped by the truncating
        // decomposition, so the reassembly check must fail.
        let w = circuit.solve_witness(&partial_for(v, rc.value, &rc.bits));
        prop_assert!(w.is_none());
    }
}

#[test]
fn adjacent_widths_share_layout() {
    // Two independent range checks in one circuit stay satisfiable.
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness();
    let y = b.witness();
    let rc_x = range_check(&mut b, x, 4);
    let rc_y = range_check(&mut b, y, 4);
    let circuit = b.build("two-ranges");

    let mut partial = vec![(rc_x.value, Fp::from(3u64)), (rc_y.value, Fp::from(11u64))];
    for (i, &bit) in rc_x.bits.iter().enumerate() {
        partial.push((bit, Fp::from(((3u64 >> i) & 1) as u64)));
    }
    for (i, &bit) in rc_y.bits.iter().enumerate() {
        partial.push((bit, Fp::from(((11u64 >> i) & 1) as u64)));
    }
    let w = circuit.solve_witness(&partial).unwrap();
    assert!(circuit.check_witness(&w).unwrap());
}
