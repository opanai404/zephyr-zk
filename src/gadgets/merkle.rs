// ─────────────────────────────────────────────────────────────
// ZEPHYR · Merkle tree gadget
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Merkle-tree commitment gadget.
//!
//! [`verify_path`] constrains that a leaf, a sibling path, and a
//! position index recompute to a given root. The compression function
//! is the Poseidon hash from [`crate::gadgets::poseidon`]; the gadget
//! is agnostic to the concrete hash so long as it exposes the same
//! `(left, right) -> digest` shape.
//!
//! Position bits are boolean-asserted as they are consumed, which both
//! bounds the index to `< 2^height` and lets the circuit normalize the
//! sibling order (left/right is selected by the bit).

use crate::dsl::CircuitBuilder;
use crate::field::Fp;
use crate::gadgets::poseidon;

/// The root output handle of a Merkle inclusion proof.
///
/// `leaf` is the committed value, `siblings` the sibling hashes from
/// the leaf up to the root (length `height`, order bottom-to-top), and
/// `bits` the binary representation of the leaf's index, most
/// significant first.
pub fn verify_path(
    b: &mut CircuitBuilder<Fp>,
    leaf: usize,
    siblings: &[usize],
    bits: &[usize],
) -> usize {
    assert_eq!(
        siblings.len(),
        bits.len(),
        "Merkle path height and index width must agree"
    );

    let mut acc = leaf;
    for (i, (&sibling, &bit)) in siblings.iter().zip(bits.iter()).enumerate() {
        b.assert_boolean(bit, &format!("index bit {i}"));
        let is_right = bit;

        // acc = H(acc, sibling) if bit == 0 else H(sibling, acc).
        let left_ordered = poseidon::hash_pair(b, acc, sibling);
        let right_ordered = poseidon::hash_pair(b, sibling, acc);

        // Selection without branching: out = left + bit·(right − left).
        // We can multiply into a difference term because R1CS is bilinear.
        let diff = b.sub(right_ordered, left_ordered, &format!("right-left {i}"));
        let selected_delta = b.mul(diff, is_right, &format!("bit*delta {i}"));
        acc = b.add(left_ordered, selected_delta, &format!("select {i}"));
    }
    acc
}

/// Convenience wrapper that also asserts the computed root equals a
/// supplied root variable, returning `()`.
pub fn assert_path(
    b: &mut CircuitBuilder<Fp>,
    root: usize,
    leaf: usize,
    siblings: &[usize],
    bits: &[usize],
) {
    let computed = verify_path(b, leaf, siblings, bits);
    b.assert_eq(computed, root, "merkle root matches");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::poseidon::native_permute;
    use ark_ff::{One, Zero};

    /// Native hash used only to build test witnesses.
    fn hash_native(a: Fp, b: Fp) -> Fp {
        native_permute([a, b, Fp::ZERO])[0]
    }

    /// Build a height-3 Merkle tree over leaves `0..8` using the
    /// native (non-circuit) hash, and return `(leaf, siblings, bits,
    /// root)` for leaf index 3.
    fn sample_tree() -> (Fp, Vec<Fp>, Vec<u8>, Fp) {
        let leaves = (0u64..8).map(Fp::from).collect::<Vec<_>>();
        let mut level = leaves.clone();
        let mut tree = vec![level.clone()];
        while level.len() > 1 {
            level = level.chunks(2).map(|pair| hash_native(pair[0], pair[1])).collect();
            tree.push(level.clone());
        }

        let idx = 3usize;
        let mut siblings = Vec::new();
        let mut bits = Vec::new();
        let mut cursor = idx;
        for h in tree.iter().take(tree.len() - 1) {
            bits.push((cursor & 1) as u8);
            let start = (cursor >> 1) * 2;
            let sib = h[start + (1 - (cursor & 1) as usize)];
            siblings.push(sib);
            cursor >>= 1;
        }
        bits.reverse();
        siblings.reverse();

        (leaves[idx], siblings, bits, tree.last().unwrap()[0])
    }

    fn build_circuit() -> (Circuit<Fp>, usize, usize, Vec<usize>, Vec<usize>) {
        let mut b = CircuitBuilder::<Fp>::new();
        let leaf_v = b.witness_named("leaf");
        let root_v = b.witness_named("root");
        let sib_v = vec![b.witness(), b.witness(), b.witness()];
        let bit_v = vec![b.witness(), b.witness(), b.witness()];
        assert_path(&mut b, root_v, leaf_v, &sib_v, &bit_v);
        b.assert_public(root_v);
        let circuit = b.build("merkle-h3");
        (circuit, leaf_v, root_v, sib_v, bit_v)
    }

    #[test]
    fn path_verifies_with_correct_witness() {
        let (leaf, siblings, bits, root) = sample_tree();
        let (circuit, leaf_v, root_v, sib_v, bit_v) = build_circuit();

        let mut partial = vec![(leaf_v, leaf), (root_v, root)];
        partial.extend(siblings.iter().zip(&sib_v).map(|(s, &v)| (v, *s)));
        partial.extend(bits.iter().zip(&bit_v).map(|(b_, &v)| (v, Fp::from(*b_ as u64))));

        let w = circuit.solve_witness(&partial).unwrap();
        assert!(circuit.check_witness(&w).unwrap());
        let (public, _) = circuit.split_witness(&w).unwrap();
        assert_eq!(public, vec![root]);
    }

    #[test]
    fn path_rejects_wrong_leaf() {
        let (leaf, siblings, bits, root) = sample_tree();
        let (circuit, leaf_v, root_v, sib_v, bit_v) = build_circuit();

        let mut partial = vec![(leaf_v, leaf + Fp::ONE), (root_v, root)];
        partial.extend(siblings.iter().zip(&sib_v).map(|(s, &v)| (v, *s)));
        partial.extend(bits.iter().zip(&bit_v).map(|(b_, &v)| (v, Fp::from(*b_ as u64))));

        // The recomputed root no longer matches the committed root.
        assert!(circuit.solve_witness(&partial).is_none());
    }

    #[test]
    fn path_rejects_wrong_sibling() {
        let (leaf, mut siblings, bits, root) = sample_tree();
        siblings[1] += Fp::ONE; // corrupt the middle sibling
        let (circuit, leaf_v, root_v, sib_v, bit_v) = build_circuit();

        let mut partial = vec![(leaf_v, leaf), (root_v, root)];
        partial.extend(siblings.iter().zip(&sib_v).map(|(s, &v)| (v, *s)));
        partial.extend(bits.iter().zip(&bit_v).map(|(b_, &v)| (v, Fp::from(*b_ as u64))));

        assert!(circuit.solve_witness(&partial).is_none());
    }
}
