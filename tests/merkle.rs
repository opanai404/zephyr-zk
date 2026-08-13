// ─────────────────────────────────────────────────────────────
// ZEPHYR · integration: Merkle gadget
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Merkle inclusion proofs over the Poseidon compression function.

use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::merkle::assert_path;
use zephyr_zk::gadgets::poseidon::native_permute;

use ark_ff::Zero;

fn hash_native(a: Fp, b: Fp) -> Fp {
    native_permute([a, b, Fp::ZERO])[0]
}

/// Height-4 tree over leaves 0..16; membership witness for index 9.
fn witness_9() -> (Fp, Vec<Fp>, Vec<u8>, Fp) {
    let leaves: Vec<Fp> = (0u64..16).map(Fp::from).collect();
    let mut level = leaves.clone();
    let mut tree = vec![level.clone()];
    while level.len() > 1 {
        level = level.chunks(2).map(|p| hash_native(p[0], p[1])).collect();
        tree.push(level.clone());
    }

    let idx = 9usize;
    let mut siblings = Vec::new();
    let mut bits = Vec::new();
    let mut cursor = idx;
    for h in tree.iter().take(tree.len() - 1) {
        bits.push((cursor & 1) as u8);
        let start = (cursor >> 1) * 2;
        siblings.push(h[start + (1 - (cursor & 1) as usize)]);
        cursor >>= 1;
    }
    bits.reverse();
    siblings.reverse();
    (leaves[idx], siblings, bits, tree.last().unwrap()[0])
}

#[test]
fn membership_proof_for_internal_leaf() {
    let (leaf, siblings, bits, root) = witness_9();

    let mut b = CircuitBuilder::<Fp>::new();
    let leaf_v = b.witness_named("leaf");
    let root_v = b.witness_named("root");
    let sib_v: Vec<usize> = siblings.iter().map(|_| b.witness()).collect();
    let bit_v: Vec<usize> = bits.iter().map(|_| b.witness()).collect();
    assert_path(&mut b, root_v, leaf_v, &sib_v, &bit_v);
    let circuit = b.build("merkle-h4");

    let mut partial = vec![(leaf_v, leaf), (root_v, root)];
    partial.extend(siblings.iter().zip(&sib_v).map(|(s, &v)| (v, *s)));
    partial.extend(bits.iter().zip(&bit_v).map(|(b_, &v)| (v, Fp::from(*b_ as u64))));

    let w = circuit.solve_witness(&partial).unwrap();
    assert!(circuit.check_witness(&w).unwrap());
}

#[test]
fn wrong_root_is_rejected() {
    let (leaf, siblings, bits, mut root) = witness_9();
    root += Fp::ONE;

    let mut b = CircuitBuilder::<Fp>::new();
    let leaf_v = b.witness_named("leaf");
    let root_v = b.witness_named("root");
    let sib_v: Vec<usize> = siblings.iter().map(|_| b.witness()).collect();
    let bit_v: Vec<usize> = bits.iter().map(|_| b.witness()).collect();
    assert_path(&mut b, root_v, leaf_v, &sib_v, &bit_v);
    let circuit = b.build("merkle-h4");

    let mut partial = vec![(leaf_v, leaf), (root_v, root)];
    partial.extend(siblings.iter().zip(&sib_v).map(|(s, &v)| (v, *s)));
    partial.extend(bits.iter().zip(&bit_v).map(|(b_, &v)| (v, Fp::from(*b_ as u64))));

    assert!(circuit.solve_witness(&partial).is_none());
}
