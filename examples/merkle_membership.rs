// ─────────────────────────────────────────────────────────────
// ZEPHYR · example: Merkle membership proof
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Build a Merkle tree, extract an inclusion witness for one leaf,
//! constrain a membership proof, and verify the witness satisfies it.
//!
//! Run with:
//!
//! ```text
//! cargo run --release --example merkle_membership
//! ```

use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::merkle::assert_path;
use zephyr_zk::gadgets::poseidon::native_permute;

use ark_ff::Zero;

fn hash_native(a: Fp, b: Fp) -> Fp {
    native_permute([a, b, Fp::ZERO])[0]
}

fn main() {
    // A height-4 tree over leaves 0..16, and an inclusion witness for
    // leaf 9 (the branch decision bits read 1 → 0 → 0 → 1).
    let (leaf, siblings, bits, root) = membership_witness(9, 16);

    let mut b = CircuitBuilder::<Fp>::new();
    let leaf_v = b.witness_named("leaf");
    let root_v = b.witness_named("root");
    let sib_v: Vec<usize> = siblings.iter().map(|_| b.witness()).collect();
    let bit_v: Vec<usize> = bits.iter().map(|_| b.witness()).collect();
    assert_path(&mut b, root_v, leaf_v, &sib_v, &bit_v);
    let circuit = b.build("merkle-height4");

    let mut partial = vec![(leaf_v, leaf), (root_v, root)];
    partial.extend(siblings.iter().zip(&sib_v).map(|(s, &v)| (v, *s)));
    partial.extend(bits.iter().zip(&bit_v).map(|(b_, &v)| (v, Fp::from(*b_ as u64))));

    let witness = circuit.solve_witness(&partial).expect("valid membership witness");
    assert!(circuit.check_witness(&witness).unwrap());

    println!("circuit:            {}", circuit.name());
    println!("  height:           {}", bits.len());
    println!("  leaf index:       9");
    println!("  commitments:      {} constraints", circuit.constraints().len());
    println!("  merkle root:      {} (public)", root);
    println!("  membership:       ✓ verified against the root");
}

/// Returns `(leaf, siblings_bottom_up, bits_msb_first, root)` for a
/// leaf at `index` in a tree over `count` leaves.
fn membership_witness(index: usize, count: usize) -> (Fp, Vec<Fp>, Vec<u8>, Fp) {
    let leaves: Vec<Fp> = (0..count as u64).map(Fp::from).collect();
    let mut level = leaves.clone();
    let mut tree = vec![level.clone()];
    while level.len() > 1 {
        level = level.chunks(2).map(|p| hash_native(p[0], p[1])).collect();
        tree.push(level.clone());
    }

    let mut siblings = Vec::new();
    let mut bits = Vec::new();
    let mut cursor = index;
    for h in tree.iter().take(tree.len() - 1) {
        bits.push((cursor & 1) as u8);
        let start = (cursor >> 1) * 2;
        siblings.push(h[start + (1 - (cursor & 1) as usize)]);
        cursor >>= 1;
    }
    bits.reverse();
    siblings.reverse();
    (leaves[index], siblings, bits, tree.last().unwrap()[0])
}
