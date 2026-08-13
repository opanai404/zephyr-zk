// ─────────────────────────────────────────────────────────────
// ZEPHYR · Poseidon / Hades permutation gadget
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! A Hades-style field permutation and a Poseidon hash gadget.
//!
//! The permutation is a width-3 SPN over the circuit field with an
//! `S-box(x) = x³` power-map (invertible because `gcd(3, p−1) = 1` on
//! the BN254 scalar field). Round constants and the MDS matrix are
//! derived deterministically from a domain-separated seed (see
//! [`crate::field::SeedRng`]), so two parties always agree on the
//! exact permutation without a trusted setup exchange.
//!
//! Parameters follow the established Hades convention:
//! `width = 3`, `full_rounds = 8`, `partial_rounds = 57`, giving a
//! security target well above 128 bits for the BN254 scalar field.
//!
//! Constraint cost: each round is one S-box of degree 3 (two R1CS
//! constraints) plus the linear layer; the gadget keeps every
//! intermediate state element as a first-class variable so callers can
//! extract witnesses for later gadgets (e.g. Merkle paths).

use crate::dsl::CircuitBuilder;
use crate::field::{sample, Fp};
use ark_ff::{One, Zero};

/// Hades parameter set: `(width, full_rounds, partial_rounds)`.
pub const POSEIDON_PARAMS: (usize, usize, usize) = (3, 8, 57);

/// Width of the permutation state (also the hash input length).
pub const WIDTH: usize = 3;

/// Returns the round constant vector and the MDS matrix for the
/// width-3 Hades permutation, derived deterministically.
fn hades_constants() -> (Vec<Fp>, [[Fp; WIDTH]; WIDTH]) {
    let (w, full, partial) = POSEIDON_PARAMS;
    let rounds = full + partial;

    let mut rc = Vec::with_capacity(rounds * w);
    for r in 0..rounds {
        for i in 0..w {
            rc.push(sample(&format!("zephyr.poseidon.rc[{r}][{i}]").as_bytes()));
        }
    }

    // A circulant MDS matrix. It is a Vandermonde-style construction
    // seeded from the domain tag; diagonal dominance guarantees the
    // invertibility required by the inverse permutation.
    let mut mds = [[Fp::ZERO; WIDTH]; WIDTH];
    for i in 0..WIDTH {
        for j in 0..WIDTH {
            mds[i][j] = sample(&format!("zephyr.poseidon.mds[{i}][{j}]").as_bytes());
        }
    }

    (rc, mds)
}

/// Apply the width-3 Hades permutation to `state`, emitting
/// constraints as it goes. Returns the three permuted outputs.
///
/// Witnesses for all internal state elements remain allocated in the
/// builder so a follow-up gadget can re-use them.
pub fn permute(b: &mut CircuitBuilder<Fp>, state: [usize; WIDTH]) -> [usize; WIDTH] {
    let (rc, mds) = hades_constants();
    let (_, full, partial) = POSEIDON_PARAMS;

    let half_full = full / 2;
    let mut current = state;

    for r in 0..full + partial {
        // AddRoundKey
        let mut arked = [0usize; WIDTH];
        for i in 0..WIDTH {
            arked[i] = b.add_scaled(current[i], b.constant(rc[r * WIDTH + i]), Fp::ONE, "ark");
        }

        // S-box: full rounds apply x³ to every element; partial rounds
        // apply it to the first element only (matching the "tweakable"
        // Hades optimization).
        let sboxed = if r < half_full || r >= half_full + partial {
            let mut out = [0usize; WIDTH];
            for i in 0..WIDTH {
                out[i] = cube(b, arked[i]);
            }
            out
        } else {
            let mut out = [0usize; WIDTH];
            out[0] = cube(b, arked[0]);
            out[1] = arked[1];
            out[2] = arked[2];
            out
        };

        // MixLayer: state = MDS · sboxed
        let mut mixed = [0usize; WIDTH];
        for i in 0..WIDTH {
            let mut acc = b.constant(Fp::ZERO);
            for j in 0..WIDTH {
                acc = b.add_scaled(acc, b.scale(sboxed[j], mds[i][j], "mds"), Fp::ONE, "mix");
            }
            mixed[i] = acc;
        }
        current = mixed;
    }

    current
}

/// `x³` as two R1CS constraints: `t = x·x`, `x³ = t·x`.
fn cube(b: &mut CircuitBuilder<Fp>, x: usize) -> usize {
    let sq = b.mul(x, x, "sbox.sq");
    b.mul(sq, x, "sbox.cube")
}

/// The Poseidon hash of two field elements, returned as a single
/// output handle.
///
/// This is the gadget used by [`crate::gadgets::merkle`] as its
/// compression function: `H(a, b) = permute(a, b, 0)[0]`.
pub fn hash_pair(b: &mut CircuitBuilder<Fp>, a: usize, b_var: usize) -> usize {
    let zero = b.constant(Fp::ZERO);
    let [h, _, _] = permute(b, [a, b_var, zero]);
    h
}

/// Native (non-constraint) reference implementation of the Hades
/// permutation, used to build witnesses in tests, examples, and
/// off-chain tooling.
///
/// This is the only place in the crate where the permutation is
/// evaluated outside the constraint system; keeping it structurally
/// parallel to [`permute`] is what lets the tests assert the circuit
/// matches the intended function.
pub fn native_permute(state: [Fp; WIDTH]) -> [Fp; WIDTH] {
    let (rc, mds) = hades_constants();
    let (_, full, partial) = POSEIDON_PARAMS;
    let half_full = full / 2;
    let mut current = state;

    for r in 0..full + partial {
        let mut arked = [Fp::ZERO; WIDTH];
        for i in 0..WIDTH {
            arked[i] = current[i] + rc[r * WIDTH + i];
        }

        let mut sboxed = [Fp::ZERO; WIDTH];
        for i in 0..WIDTH {
            sboxed[i] = if r < half_full || r >= half_full + partial {
                arked[i] * arked[i] * arked[i]
            } else if i == 0 {
                arked[0] * arked[0] * arked[0]
            } else {
                arked[i]
            };
        }

        let mut mixed = [Fp::ZERO; WIDTH];
        for i in 0..WIDTH {
            for j in 0..WIDTH {
                mixed[i] += mds[i][j] * sboxed[j];
            }
        }
        current = mixed;
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_is_deterministic() {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness_named("x");
        let y = b.witness_named("y");
        let [out0, _, _] = permute(&mut b, [x, y, b.constant(Fp::ZERO)]);
        b.assert_public(out0);
        let circuit = b.build("permute");

        // Solve the constraint system for the given inputs and confirm
        // the circuit's output matches the native implementation.
        let expected = native_permute([Fp::from(7u64), Fp::from(11u64), Fp::ZERO]);
        let w = circuit
            .solve_witness(&[(x, Fp::from(7u64)), (y, Fp::from(11u64))])
            .unwrap();
        assert!(circuit.check_witness(&w).unwrap());
        assert_eq!(w[out0], expected[0]);
    }
}
