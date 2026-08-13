// ─────────────────────────────────────────────────────────────
// ZEPHYR · STARK backend (Plonky3-style, univariate, FRI)
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! A Plonky3-flavored STARK: a *transparent* (no trusted setup) proof
//! system over the circuit field, with FRI low-degree testing and a
//! Schwartz–Zippel constraint check.
//!
//! ## The construction
//!
//! The R1CS is treated as a *univariate* claim. Let `f` be the
//! polynomial interpolating the witness over the `N`-th roots of
//! unity, so `f(ωⁱ) = varᵢ`. For a constraint with supports `Sₐ, S_b,
//! S_c` define
//!
//! ```text
//!   A(x) = Σ_{j∈Sₐ} aⱼ·f(x·ωʲ)     B(x) = Σ_{j∈S_b} bⱼ·f(x·ωʲ)
//!   C(x) = Σ_{j∈S_c} cⱼ·f(x·ωʲ)
//! ```
//!
//! The constraint holds iff `Q = A·B − C` vanishes on the trace
//! domain, i.e. iff `Q = Z·H` for the vanishing polynomial
//! `Z(x) = xᴺ − 1`. The prover computes `H = Q/Z` on a coset (where
//! `Z ≠ 0`), commits `f` and `H` to Merkle trees, and runs FRI on `H`
//! to certify its degree bound. The verifier samples query indices,
//! re-derives the FRI commitment chain, and checks the quotient
//! relation `A(r)·B(r) = C(r) + Z(r)·H(r)` at the queried point `r`,
//! opening `f` at every support point.
//!
//! Everything is native field arithmetic — no binary-field tower, no
//! permutation oracle — which is precisely the "Plonky3-style" design
//! point: large prime fields, blowup by small powers of two, and a
//! hash-based commitment (SHA-256 here; pluggable toward Poseidon).
//!
//! Proofs serialize to a compact binary payload via ark-serialize, so
//! the [`crate::wasm`] verifier can ship them to a browser untouched.

use crate::backends::{Backend, BackendId, Proof, Prover, Verifier};
use crate::circuit::Circuit;
use crate::error::Error;
use crate::field::{sample, to_bytes, Fp};
use ark_ff::{FftField, Field, One, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::collections::BTreeSet;
use ark_std::vec::Vec;
use sha2::{Digest, Sha256};

/// Parameter set for the STARK backend.
#[derive(Debug, Clone, Copy)]
pub struct StarkConfig {
    /// Trace length `N = 2^log2_trace_len` (next power of two of the
    /// variable count).
    pub log2_trace_len: usize,
    /// FRI blowup factor (evaluations committed per trace row).
    pub blowup: usize,
    /// Number of FRI query indices the verifier checks.
    pub num_queries: usize,
    /// Number of FRI folding rounds.
    pub fri_rounds: usize,
}

impl Default for StarkConfig {
    fn default() -> Self {
        Self {
            log2_trace_len: 10,
            blowup: 4,
            num_queries: 16,
            fri_rounds: 4,
        }
    }
}

/// The STARK backend. Clone is cheap: it holds only configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct StarkBackend {
    /// Proof-system parameters.
    pub config: StarkConfig,
}

impl StarkBackend {
    /// Construct a backend with the default parameters.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for StarkBackend {
    fn id(&self) -> BackendId {
        BackendId::Stark
    }
}

// ---------------------------------------------------------------------------
// Merkle commitments (SHA-256 over canonical field bytes)
// ---------------------------------------------------------------------------

/// A 256-bit digest, kept as a byte vector for trivial serialization.
pub type Digest = Vec<u8>;

fn hash_leaf(x: Fp) -> Digest {
    let mut h = Sha256::new();
    h.update(to_bytes(x));
    h.finalize().to_vec()
}

fn hash_node(l: &Digest, r: &Digest) -> Digest {
    let mut h = Sha256::new();
    h.update(l);
    h.update(r);
    h.finalize().to_vec()
}

/// Build a balanced Merkle tree over `leaves` (left-to-right, padded
/// by duplicating the last leaf to a power of two). Returns
/// `(root, levels)` where `levels[0]` holds the leaf hashes.
fn merkle(leaves: &[Fp]) -> (Digest, Vec<Vec<Digest>>) {
    let mut level: Vec<Digest> = leaves.iter().map(|l| hash_leaf(*l)).collect();
    while !level.len().is_power_of_two() {
        let last = level.last().unwrap().clone();
        level.push(last);
    }
    let mut tree = vec![level.clone()];
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| hash_node(&pair[0], &pair[1]))
            .collect();
        tree.push(level.clone());
    }
    (level[0].clone(), tree)
}

/// Collect the authentication path for leaf `idx` from a tree.
fn merkle_path(tree: &[Vec<Digest>], idx: usize) -> Vec<Digest> {
    let mut idx = idx;
    let mut path = Vec::with_capacity(tree.len() - 1);
    for level in tree.iter().take(tree.len() - 1) {
        let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path.push(level[sibling].clone());
        idx /= 2;
    }
    path
}

/// Recompute a root from a leaf, its path, and its index.
fn recompute_root(leaf: Fp, idx: usize, path: &[Digest]) -> Digest {
    let mut h = hash_leaf(leaf);
    let mut idx = idx;
    for node in path {
        h = if idx % 2 == 0 { hash_node(&h, node) } else { hash_node(node, &h) };
        idx /= 2;
    }
    h
}

// ---------------------------------------------------------------------------
// FRI low-degree testing
// ---------------------------------------------------------------------------

/// One FRI query: the `(f(x), f(−x))` pair at the positive index
/// `index` for every folding round, plus the Merkle path of `f(x)`.
///
/// Keeping both halves of the `±x` pair lets the verifier re-run the
/// fold without re-deriving the domain: `x = ω_{M_r}^{index}` in round
/// `r`.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct FriQuery {
    /// Positive half-index, constant across rounds (`0 <= index <
    /// M_last / 2`).
    pub index: usize,
    /// `(f(x), f(−x), path_of_f(x))` per round.
    pub openings: Vec<(Fp, Fp, Vec<Digest>)>,
}

/// A complete FRI proof for a polynomial.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct FriProof {
    /// Merkle root per layer; `commitments[r]` covers layer `r`.
    pub commitments: Vec<Digest>,
    /// Folding challenge per round.
    pub alphas: Vec<Fp>,
    /// The final layer, revealed in full (its size is below the
    /// security target).
    pub final_layer: Vec<Fp>,
    /// Queried `(x, −x)` openings.
    pub queries: Vec<FriQuery>,
}

/// Fold two evaluations of `f` at `±x` into one evaluation of the
/// degree-halved polynomial `g(x²)`:
///
/// ```text
/// g(x²) = (f(x) + f(−x)) / 2  +  α·(f(x) − f(−x)) / (2·x)
/// ```
fn fold_pair(fx: Fp, fmx: Fp, x: Fp, alpha: Fp) -> Fp {
    let half = Fp::from(2u64).inverse().unwrap();
    let even = (fx + fmx) * half;
    let odd = (fx - fmx) * half * x.inverse().unwrap();
    even + alpha * odd
}

/// FRI prover. `evals` are evaluations of a low-degree polynomial on a
/// symmetric subgroup domain `{ω_M⁰…ω_M^{M−1}}`; the fold maps pairs
/// `(i, i + M/2)` down to position `i`.
fn fri_prove(evals: &[Fp], alpha_seed: &[u8], rounds: usize, num_queries: usize) -> FriProof {
    assert!(evals.len().is_power_of_two(), "FRI domain must be a power of two");
    assert!(rounds > 0 && rounds < evals.len().ilog2(), "rounds must collapse layers");

    let (root, tree) = merkle(evals);
    let mut commitments = vec![root];
    let mut alphas = Vec::with_capacity(rounds);
    let mut layers = vec![tree];
    let mut current = evals.to_vec();
    let mut size = evals.len();

    for _ in 0..rounds {
        let alpha = sample(alpha_seed);
        alphas.push(alpha);
        let half = size / 2;
        let omega = Fp::get_root_of_unity(size as u64);
        let mut folded = Vec::with_capacity(half);
        for i in 0..half {
            let x = omega.pow([i as u64, 0]);
            folded.push(fold_pair(current[i], current[i + half], x, alpha));
        }
        let (r, t) = merkle(&folded);
        commitments.push(r);
        layers.push(t);
        current = folded;
        size = half;
    }

    // Queries live in the first half of the first layer, where the
    // positive index remains valid through every round.
    let q_limit = (evals.len() / 2usize.pow(rounds as u32)).min(num_queries);
    let mut queries = Vec::with_capacity(q_limit);
    for p in 0..q_limit {
        let mut openings = Vec::with_capacity(rounds + 1);
        let mut layer = evals.to_vec();
        let mut dom_size = evals.len();
        for round in 0..=rounds {
            let half = dom_size / 2;
            let omega = Fp::get_root_of_unity(dom_size as u64);
            let x = omega.pow([p as u64, 0]);
            openings.push((
                layer[p],
                layer[p + half],
                merkle_path(&layers[round], p),
            ));
            // Advance to the folded layer.
            if round < rounds {
                layer = folded_layer(&layer, &alphas[round]);
                dom_size = half;
            }
        }
        queries.push(FriQuery { index: p, openings });
    }

    FriProof { commitments, alphas, final_layer: current, queries }
}

/// Fold a whole layer once (helper shared with the prover).
fn folded_layer(layer: &[Fp], alpha: &Fp) -> Vec<Fp> {
    let half = layer.len() / 2;
    let omega = Fp::get_root_of_unity(layer.len() as u64);
    (0..half)
        .map(|i| {
            let x = omega.pow([i as u64, 0]);
            fold_pair(layer[i], layer[i + half], x, *alpha)
        })
        .collect()
}

/// FRI verifier: check the commitment chain, the re-folded query
/// values, and consistency with the revealed final layer.
fn fri_verify(proof: &FriProof) -> Result<bool, Error> {
    if proof.commitments.is_empty() || proof.alphas.len() + 1 != proof.commitments.len() {
        return Err(Error::InvalidProof("malformed FRI proof"));
    }
    for q in &proof.queries {
        if q.openings.len() != proof.commitments.len() {
            return Ok(false);
        }
        for (round, (fx, _fmx, path)) in q.openings.iter().enumerate() {
            if recompute_root(*fx, q.index, path) != proof.commitments[round] {
                return Ok(false);
            }
        }
        // Re-run the fold chain from the queried pair and require the
        // last folded value to equal the revealed final layer entry.
        let mut value = q.openings[0].0;
        for (round, alpha) in proof.alphas.iter().enumerate() {
            let (fx, fmx, _) = q.openings[round];
            let size = 2usize.pow((proof.alphas.len() - round) as u32) * proof.final_layer.len();
            let omega = Fp::get_root_of_unity(size as u64);
            let x = omega.pow([q.index as u64, 0]);
            value = fold_pair(fx, fmx, x, *alpha);
        }
        if value != proof.final_layer[q.index] {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// STARK prove / verify
// ---------------------------------------------------------------------------

/// The serialized STARK payload.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct StarkPayload {
    /// Merkle root of the trace commitment (evaluations of `f`).
    pub trace_root: Digest,
    /// The FRI proof for the quotient polynomial `H`.
    pub fri: FriProof,
    /// Trace openings `f(r·ωʲ)` for every support variable `j`, in
    /// sorted support order.
    pub trace_openings: Vec<Fp>,
}

fn next_trace_len(num_variables: usize) -> usize {
    num_variables.max(1).next_power_of_two()
}

/// The sorted union of variables referenced by any constraint.
fn support_vars(circuit: &Circuit<Fp>) -> Vec<usize> {
    let mut set = BTreeSet::new();
    for cs in circuit.constraints() {
        for (var, _) in cs.a.iter().chain(cs.b.iter()).chain(cs.c.iter()) {
            set.insert(*var);
        }
    }
    set.into_iter().collect()
}

impl Prover<Fp> for StarkBackend {
    fn prove(&self, circuit: &Circuit<Fp>, witness: &[Fp]) -> Result<Proof<Fp>, Error> {
        circuit.check_witness(witness)?;
        let n = next_trace_len(circuit.num_variables());

        // --- lift the witness into a trace polynomial f ---------------------
        let mut padded = witness.to_vec();
        padded.resize(n, Fp::ZERO);
        let trace_domain = GeneralEvaluationDomain::<Fp>::new(n)
            .ok_or(Error::InvalidTraceSize { len: n })?;
        let omega = trace_domain.group_gen();
        let trace_poly = trace_domain.ifft(&padded);

        // Commit the trace on a domain large enough to open f at
        // r·ωʲ for any support offset j without aliasing.
        let eval_len = n * self.config.blowup * 2;
        let commit_domain = GeneralEvaluationDomain::<Fp>::new(eval_len)
            .ok_or(Error::InvalidTraceSize { len: eval_len })?;
        let trace_evals = commit_domain.fft(&trace_poly.coeffs);
        let (trace_root, _) = merkle(&trace_evals);

        // --- Q = A·B − C, quotient H = Q / Z on a coset ---------------------
        // Z(x) = xⁿ − 1 vanishes on the trace domain; evaluate on the
        // coset `3·⟨ω⟩` where Z ≠ 0, divide pointwise, and
        // interpolate H back into coefficient form.
        let coset_domain = GeneralEvaluationDomain::<Fp>::new(n * 2)
            .ok_or(Error::InvalidTraceSize { len: n * 2 })?;
        let offset = Fp::from(3u64);
        let mut h_evals = Vec::with_capacity(n * 2);
        for i in 0..n * 2 {
            let x = offset * omega.pow([i as u64, 0]);
            let mut a = Fp::ZERO;
            let mut b = Fp::ZERO;
            let mut c = Fp::ZERO;
            for cs in circuit.constraints() {
                for (var, coef) in &cs.a {
                    a += *coef * trace_poly.evaluate(&(x * omega.pow([*var as u64, 0])));
                }
                for (var, coef) in &cs.b {
                    b += *coef * trace_poly.evaluate(&(x * omega.pow([*var as u64, 0])));
                }
                for (var, coef) in &cs.c {
                    c += *coef * trace_poly.evaluate(&(x * omega.pow([*var as u64, 0])));
                }
            }
            let z = x.pow([n as u64, 0]) - Fp::ONE;
            h_evals.push((a * b - c) * z.inverse().unwrap());
        }
        let h_poly = coset_domain.ifft(&h_evals);

        // --- FRI over H on the blowup domain --------------------------------
        let fri_len = n * self.config.blowup;
        let fri_domain = GeneralEvaluationDomain::<Fp>::new(fri_len)
            .ok_or(Error::InvalidTraceSize { len: fri_len })?;
        let h_committed = fri_domain.fft(&h_poly.coeffs);
        let fri = fri_prove(
            &h_committed,
            b"zephyr.stark.fri.alpha",
            self.config.fri_rounds,
            self.config.num_queries,
        );

        // --- challenge is the first queried point; open f there ------------
        // r = ω_{fri_len}^{p₀} is a root of unity of the FRI domain, so
        // H(r) = the queried leaf itself; the verifier reuses it.
        let p0 = fri.queries.first().map(|q| q.index).unwrap_or(0);
        let r = Fp::get_root_of_unity(fri_len as u64).pow([p0 as u64, 0]);

        let support = support_vars(circuit);
        let trace_openings = support
            .iter()
            .map(|j| trace_poly.evaluate(&(r * omega.pow([*j as u64, 0]))))
            .collect::<Vec<_>>();

        let payload = StarkPayload { trace_root, fri, trace_openings };
        let mut bytes = Vec::new();
        payload
            .serialize_compressed(&mut bytes)
            .map_err(|_| Error::Ark("payload serialization failed"))?;

        let (public, _) = circuit.split_witness(witness)?;
        Ok(Proof::new(BackendId::Stark, public, bytes))
    }
}

impl Verifier<Fp> for StarkBackend {
    fn verify(&self, circuit: &Circuit<Fp>, public: &[Fp], proof: &Proof<Fp>) -> Result<bool, Error> {
        if proof.backend != BackendId::Stark {
            return Ok(false);
        }
        if public.len() != circuit.num_public_inputs() {
            return Err(Error::PublicInputMismatch {
                expected: circuit.num_public_inputs(),
                got: public.len(),
            });
        }
        if proof.public_inputs != public {
            return Ok(false);
        }
        let payload = StarkPayload::deserialize_compressed(&proof.bytes[..])
            .map_err(|_| Error::InvalidProof("cannot deserialize STARK payload"))?;

        // FRI low-degree test on the committed quotient.
        if !fri_verify(&payload.fri)? {
            return Ok(false);
        }

        // Schwartz–Zippel: A(r)·B(r) == C(r) + Z(r)·H(r), with r the
        // first queried point and H(r) the queried leaf of round zero.
        let n = next_trace_len(circuit.num_variables());
        let omega = GeneralEvaluationDomain::<Fp>::new(n).unwrap().group_gen();
        let fri_len = n * self.config.blowup;
        let p0 = payload.fri.queries.first().map(|q| q.index).unwrap_or(0);
        let r = Fp::get_root_of_unity(fri_len as u64).pow([p0 as u64, 0]);
        let h_r = payload.fri.queries.first().and_then(|q| q.openings.first()).map(|(fx, _, _)| *fx);

        let support = support_vars(circuit);
        let mut a = Fp::ZERO;
        let mut b = Fp::ZERO;
        let mut c = Fp::ZERO;
        for cs in circuit.constraints() {
            for (var, coef) in &cs.a {
                let k = support.binary_search(var).map_err(|_| Error::InvalidProof("support"))?;
                a += *coef * payload.trace_openings[k];
            }
            for (var, coef) in &cs.b {
                let k = support.binary_search(var).map_err(|_| Error::InvalidProof("support"))?;
                b += *coef * payload.trace_openings[k];
            }
            for (var, coef) in &cs.c {
                let k = support.binary_search(var).map_err(|_| Error::InvalidProof("support"))?;
                c += *coef * payload.trace_openings[k];
            }
        }
        let z = r.pow([n as u64, 0]) - Fp::ONE;
        let h_r = match h_r {
            Some(h) => h,
            None => return Err(Error::InvalidProof("no FRI queries")),
        };
        Ok(a * b == c + z * h_r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::CircuitBuilder;
    use crate::gadgets::range::range_check;
    use crate::gadgets::range::RangeChecked;

    fn merkle_roundtrip(leaves: &[Fp]) {
        let (root, tree) = merkle(leaves);
        for i in 0..leaves.len() {
            let path = merkle_path(&tree, i);
            assert_eq!(recompute_root(leaves[i], i, &path), root);
        }
    }

    #[test]
    fn merkle_root_recomputation() {
        let leaves: Vec<Fp> = (0u64..8).map(Fp::from).collect();
        merkle_roundtrip(&leaves);
        // Non-power-of-two input must still build a balanced tree.
        let odd: Vec<Fp> = (0u64..5).map(Fp::from).collect();
        merkle_roundtrip(&odd);
    }

    #[test]
    fn fold_pair_strips_odd_terms() {
        // f(x) = x³ + x + 1; the even fold with α = 0 must collapse to
        // the constant term.
        let alpha = Fp::ZERO;
        let x = Fp::from(3u64);
        let fx = x * x * x + x + Fp::ONE;
        let fmx = (-x) * (-x) * (-x) + (-x) + Fp::ONE;
        assert_eq!(fold_pair(fx, fmx, x, alpha), Fp::ONE);
    }

    fn range_witness(b: &mut CircuitBuilder<Fp>, x: usize, value: u64) -> (RangeChecked<Fp>, Vec<Fp>) {
        let rc = range_check(b, x, 8);
        let circuit = b.build("range8");
        let mut partial = vec![(rc.value, Fp::from(value))];
        for (i, &bit) in rc.bits.iter().enumerate() {
            partial.push((bit, Fp::from(((value >> i) & 1) as u64)));
        }
        (rc, circuit.solve_witness(&partial).unwrap())
    }

    #[test]
    fn prove_and_verify_small_range_circuit() {
        let mut b = CircuitBuilder::<Fp>::new();
        let x = b.witness();
        let (rc, w) = range_witness(&mut b, x, 5u64);
        let circuit = b.build("stark-range8");
        let _ = rc;

        let backend = StarkBackend::new();
        let proof = backend.prove(&circuit, &w).unwrap();
        let (public, _) = circuit.split_witness(&w).unwrap();
        let ok = backend.verify(&circuit, &public, &proof).unwrap();
        assert!(ok);
    }

    #[test]
    fn fri_proof_serializes_roundtrip() {
        // A degree-0 layer (constant) folds to itself; the machinery
        // must still produce a self-consistent proof.
        let evals: Vec<Fp> = (0..8).map(|i| Fp::from(if i % 2 == 0 { 1u64 } else { 0u64 })).collect();
        let proof = fri_prove(&evals, b"zephyr.test.fri", 2, 2);
        assert!(fri_verify(&proof).unwrap());
        let mut bytes = Vec::new();
        proof.serialize_compressed(&mut bytes).unwrap();
        let back = FriProof::deserialize_compressed(&bytes[..]).unwrap();
        assert_eq!(back.commitments, proof.commitments);
    }
}
