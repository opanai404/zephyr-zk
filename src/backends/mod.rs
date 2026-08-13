// ─────────────────────────────────────────────────────────────
// ZEPHYR · pluggable proof backends
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Pluggable proving systems.
//!
//! A backend turns a [`crate::circuit::Circuit`] plus a witness into a
//! [`Proof`], and later decides — given only the public inputs and the
//! circuit shape — whether a [`Proof`] is valid. The two shipped
//! backends are:
//!
//! - [`stark`] — a Plonky3-flavored FRI-based STARK over the circuit
//!   field (fast, transparent, post-quantum-flavored).
//! - [`groth16`] — a classic pairing-based R1CS proof over BN254 via
//!   arkworks (small proofs, trusted setup).
//!
//! The [`Prover`]/[`Verifier`] traits are the seam that lets a single
//! circuit description be proven under either assumption class — and
//! lets the [`crate::wasm`] verifier bindings accept proofs from both.

use crate::circuit::Circuit;
use crate::error::Error;
use ark_ff::PrimeField;

/// Stable identity of a proving system. This is what a [`Proof`]
/// carries so a verifier can select the right code path without
/// trusting the serialized payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendId {
    /// FRI-based STARK over the circuit field.
    Stark,
    /// Groth16 over BN254.
    Groth16,
}

/// A proof under a specific backend, serialized to opaque bytes.
///
/// `public_inputs` are stored alongside the proof so that a verifier
/// can re-check them against what it was told; `bytes` is the
/// backend-specific payload (FRI openings, or a Groth16 proof).
#[derive(Debug, Clone)]
pub struct Proof<F: PrimeField> {
    /// Which backend produced this proof.
    pub backend: BackendId,
    /// The public input vector, in circuit declaration order.
    pub public_inputs: Vec<F>,
    /// Backend-specific serialized proof payload.
    pub bytes: Vec<u8>,
}

impl<F: PrimeField> Proof<F> {
    /// Construct a new proof.
    pub fn new(backend: BackendId, public_inputs: Vec<F>, bytes: Vec<u8>) -> Self {
        Self { backend, public_inputs, bytes }
    }
}

/// Anything that identifies itself as a proving system.
pub trait Backend {
    /// The stable backend id.
    fn id(&self) -> BackendId;
}

/// Proof generation.
///
/// Implementors must validate the witness (via
/// [`Circuit::check_witness`]) before proving and surface
/// [`Error::InvalidWitness`] on failure.
pub trait Prover<F: PrimeField>: Backend {
    /// Produce a proof that `circuit` is satisfiable by `witness`.
    fn prove(&self, circuit: &Circuit<F>, witness: &[F]) -> Result<Proof<F>, Error>;
}

/// Proof verification.
///
/// `public` must contain exactly `circuit.num_public_inputs()` field
/// elements, in the order the circuit declared them. Implementors must
/// reject proofs whose embedded public inputs disagree with `public`.
pub trait Verifier<F: PrimeField>: Backend {
    /// Return `Ok(true)` iff `proof` is a valid proof that `public`
    /// satisfies `circuit`.
    fn verify(&self, circuit: &Circuit<F>, public: &[F], proof: &Proof<F>) -> Result<bool, Error>;
}

/// A convenience: prove *and* immediately verify, as a smoke check.
pub fn prove_and_verify<F: PrimeField>(
    prover: &dyn Prover<F>,
    verifier: &dyn Verifier<F>,
    circuit: &Circuit<F>,
    witness: &[F],
) -> Result<bool, Error> {
    let proof = prover.prove(circuit, witness)?;
    let (public, _) = circuit.split_witness(witness)?;
    verifier.verify(circuit, &public, &proof)
}

#[cfg(feature = "stark")]
pub mod stark;

#[cfg(feature = "groth16")]
pub mod groth16;
