// ─────────────────────────────────────────────────────────────
// ZEPHYR · Groth16 backend (arkworks over BN254)
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! A classic pairing-based R1CS proof system via arkworks.
//!
//! This backend instantiates Groth16 over BN254, the pairing curve of
//! record for proving systems. It is the *small-proof* counterpart to
//! [`crate::backends::stark`]: proofs are ~128 bytes and verify in two
//! pairings, at the cost of a per-circuit trusted setup.
//!
//! The bridge between Zephyr's [`crate::circuit::Circuit`] IR and
//! arkworks is [`R1CSAdapter`], a [`ConstraintSynthesizer`] that maps
//! our sparse R1CS onto a `ConstraintSystem`. The adapter is also the
//! reference for how *any* arkworks gadget can be embedded: implement
//! the synthesizer, hand it a witness, and the backend takes over.
//!
//! Setup is deterministic for a given circuit *and label*, which makes
//! keys reproducible across machines — a deliberate departure from
//! fresh randomness, chosen so CI and examples are stable.

use crate::backends::{Backend, BackendId, Proof, Prover, Verifier};
use crate::circuit::Circuit;
use crate::error::Error;
use crate::field::{Fp, SeedRng};
use ark_bn254::Bn254;
use ark_ff::{One, PrimeField, Zero};
use ark_groth16::{Groth16, Proof as Groth16Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// A ready-to-use Groth16 backend: setup once, prove/verify many.
#[derive(Debug, Clone)]
pub struct Groth16Backend {
    /// Per-circuit proving key.
    pub pk: ProvingKey<Bn254>,
    /// Per-circuit verifying key.
    pub vk: VerifyingKey<Bn254>,
    /// Name of the circuit this key was derived for.
    circuit_name: Box<str>,
}

/// Maps Zephyr's sparse R1CS onto an arkworks constraint system.
///
/// Witness layout: input `0` is the constant `1`; inputs `1..` are the
/// circuit's public variables in *declaration order*; auxiliary
/// variables are everything else. This order is what the verifier must
/// supply to [`Groth16::verify`], and it matches the public input
/// vector produced by [`Circuit::split_witness`].
pub struct R1CSAdapter<'a, F: PrimeField> {
    circuit: &'a Circuit<F>,
    witness: Vec<F>,
}

impl<'a, F: PrimeField> R1CSAdapter<'a, F> {
    /// Wrap a circuit and its (already validated) witness.
    pub fn new(circuit: &'a Circuit<F>, witness: &[F]) -> Self {
        Self {
            circuit,
            witness: witness.to_vec(),
        }
    }

    /// A structure-only adapter used for key generation: setup only
    /// needs the variable count and constraint list, so the witness is
    /// zero-filled.
    pub fn dummy(circuit: &'a Circuit<F>) -> Self {
        let mut witness = vec![F::ZERO; circuit.num_variables()];
        witness[0] = F::ONE;
        Self { circuit, witness }
    }
}

impl<'a, F: PrimeField> ConstraintSynthesizer<F> for R1CSAdapter<'a, F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let value_of = |var: usize| {
            self.witness
                .get(var)
                .copied()
                .ok_or(SynthesisError::AssignmentMissing)
        };

        // input 0: the constant one.
        let _one = cs.alloc_input(|| value_of(0))?;

        // Public inputs, in declaration order.
        let mut public_to_var = std::collections::HashMap::new();
        for &var in self.circuit.public_inputs() {
            let v = cs.alloc_input(|| value_of(var))?;
            public_to_var.insert(var, v);
        }

        // Everything else is auxiliary.
        for var in 1..self.circuit.num_variables() {
            if public_to_var.contains_key(&var) {
                continue;
            }
            let v = cs.alloc(|| value_of(var))?;
            public_to_var.insert(var, v);
        }

        // Translate each R1CS constraint into an arkworks enforcement.
        for constraint in self.circuit.constraints() {
            let a = to_lc(&constraint.a, &public_to_var);
            let b = to_lc(&constraint.b, &public_to_var);
            let c = to_lc(&constraint.c, &public_to_var);
            cs.enforce_constraint(a, b, c)?;
        }
        Ok(())
    }
}

/// Convert a sparse `(variable, coefficient)` list into a linear
/// combination over allocated variables.
fn to_lc<F: PrimeField>(
    terms: &[(usize, F)],
    vars: &std::collections::HashMap<usize, ark_relations::r1cs::Variable>,
) -> LinearCombination<F> {
    let mut lc = LinearCombination::zero();
    for (var, coef) in terms {
        let variable = vars.get(var).expect("all referenced variables are allocated");
        lc += (*coef, *variable);
    }
    lc
}

impl Groth16Backend {
    /// Run the per-circuit trusted setup deterministically from
    /// `label`, so keys are reproducible.
    pub fn setup(circuit: &Circuit<Fp>, label: &[u8]) -> Result<Self, Error> {
        let mut rng = SeedRng::new(label);
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
            R1CSAdapter::dummy(circuit),
            &mut rng,
        )?;
        Ok(Self {
            pk,
            vk,
            circuit_name: circuit.name().into(),
        })
    }

    /// Serialize the verifying key to canonical bytes (for distribution
    /// to verifiers, including the WASM build).
    pub fn vk_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.vk
            .serialize_compressed(&mut out)
            .map_err(|_| Error::Ark("verifying key serialization failed"))?;
        Ok(out)
    }
}

impl Backend for Groth16Backend {
    fn id(&self) -> BackendId {
        BackendId::Groth16
    }
}

/// Verifier-only handle: carries the verifying key and nothing else.
///
/// This is what the [`crate::wasm`] bindings instantiate, so a browser
/// build ships a verifying key but never a proving key.
#[derive(Debug, Clone)]
pub struct Groth16Verifier {
    /// Per-circuit verifying key.
    pub vk: VerifyingKey<Bn254>,
    /// Name of the circuit this key was derived for.
    circuit_name: Box<str>,
}

impl Groth16Verifier {
    /// Rebuild a verifier from serialized verifying-key bytes.
    pub fn from_vk_bytes(vk: &[u8], circuit_name: &str) -> Result<Self, Error> {
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk)
            .map_err(|_| Error::Ark("cannot deserialize verifying key"))?;
        Ok(Self { vk, circuit_name: circuit_name.into() })
    }
}

impl Backend for Groth16Verifier {
    fn id(&self) -> BackendId {
        BackendId::Groth16
    }
}

impl Verifier<Fp> for Groth16Verifier {
    fn verify(&self, circuit: &Circuit<Fp>, public: &[Fp], proof: &Proof<Fp>) -> Result<bool, Error> {
        if proof.backend != BackendId::Groth16 {
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
        if circuit.name() != self.circuit_name.as_ref() {
            return Err(Error::BackendNotEnabled("groth16 verifier/circuit name mismatch"));
        }
        let groth_proof = Groth16Proof::<Bn254>::deserialize_compressed(&proof.bytes[..])
            .map_err(|_| Error::InvalidProof("cannot deserialize Groth16 proof"))?;
        let mut inputs = vec![Fp::ONE];
        inputs.extend_from_slice(public);
        Ok(Groth16::<Bn254>::verify(&self.vk, &inputs, &groth_proof)?)
    }
}

impl Prover<Fp> for Groth16Backend {
    fn prove(&self, circuit: &Circuit<Fp>, witness: &[Fp]) -> Result<Proof<Fp>, Error> {
        circuit.check_witness(witness)?;
        if circuit.name() != self.circuit_name.as_ref() {
            return Err(Error::BackendNotEnabled("groth16 key/circuit name mismatch"));
        }
        let mut rng = SeedRng::new(b"zephyr.groth16.blinding");
        let adapter = R1CSAdapter::new(circuit, witness);
        let proof = Groth16::<Bn254>::prove(&self.pk, adapter, &mut rng)?;

        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|_| Error::Ark("proof serialization failed"))?;

        let (public, _) = circuit.split_witness(witness)?;
        Ok(Proof::new(BackendId::Groth16, public, bytes))
    }
}

impl Verifier<Fp> for Groth16Backend {
    fn verify(&self, circuit: &Circuit<Fp>, public: &[Fp], proof: &Proof<Fp>) -> Result<bool, Error> {
        if proof.backend != BackendId::Groth16 {
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
        if circuit.name() != self.circuit_name.as_ref() {
            return Err(Error::BackendNotEnabled("groth16 key/circuit name mismatch"));
        }

        let groth_proof = Groth16Proof::<Bn254>::deserialize_compressed(&proof.bytes[..])
            .map_err(|_| Error::InvalidProof("cannot deserialize Groth16 proof"))?;

        // arkworks expects the full input vector including the leading one.
        let mut inputs = vec![Fp::ONE];
        inputs.extend_from_slice(public);
        Ok(Groth16::<Bn254>::verify(&self.vk, &inputs, &groth_proof)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsl::CircuitBuilder;

    #[test]
    fn prove_and_verify_round_trip() {
        // c = a·a (a public square), proven under Groth16.
        let mut b = CircuitBuilder::<Fp>::new();
        let a = b.witness();
        let c = b.mul(a, a, "square");
        b.assert_public(c);
        let circuit = b.build("g16-square");
        let w = circuit.solve_witness(&[(a, Fp::from(9u64))]).unwrap();

        let backend = Groth16Backend::setup(&circuit, b"zephyr.test.g16").unwrap();
        let proof = backend.prove(&circuit, &w).unwrap();
        let (public, _) = circuit.split_witness(&w).unwrap();
        assert_eq!(public, vec![Fp::from(81u64)]);
        let ok = backend.verify(&circuit, &public, &proof).unwrap();
        assert!(ok);
    }

    #[test]
    fn verify_rejects_tampered_public_input() {
        let mut b = CircuitBuilder::<Fp>::new();
        let a = b.witness();
        let c = b.mul(a, a, "square");
        b.assert_public(c);
        let circuit = b.build("g16-square");
        let w = circuit.solve_witness(&[(a, Fp::from(9u64))]).unwrap();

        let backend = Groth16Backend::setup(&circuit, b"zephyr.test.g16").unwrap();
        let proof = backend.prove(&circuit, &w).unwrap();
        let (public, _) = circuit.split_witness(&w).unwrap();

        // The embedded public input disagrees with the supplied one.
        let wrong = vec![Fp::from(80u64)];
        let ok = backend.verify(&circuit, &wrong, &proof).unwrap();
        assert!(!ok);
    }

    #[test]
    fn verifying_key_is_serializable() {
        let mut b = CircuitBuilder::<Fp>::new();
        let a = b.witness();
        b.assert_boolean(a, "bool");
        let circuit = b.build("g16-bool");
        let backend = Groth16Backend::setup(&circuit, b"zephyr.test.g16").unwrap();
        let vk = backend.vk_bytes().unwrap();
        assert!(!vk.is_empty());
    }
}
