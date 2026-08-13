// ─────────────────────────────────────────────────────────────
// ZEPHYR · wasm verifier implementation
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! The exported WASM surface.
//!
//! All functions return a `Result<_, JsValue>` so errors surface as
//! JavaScript exceptions with a readable message. Field elements cross
//! the boundary as canonical 32-byte compressed encodings (or decimal
//! strings for public inputs), which keeps the bindings dependency-free
//! and easy to test from JS.

use crate::backends::groth16::Groth16Verifier;
use crate::backends::stark::StarkBackend;
use crate::backends::{BackendId, Proof, Verifier};
use crate::circuit::Circuit;
use crate::dsl::CircuitBuilder;
use crate::error::Error;
use crate::field::Fp;
use ark_std::str::FromStr;
use ark_std::vec::Vec;
use wasm_bindgen::prelude::*;

/// The canonical demo circuit: prove knowledge of a 16-bit secret `x`
/// whose square `y = x·x` is public.
///
/// Rebuilt deterministically by both the prover and the verifier, so
/// the browser never needs to ship a full circuit description.
fn demo_circuit() -> Circuit<Fp> {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness_named("secret.x");
    crate::gadgets::range::range16(&mut b, x);
    let y = b.mul(x, x, "secret.x²");
    b.assert_public(y);
    b.build("demo.square16")
}

fn demo_witness(x_value: u64) -> (Circuit<Fp>, Vec<Fp>) {
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness();
    let rc = crate::gadgets::range::range16(&mut b, x);
    let y = b.mul(x, x, "x²");
    b.assert_public(y);
    let circuit = b.build("demo.square16");

    let mut partial = vec![(x, Fp::from(x_value))];
    for (i, &bit) in rc.bits.iter().enumerate() {
        partial.push((bit, Fp::from(((x_value >> i) & 1) as u64)));
    }
    let witness = circuit.solve_witness(&partial).expect("x is 16-bit by construction");
    (circuit, witness)
}

fn to_js(e: Error) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn decode_public(public: &[String]) -> Result<Vec<Fp>, JsValue> {
    public
        .iter()
        .map(|s| Fp::from_str(s).map_err(|_| JsValue::from_str("invalid public input: not a field element")))
        .collect()
}

/// Prove the demo circuit for a 16-bit secret.
///
/// Returns a single byte buffer framing `[n_public(4 bytes LE)]
/// [public inputs (32 bytes each)] [STARK payload]`, which
/// [`verify_demo`] accepts verbatim.
#[wasm_bindgen]
pub fn prove_demo(secret: String) -> Result<Vec<u8>, JsValue> {
    let x = secret
        .parse::<u64>()
        .map_err(|_| JsValue::from_str("secret must be an integer < 2^16"))?;
    if x >= (1u64 << 16) {
        return Err(JsValue::from_str("secret must be < 2^16"));
    }

    let (circuit, witness) = demo_witness(x);
    let backend = StarkBackend::new();
    let proof = backend.prove(&circuit, &witness).map_err(to_js)?;

    let mut out = Vec::new();
    out.extend_from_slice(&(proof.public_inputs.len() as u32).to_le_bytes());
    for p in &proof.public_inputs {
        out.extend_from_slice(&crate::field::to_bytes(*p));
    }
    out.extend_from_slice(&proof.bytes);
    Ok(out)
}

/// Verify a demo proof (STARK backend, transparent).
#[wasm_bindgen]
pub fn verify_demo(frame: &[u8]) -> Result<bool, JsValue> {
    let (public, payload) = split_frame(frame)?;
    let circuit = demo_circuit();
    let backend = StarkBackend::new();
    let proof = Proof::new(BackendId::Stark, public.clone(), payload);
    backend.verify(&circuit, &public, &proof).map_err(to_js)
}

/// Verify an arbitrary STARK proof produced by the native library,
/// given the public inputs as decimal strings.
#[wasm_bindgen]
pub fn verify_stark(payload: &[u8], public: Vec<String>) -> Result<bool, JsValue> {
    let public = decode_public(&public)?;
    let circuit = demo_circuit();
    let backend = StarkBackend::new();
    let proof = Proof::new(BackendId::Stark, public.clone(), payload.to_vec());
    backend.verify(&circuit, &public, &proof).map_err(to_js)
}

/// Verify a Groth16 proof against a serialized verifying key.
#[wasm_bindgen]
pub fn verify_groth16(proof: &[u8], public: Vec<String>, vk: &[u8]) -> Result<bool, JsValue> {
    let public = decode_public(&public)?;
    let circuit = demo_circuit();
    let verifier = Groth16Verifier::from_vk_bytes(vk, circuit.name()).map_err(to_js)?;
    let proof = Proof::new(BackendId::Groth16, public.clone(), proof.to_vec());
    verifier.verify(&circuit, &public, &proof).map_err(to_js)
}

/// Split a framed demo buffer into `(public, payload)`.
fn split_frame(frame: &[u8]) -> Result<(Vec<Fp>, Vec<u8>), JsValue> {
    if frame.len() < 4 {
        return Err(JsValue::from_str("empty proof frame"));
    }
    let n = u32::from_le_bytes(frame[..4].try_into().unwrap()) as usize;
    let head = 4 + n * 32;
    if frame.len() < head {
        return Err(JsValue::from_str("truncated proof frame"));
    }
    let mut public = Vec::with_capacity(n);
    for chunk in frame[4..head].chunks_exact(32) {
        public.push(crate::field::from_bytes::<Fp>(chunk));
    }
    Ok((public, frame[head..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_proof_frames_and_verifies() {
        let frame = prove_demo("42".to_string()).unwrap();
        assert!(verify_demo(&frame).unwrap());
    }

    #[test]
    fn demo_rejects_oversized_secret() {
        let err = prove_demo("70000".to_string());
        assert!(err.is_err());
    }

    #[test]
    fn decode_public_rejects_garbage() {
        assert!(decode_public(&["not-a-field".to_string()]).is_err());
    }
}
