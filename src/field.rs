// ─────────────────────────────────────────────────────────────
// ZEPHYR · field arithmetic primitives
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Field arithmetic shims shared by every layer of Zephyr.
//!
//! The default field is the BN254 scalar field (`ark_bn254::Fr`),
//! which matches both the Plonky3-style STARK backend (large prime
//! fields are natively supported) and the Groth16 backend (BN254 is
//! the pairing-friendly curve of record). Anything implementing
//! [`ark_ff::PrimeField`] is a valid circuit field.
//!
//! This module also owns deterministic sampling so that gadgets that
//! need constants (round constants, MDS entries, domain separators)
//! are reproducible across runs and platforms.

use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_std::rand::RngCore;
use sha2::Digest;

/// The default circuit field: the BN254 scalar field.
pub type Fp = ark_bn254::Fr;

/// A domain-separation tag prepended to every hash domain.
pub const DOMAIN_TAG: &[u8] = b"ZEPHYR-V0";

/// Little-endian canonical bytes of a field element.
pub fn to_bytes<F: PrimeField>(x: F) -> Vec<u8> {
    let big = x.into_bigint();
    big.to_bytes_le()
}

/// Interpret a fixed number of little-endian bytes as a field element,
/// reducing modulo the field modulus.
pub fn from_bytes<F: PrimeField>(bytes: &[u8]) -> F {
    debug_assert!(bytes.len() <= F::BigInt::NUM_LIMBS * 8);
    F::from_le_bytes_mod_order(bytes)
}

/// A deterministic PRNG seeded from an ASCII label. Used to derive
/// round constants, MDS matrices, and proving keys so that "random"
/// setup material is actually reproducible (and, for Groth16, an
/// instantiation point for a future universal/recursive backend).
pub struct SeedRng {
    state: [u64; 4],
}

impl SeedRng {
    /// Seed from a static label (e.g. `b"zephyr.poseidon.3-61"`).
    pub fn new(label: &[u8]) -> Self {
        let mut h = sha2::Sha256::new();
        h.update(DOMAIN_TAG);
        h.update(label);
        let digest = h.finalize();
        let mut state = [0u64; 4];
        for (i, chunk) in digest.chunks_exact(8).enumerate() {
            state[i] = u64::from_le_bytes(chunk.try_into().unwrap());
        }
        Self { state }
    }

    fn next_u64(&mut self) -> u64 {
        // xorshift64* over four lanes, summed back into the first lane.
        let mut acc = 0u64;
        for lane in self.state.iter_mut() {
            let mut x = *lane;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            acc ^= x;
            *lane = x;
        }
        self.state[0] = self.state[0].wrapping_add(0x9E3779B97F4A7C15);
        acc ^ self.state[0]
    }
}

impl RngCore for SeedRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    fn next_u64(&mut self) -> u64 {
        self.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ark_std::rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Sample a field element deterministically from a label. Every source
/// of "randomness" in Zephyr — round constants, MDS entries, FRI
/// challenges, Groth16 blinding — flows through here, so results are
/// reproducible across runs and platforms.
pub fn sample<F: PrimeField>(label: &[u8]) -> F {
    let mut rng = SeedRng::new(label);
    F::rand(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn seeded_rng_is_reproducible() {
        let a = sample::<Fp>(b"zephyr.test.1");
        let b = sample::<Fp>(b"zephyr.test.1");
        assert_eq!(a, b);

        let c = sample::<Fp>(b"zephyr.test.2");
        assert_ne!(a, c);
    }

    #[test]
    fn bytes_round_trip() {
        let x = sample::<Fp>(b"roundtrip");
        assert_eq!(from_bytes::<Fp>(&to_bytes(x)), x);
        assert!(to_bytes(Fp::ZERO).iter().all(|b| *b == 0));
    }
}
