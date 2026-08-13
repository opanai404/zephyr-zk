// ─────────────────────────────────────────────────────────────
// ZEPHYR · wasm-bindgen verifier bindings
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Browser-facing bindings.
//!
//! Compile with `--features wasm` to produce a `wasm32-unknown-unknown`
//! module exposing the functions in [`crate::wasm::verify`]. The demo
//! verifier targets a fixed circuit ("prove you know a 16-bit secret
//! whose square is y") so a page can verify a proof with two calls and
//! no server round-trip.
//!
//! The STARK backend is fully transparent — verification needs only
//! the public inputs and the proof bytes. The Groth16 verifier takes a
//! serialized verifying key, keeping proving keys off the client.

pub mod verify;

pub use verify::{prove_demo, verify_demo, verify_groth16, verify_stark};
