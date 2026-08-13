// ─────────────────────────────────────────────────────────────
// ZEPHYR · gadget library
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Reusable constraint gadgets.
//!
//! A gadget is a *constraint recipe*: it consumes variables from a
//! [`crate::dsl::CircuitBuilder`] and emits the constraints that make
//! a stated algebraic relationship hold. Gadgets are responsible for
//! allocating any intermediate variables they need and for returning a
//! single canonical output handle.
//!
//! Available gadgets:
//!
//! - [`range`] — tight range checks via binary decomposition.
//! - [`poseidon`] — a Hades-style field permutation and a Poseidon
//!   hash function over the circuit field.
//! - [`merkle`] — Merkle-tree root accumulation over a hash gadget.
//! - [`ec`] — short-Weierstrass curve addition, doubling, and
//!   scalar multiplication (the BN254 curve).
//!
//! Gadgets are backend-agnostic; proving happens later in
//! [`crate::backends`].

pub mod ec;
pub mod merkle;
pub mod poseidon;
pub mod range;
