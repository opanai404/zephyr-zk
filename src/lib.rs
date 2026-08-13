// ─────────────────────────────────────────────────────────────
// ZEPHYR · zero-knowledge circuit toolkit with pluggable backends
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! **Zephyr** is a zero-knowledge proving toolkit: a declarative
//! constraint DSL, a gadget library (range, Merkle, hashing,
//! elliptic-curve ops), and pluggable proof backends (Plonky3-style
//! STARKs, arkworks Groth16).
//!
//! The design goal is *one circuit description, many proving
//! systems*. A [`circuit::Circuit`] is a rank-1 constraint
//! (R1CS) program built through the [`dsl::CircuitBuilder`];
//! gadget layers compile down to constraints; and a backend turns
//! those constraints into a proof under a chosen assumption class.
//!
//! ```no_run
//! use zephyr_zk::dsl::CircuitBuilder;
//! use zephyr_zk::field::Fp;
//! use zephyr_zk::gadgets::range::range_check;
//!
//! // a < 2^16 is a range-checked witness
//! let mut b = CircuitBuilder::<Fp>::new();
//! let a = b.witness();
//! range_check(&mut b, a, 16);
//! b.assert_public(a);
//! let circuit = b.build("range16");
//! assert!(circuit.num_constraints() > 16);
//! ```
//!
//! Proof systems are selected through [`backends`] traits so the
//! same circuit can be proven in a browser via the [`wasm`]
//! verifier bindings.

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]
#![doc = include_str!("../README.md")]

pub mod backends;
pub mod circuit;
pub mod dsl;
pub mod error;
pub mod field;
pub mod gadgets;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use circuit::{Constraint, Variable, Witness};
pub use error::Error;
pub use field::Fp;
