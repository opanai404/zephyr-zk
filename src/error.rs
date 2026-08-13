// ─────────────────────────────────────────────────────────────
// ZEPHYR · error model
// SPDX-License-Identifier: MIT
// ─────────────────────────────────────────────────────────────
//! Central error type. Zephyr keeps a single [`Error`] enum so that
//! `?` flows cleanly from the DSL through the gadget layer into the
//! backends, and so the WASM surface can stringify every failure mode
//! into a `JsValue` without losing the category.

use core::fmt;

/// All error kinds surfaced by Zephyr.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A variable or label was referenced before it existed.
    UnknownVariable { id: usize },
    /// A constraint referenced a degree above the circuit's maximum.
    DegreeTooHigh { constraint: usize, degree: u32, max_degree: u32 },
    /// A witness did not satisfy a constraint during setup or prove.
    UnsatisfiedConstraint { constraint: usize },
    /// The witness did not satisfy the circuit at all.
    InvalidWitness,
    /// An operation expected a power-of-two trace length.
    InvalidTraceSize { len: usize },
    /// A backend was asked for a proof it does not implement.
    BackendNotEnabled(&'static str),
    /// Proof deserialization or verification failed.
    InvalidProof(&'static str),
    /// Public inputs in the proof did not match the circuit layout.
    PublicInputMismatch { expected: usize, got: usize },
    /// A gadget was used with an incompatible width or field.
    InvalidConfiguration(&'static str),
    /// Errors forwarded from the arkworks Groth16 implementation.
    Ark(&'static str),
    /// WebAssembly glue errors (argument marshaling, field decoding).
    Wasm(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownVariable { id } => write!(f, "unknown variable {id}"),
            Self::DegreeTooHigh { constraint, degree, max_degree } => {
                write!(f, "constraint {constraint} has degree {degree}, max is {max_degree}")
            }
            Self::UnsatisfiedConstraint { constraint } => {
                write!(f, "witness fails constraint {constraint}")
            }
            Self::InvalidWitness => write!(f, "witness does not satisfy the circuit"),
            Self::InvalidTraceSize { len } => write!(f, "trace size {len} is not a power of two"),
            Self::BackendNotEnabled(name) => {
                write!(f, "backend `{name}` is not compiled in; enable the feature flag")
            }
            Self::InvalidProof(what) => write!(f, "invalid proof: {what}"),
            Self::PublicInputMismatch { expected, got } => {
                write!(f, "public input count mismatch: expected {expected}, got {got}")
            }
            Self::InvalidConfiguration(what) => write!(f, "invalid configuration: {what}"),
            Self::Ark(what) => write!(f, "arkworks error: {what}"),
            Self::Wasm(what) => write!(f, "wasm error: {what}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(feature = "groth16")]
impl From<ark_groth16::ProvingError> for Error {
    fn from(e: ark_groth16::ProvingError) -> Self {
        use ark_groth16::ProvingError;
        let msg = match e {
            ProvingError::CircuitAlreadySynthesized => "circuit already synthesized",
            ProvingError::MissingEvaluationDomain => "missing evaluation domain",
            ProvingError::MissingProverKey => "missing prover key",
            ProvingError::MissingVerifierKey => "missing verifier key",
            ProvingError::UnconstrainedVariable(_) => "unconstrained variable",
            ProvingError::IndexTooBig => "index too big",
            ProvingError::IncorrectInputLength(_) => "incorrect input length",
            ProvingError::NonCompositeField => "non-composite field",
        };
        Self::Ark(msg)
    }
}

#[cfg(feature = "groth16")]
impl From<ark_groth16::Error> for Error {
    fn from(e: ark_groth16::Error) -> Self {
        use ark_groth16::Error as ArkError;
        let msg = match e {
            ArkError::PolynomialDegreeTooLarge => "polynomial degree too large",
            ArkError::MissingVerifierKey => "missing verifier key",
            ArkError::MalformedVerifyingKey => "malformed verifying key",
            ArkError::PreprocessingError => "preprocessing error",
            ArkError::CircuitAlreadySynthesized => "circuit already synthesized",
            ArkError::IncorrectInputLength(_) => "incorrect input length",
            ArkError::UnconstrainedVariable(_) => "unconstrained variable",
            ArkError::IndexTooBig => "index too big",
            ArkError::NonCompositeField => "non-composite field",
            _ => "arkworks groth16 error",
        };
        Self::Ark(msg)
    }
}

#[cfg(feature = "groth16")]
impl From<ark_groth16::VerificationError> for Error {
    fn from(e: ark_groth16::VerificationError) -> Self {
        use ark_groth16::VerificationError;
        let msg = match e {
            VerificationError::MalformedVerifyingKey => "malformed verifying key",
            VerificationError::IndexOutOfBounds => "index out of bounds",
            VerificationError::IncorrectInputLength(_) => "incorrect input length",
        };
        Self::Ark(msg)
    }
}
