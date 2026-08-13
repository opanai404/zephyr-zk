# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-08-13

Initial release: the constraint toolkit and both backends land together
so the IR↔backend seam is exercised end-to-end from day one.

### Added

- **DSL and IR**
  - `CircuitBuilder`: witnesses, constants, `mul`/`add`/`sub`/`scale`,
    `assert_eq`/`assert_zero`/`assert_boolean`/`assert_public`,
    stable circuit naming.
  - Sparse rank-1 `Circuit<F>` with `check_witness`,
    `split_witness`, `max_degree`, and public-input layout.
  - Dataflow witness solver `Circuit::solve_witness` with automatic
    constant pre-fill and contradiction detection.
- **Gadgets**
  - `range`: tight binary-decomposition range checks (`RangeChecked`
    exposes bit handles for witness generation).
  - `poseidon`: Hades width-3 permutation (8 full + 57 partial
    rounds, `x³` S-box) with deterministic round constants, plus a
    native reference implementation for off-chain witnesses.
  - `merkle`: `verify_path`/`assert_path` over the Poseidon
    compression function.
  - `ec`: short-Weierstrass `add`/`double`/`scalar_mul` and checked
    inversion.
- **Backends**
  - `stark` (Plonky3-style, transparent): univariate R1CS STARK with
    coset quotienting, SHA-256 Merkle commitments, and FRI
    low-degree testing.
  - `groth16` (arkworks, BN254): `Groth16Backend` with deterministic
    setup and a verifier-only `Groth16Verifier` handle.
  - `Prover`/`Verifier` traits and the `prove_and_verify` smoke
    helper.
- **WASM bindings** (`wasm` feature): `prove_demo`, `verify_demo`,
  `verify_stark`, `verify_groth16` via wasm-bindgen.
- **Tooling**
  - Criterion benches for circuit construction and STARK
    prove/verify.
  - proptest property tests for the range gadget.
  - CI matrix (Linux/macOS/Windows) with `clippy`, `fmt`, and
    typecheck jobs.
  - Docker build, `Makefile`, and `.editorconfig`.
- **Docs**: architecture overview, getting-started guide, DSL design
  spec, and API reference.

### Fixed

- Nothing yet — this is the initial release.
