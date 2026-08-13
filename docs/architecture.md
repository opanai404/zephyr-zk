# Zephyr · Architecture

Zephyr is a zero-knowledge proving toolkit built around one idea: **a
circuit is a rank-1 constraint system, and a proving system is a
pluggable backend.** The crate is layered so each layer is testable in
isolation and swappable without disturbing the others.

## Layer map

```text
┌──────────────────────────────────────────────────────────────────────┐
│  Layer 5 · backends        StarkBackend          Groth16Backend      │
│  "how is this proven?"     (transparent, FRI)     (pairing, trusted)  │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 4 · wasm            prove_demo / verify_stark / verify_groth16 │
│  "how does a browser      wasm-bindgen glue, 32-byte field framing   │
│   check a proof?"                                                     │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 3 · gadgets         range · poseidon · merkle · ec             │
│  "what is the statement?"  constraint recipes built on the DSL        │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 2 · dsl             CircuitBuilder: witness/constant/mul/add/  │
│  "how is it written?"      assert_eq/assert_boolean/range            │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 1 · ir              Circuit { constraints, variables, public } │
│  "what is a proof of?"     sparse R1CS: (Σaᵢxᵢ)·(Σbᵢxᵢ) = Σcᵢxᵢ        │
├──────────────────────────────────────────────────────────────────────┤
│  Layer 0 · field           ark-bn254 scalar field, SeedRng, encoding  │
│  "over what?"             deterministic domain separation            │
└──────────────────────────────────────────────────────────────────────┘
```

## Data flow

1. **Author** — a gadget or an example calls `CircuitBuilder` methods,
   which allocate variables and emit `Constraint` records into a
   `CircuitBuilderState`. The builder never reads witness values.
2. **Finalize** — `CircuitBuilder::build(name)` freezes the state into
   an immutable `Circuit<F>` with a stable name and a public-input
   layout.
3. **Witness** — `Circuit::solve_witness(partial)` runs a dataflow
   solver over the constraints (each constraint has at most one
   undetermined output variable), filling constants automatically and
   rejecting contradictory assignments. This mirrors circom's witness
   calculator.
4. **Prove** — a backend implements `Prover<F>`:
   - `StarkBackend` interpolates the witness into a trace polynomial,
     computes the quotient `H = Q/Z` on a coset, commits `f` and `H`
     to SHA-256 Merkle trees, runs FRI, and returns a `StarkPayload`.
   - `Groth16Backend` wraps the R1CS in an arkworks
     `ConstraintSynthesizer` adapter and calls
     `Groth16::<Bn254>::prove`.
5. **Verify** — a backend implements `Verifier<F>`: the STARK verifier
   checks the FRI commitment chain and the Schwartz–Zippel identity
   `A(r)·B(r) = C(r) + Z(r)·H(r)`; the Groth16 verifier runs two
   pairings. Both reject wrong-backend or mismatched-public proofs.

## Key design decisions

- **R1CS as the IR.** Rank-1 constraints are the lingua franca of ZK:
  arkworks consumes them natively for Groth16, and the STARK backend
  lifts them into a univariate AIR without a change of formalism.
- **Assignment at prove time.** The DSL is value-free, so a circuit is
  a pure description — serializable, reusable across backends, and
  auditable without a witness.
- **Deterministic randomness.** `SeedRng` derives round constants, MDS
  matrices, FRI challenges, and setup material from domain-separated
  labels. Two parties always agree on setup material; the Groth16
  backend is a deliberate (documented) departure from fresh setup
  entropy for reproducibility.
- **No binary-field tower.** The STARK runs over the BN254 scalar
  field with a native (non-native-arithmetic) Hades permutation, the
  Plonky3-style choice rather than the binary-field Plonky3 choice.

## The STARK construction (in detail)

Let `f` interpolate the witness over the `N`-th roots of unity. For a
constraint with support sets `Sₐ, S_b, S_c`:

```text
A(x) = Σ_{j∈Sₐ} aⱼ·f(x·ωʲ)     B(x) = Σ_{j∈S_b} bⱼ·f(x·ωʲ)
C(x) = Σ_{j∈S_c} cⱼ·f(x·ωʲ)    Z(x) = xᴺ − 1
```

The constraint holds iff `Q = A·B − C` vanishes on the trace domain,
i.e. `Q = Z·H`. The prover:

- computes `H` by pointwise division on the coset `3·⟨ω⟩` (where `Z ≠ 0`),
- commits evaluations of `f` and `H` to Merkle trees,
- runs FRI on `H` to certify its degree bound, folding with
  `g(x²) = (f(x)+f(−x))/2 + α·(f(x)−f(−x))/(2x)`.

The verifier checks the Merkle paths, re-folds the queried pairs, and
samples one point `r` to check the quotient identity — one
Schwartz–Zippel test plus the FRI low-degree test. Proof size is
`O(λ·log²N)` and verification is `O(λ·log N)` field ops.

## Cross-cutting: errors and serialization

All failures collapse into a single `Error` enum (`src/error.rs`) so
`?` flows cleanly from DSL → gadgets → backends → WASM. Backend
payloads use `ark_serialize` canonical encoding; the WASM layer frames
public inputs as 32-byte compressed field elements so proofs cross the
JS boundary as plain byte arrays.
