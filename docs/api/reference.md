# Zephyr · API Reference (v0.1)

This is the stable public surface. Everything listed here is exported
from the crate root or a public module; everything else is internal.

## Crate root

| Item | Kind | Notes |
|---|---|---|
| `Fp` | type alias | `ark_bn254::Fr`, the default circuit field |
| `Circuit<F>` | struct | immutable R1CS (`src/circuit.rs`) |
| `Constraint<F>` | struct | one `(a·b = c)` record |
| `Variable` / `Witness` | re-exports | doc aliases for handles |
| `Error` | enum | the single error type (`src/error.rs`) |

## Field layer (`zephyr_zk::field`)

- `Fp` — the BN254 scalar field.
- `to_bytes(x) / from_bytes::<F>(bytes)` — canonical little-endian
  encoding and its inverse.
- `SeedRng::new(label)` — deterministic PRNG; drives round constants,
  FRI challenges, and (by design) Groth16 setup.
- `sample(label)` — deterministic field element from a label.

## DSL (`zephyr_zk::dsl`)

`CircuitBuilder<F>`:

- `new()`, `witness()`, `witness_named(name)`, `bind(name, var)`
- `constant(value)` — returns `ONE` for `1`, else a pinned variable.
- `add(x, y, label)`, `sub(x, y, label)`, `mul(x, y, label)`,
  `scale(x, k, label)`, `add_scaled(x, y, k, label)`
- `assert_eq(x, y, label)`, `assert_zero(x, label)`,
  `assert_boolean(x, label)`, `assert_public(x)`
- `num_constraints()`, `num_variables()`, `build(name)`,
  `build_checked(name, witness)`

## Circuit IR (`zephyr_zk::circuit`)

- `ONE` — the reserved constant-one variable.
- `Circuit::constraints()`, `num_variables()`, `public_inputs()`,
  `num_public_inputs()`, `name()`, `max_degree()`
- `Circuit::check_witness(w)`, `check_public_inputs(public, w)`,
  `split_witness(w)`, `solve_witness(partial)`, `constant_value(var)`

## Gadgets

### `zephyr_zk::gadgets::range`

- `range_check(b, x, bits) -> RangeChecked<F>` — constrain `x < 2^bits`.
- `range16(b, x) -> RangeChecked<F>` — the `bits = 16` convenience.
- `RangeChecked { value, bits }` — output and bit handles (LSB first).

### `zephyr_zk::gadgets::poseidon`

- `permute(b, state) -> [usize; 3]` — Hades width-3 permutation as
  constraints.
- `hash_pair(b, a, bv) -> usize` — `H(a, b) = permute(a, b, 0)[0]`.
- `native_permute(state) -> [Fp; 3]` — reference implementation for
  witness generation.
- `POSEIDON_PARAMS`, `WIDTH` — `(3, 8, 57)`.

### `zephyr_zk::gadgets::merkle`

- `verify_path(b, leaf, siblings, bits) -> usize` — recomputed root.
- `assert_path(b, root, leaf, siblings, bits)` — pin the root.

### `zephyr_zk::gadgets::ec`

- `Point { x, y }` — affine point as variable handles.
- `default_curve()` — `y² = x³ + 3` over the scalar field.
- `assert_on_curve(b, curve, p, label)`
- `invert(b, z, label) -> usize` — checked field inversion.
- `add(b, curve, p, q, label) -> Result<Point>`
- `double(b, curve, p, label) -> Result<Point>`
- `scalar_mul(b, curve, k, p, bits, label) -> Result<Point>`

## Backends (`zephyr_zk::backends`)

- `BackendId::{Stark, Groth16}`, `Proof<F> { backend, public_inputs,
  bytes }`
- `trait Prover<F> { prove(&self, circuit, witness) -> Result<Proof> }`
- `trait Verifier<F> { verify(&self, circuit, public, proof) ->
  Result<bool> }`
- `prove_and_verify(prover, verifier, circuit, witness)`

### `zephyr_zk::backends::stark` (feature `stark`)

- `StarkBackend { config }`, `StarkConfig` with defaults.
- `StarkPayload`, `FriProof`, `FriQuery` — serialized via
  `ark_serialize`.

### `zephyr_zk::backends::groth16` (feature `groth16`)

- `Groth16Backend { pk, vk }` — `setup(circuit, label)`,
  `prove`, `verify`, `vk_bytes()`.
- `Groth16Verifier` — verifier-only handle from `vk_bytes`.
- `R1CSAdapter` — the arkworks `ConstraintSynthesizer` bridge.

## WASM (`zephyr_zk::wasm`, feature `wasm`)

- `prove_demo(secret) -> Result<Vec<u8>>` — framed demo proof.
- `verify_demo(frame) -> Result<bool>`
- `verify_stark(payload, public) -> Result<bool>`
- `verify_groth16(proof, public, vk) -> Result<bool>`

All return `Result<_, JsValue>`; errors stringify the `Error` enum.
