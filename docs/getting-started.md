# Zephyr · Getting Started

This guide walks through installing, building, and running your first
proof. It assumes Rust 1.90+ (edition 2024) and a nightly-free
toolchain.

## Prerequisites

```text
rustup toolchain install 1.90.0 --profile minimal
rustup override set 1.90.0
```

For the browser bindings you additionally need the wasm target:

```text
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

## Build and test

```text
# library + default (STARK) backend
cargo build

# everything, including Groth16 and WASM
cargo build --features wasm

# unit + integration tests (proptest included in tests/range.rs)
cargo test

# micro-benchmarks
cargo bench --bench circuits
cargo bench --bench stark

# lint + fmt
cargo clippy --all-features -- -D warnings
cargo fmt --check
```

The `Makefile` wraps all of these as `make build`, `make test`, `make
lint`, `make fmt`, `make clean`.

## Your first circuit

`examples/range_proof.rs` is the canonical walkthrough. In five
minutes you can write the same thing by hand:

```rust
use zephyr_zk::backends::stark::StarkBackend;
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;
use zephyr_zk::gadgets::range::range16;

fn main() {
    // 1. Author: a 16-bit secret whose square is public.
    let mut b = CircuitBuilder::<Fp>::new();
    let x = b.witness_named("secret.x");
    let rc = range16(&mut b, x);
    let y = b.mul(x, x, "secret.x²");
    b.assert_public(y);
    let circuit = b.build("square16");

    // 2. Witness: supply the secret; the solver fills the bits.
    let mut partial = vec![(x, Fp::from(1234u64))];
    for (i, &bit) in rc.bits.iter().enumerate() {
        partial.push((bit, Fp::from(((1234u64 >> i) & 1) as u64)));
    }
    let witness = circuit.solve_witness(&partial).expect("x < 2^16");
    assert!(circuit.check_witness(&witness).unwrap());

    // 3. Prove (transparent, no setup) and verify.
    let backend = StarkBackend::new();
    let proof = backend.prove(&circuit, &witness).unwrap();
    let (public, _) = circuit.split_witness(&witness).unwrap();
    assert!(backend.verify(&circuit, &public, &proof).unwrap());
    println!("y = {} is a public square, proven ✓", public[0]);
}
```

Run it with `cargo run --release --example range_proof`.

## Using the Merkle gadget

`examples/merkle_membership.rs` builds a height-4 tree over leaves
`0..16`, derives an inclusion witness for leaf 9, and constrains a
membership proof. The compression function is the crate's Poseidon
gadget; the native reference permutation (`native_permute`) generates
off-chain witnesses that the circuit then checks.

## Writing a gadget

A gadget is just a function that consumes `CircuitBuilder` and returns
handles:

```rust
use zephyr_zk::dsl::CircuitBuilder;
use zephyr_zk::field::Fp;

/// Constrain that `x` is either 0 or 1 and return a handle for it.
pub fn my_boolean(b: &mut CircuitBuilder<Fp>, x: usize) -> usize {
    b.assert_boolean(x, "boolean");
    x
}
```

See `src/gadgets/range.rs` for the archetype: it allocates bits,
asserts each is boolean, re-assembles the weighted sum, and returns
both the value and the bit handles for witness generation.

## Choosing a backend

| Backend | Setup | Proof size | Verify | Use when |
|---|---|---|---|---|
| `StarkBackend` | transparent | ~tens of KB | fast, field-native | browser/CI, no trusted setup |
| `Groth16Backend` | per-circuit trusted | ~128 B | two pairings | tiny proofs on-chain |

Enable `groth16` and `wasm` via Cargo features; `default = ["stark"]`.

## Next steps

- [Architecture](architecture.md) — how the layers fit together.
- [DSL design](design/dsl.md) — the builder and solver contracts.
- [API reference](api/reference.md) — the public surface.
