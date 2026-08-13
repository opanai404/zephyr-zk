# ─────────────────────────────────────────────────────────────
# ZEPHYR · development targets
# SPDX-License-Identifier: MIT
# ─────────────────────────────────────────────────────────────

RUSTFLAGS ?=

.PHONY: all build test lint fmt clean bench docs wasm check

all: build

## Compile the library and all examples.
build:
	cargo build --all-features
	cargo build --examples --all-features

## Run the full test suite (unit + integration).
test:
	cargo test --all-features

## Lint: clippy (deny warnings) + fmt check.
lint:
	cargo clippy --all-features --all-targets -- -D warnings
	cargo fmt --check

## Format the tree in place.
fmt:
	cargo fmt --all

## Benchmarks.
bench:
	cargo bench --bench circuits
	cargo bench --bench stark
	cargo bench --features groth16 --bench groth16

## Documentation.
docs:
	cargo doc --all-features --no-deps

## Check that the WASM target builds.
wasm:
	cargo build --features wasm --target wasm32-unknown-unknown --release

## Smoke: prove + verify the range example end-to-end.
check: build
	cargo run --release --example range_proof

## Remove build artifacts.
clean:
	cargo clean
	rm -rf target pkg
