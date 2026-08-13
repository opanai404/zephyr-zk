# Contributing to Zephyr

Thanks for considering a contribution. This project is a zero-knowledge
toolkit; correctness of the proof pipeline matters more than feature
count, so the bar for code is deliberately high.

## Ground rules

- **No `unsafe`.** The crate is built with `#![forbid(unsafe_code)]`;
  keep it that way.
- **No crypto roll-ups.** New hashes, permutations, or field tricks
  need a reference implementation and a differential test against it
  (`native_permute` is the pattern to copy).
- **No placeholder code.** A PR that lands with `TODO: implement`,
  dead stubs, or unimplemented!() paths will be sent back.
- **Witness solver discipline.** Every gadget must discharge in
  dataflow order (see `docs/design/dsl.md`); tests must prove that.

## Development setup

```text
rustup override set 1.90.0
cargo build
cargo test
cargo clippy --all-features -- -D warnings
cargo fmt --check
make lint   # same as clippy+fmt
```

For the browser surface:

```text
rustup target add wasm32-unknown-unknown
cargo build --features wasm --target wasm32-unknown-unknown
```

## Pull request flow

1. Fork and create a branch from `main`. Name it after the work, e.g.
   `feat/keccak-gadget` or `fix/stark-blowup-overflow`.
2. Make small, reviewable commits with [conventional
   commits](https://www.conventionalcommits.org) prefixes (`feat`,
   `fix`, `docs`, `refactor`, `test`, `chore`, `bench`).
3. Add tests that exercise the new behavior both ways: the happy path
   and at least one failing-input path.
4. Run `make lint && make test` locally; CI enforces the same on
   Linux, macOS, and Windows.
5. Open the PR against `main`, describe the change and any security
   implications, and request a review.

## Reviewing

- Check the architecture docs stay accurate — the README architecture
  diagram must keep matching the real modules.
- Verify gadget constraint counts are asserted (cheap regression canary).
- Confirm new public API is documented with `///` and appears in
  `docs/api/reference.md`.

## Releasing

Version bumps go through the maintainer. `CHANGELOG.md` is updated
manually with the diff summary and a dated entry; tags follow `vX.Y.Z`.

## Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
