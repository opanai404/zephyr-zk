# Security Policy

Zephyr is cryptographic software. If you believe you have found a
security vulnerability in the proving pipeline, the DSL, or the
backend code, please report it privately and responsibly.

## Reporting a vulnerability

**Do not open a public issue.** Instead, email the maintainer at
`security@zephyr-zk.dev` (or, if you have one, open a private advisory
via the GitHub "Security" tab on the repository).

Include, if possible:

- the affected crate/module and version,
- a minimal circuit or witness that triggers the issue,
- the expected vs. observed behavior,
- whether the issue affects proof soundness, proof zero-knowledge, or
  availability.

You will receive an acknowledgment within 72 hours and a triage
assessment within a week. We will keep you updated as the fix lands.

## Scope

In scope:

- the constraint IR and witness solver (`src/circuit.rs`, `src/dsl.rs`),
- the gadget library (`src/gadgets/`),
- the STARK and Groth16 backends (`src/backends/`),
- the WASM bindings (`src/wasm/`).

Out of scope (report upstream):

- bugs in `arkworks-rs`, `ark-groth16`, or `ark-ff` themselves,
- general Rust toolchain issues,
- the upstream SHA-256 / arkworks hash implementations used for
  commitments.

## Supported versions

| Version | Support |
|---|---|
| 0.1.x | Active; security fixes prioritized |
| < 0.1 | Unsupported |

## Disclosure

We will disclose confirmed vulnerabilities after a fix is released,
with credit to the reporter unless they request otherwise. We ask that
you give us a reasonable window before any public disclosure.
