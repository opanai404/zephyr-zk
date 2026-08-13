# Zephyr · The DSL Design

This document specifies the contracts that make the DSL safe to build
on: variable allocation, constraint shape, the witness solver, and the
rules gadgets must follow.

## Variables

A variable is a `usize` index into the circuit's assignment vector.
Index `0` is reserved for the constant `1` (`circuit::ONE`). Every
other index names either a witness, a constant introduced by
`constant`, or an intermediate allocated by a gadget.

The builder never reads values. All assignment happens at witness time
through `Circuit::solve_witness`, which means a circuit description is
pure and reusable across backends.

## Constraint shape

Every constraint is dense R1CS:

```text
(Σ aᵢ·xᵢ) · (Σ bᵢ·xᵢ) = (Σ cᵢ·xᵢ)      x₀ = 1
```

Primitive operations and their canonical encodings:

| Operation | Encoding | Output variable lives on |
|---|---|---|
| `mul(x, y)` | `(x)·(y) = (out)` | `c` side |
| `add(x, k·y)` | `(1)·(out) = (x, k·y)` | `b` side |
| `constant(v)` | `(1)·(x) = (v)` | check (no output) |
| `assert_eq(x, y)` | `(x)·(1) = (y)` | check |
| `assert_boolean(x)` | `(x)·(x−1) = (0)` | check |

The `b`-side placement of `add` output is a deliberate choice: it keeps
`a` constant so the witness solver can discharge the constraint in one
step, and it matches how arkworks linear combinations are built.

## The witness solver

`Circuit::solve_witness(partial)` walks constraints in emission order.
A constraint is *discharged* when at most one of its referenced
variables is undetermined:

- 0 undetermined → verify `A·B == C`;
- exactly 1 on the `c` side → `out = (A·B − C_known)/k`;
- exactly 1 on the `a` side → `out = (C/B − A_known)/k`;
- exactly 1 on the `b` side → `out = (C/A − B_known)/k`;
- otherwise → the circuit is not a dataflow circuit; return `None`.

Constants are pre-filled, so `solve_witness(&[])` works on any
constant-only circuit. A partial assignment that contradicts a
constant is rejected.

**Gadget rule:** every constraint a gadget emits must discharge in
this order. In practice this means "introduce intermediate variables in
dependency order and never re-read a variable you have not yet
constrained."

## The `constant` subtlety

`constant(1)` returns `ONE` and emits no constraint; any other constant
allocates a fresh variable *and* a check constraint pinning its value.
This keeps the R1CS fully explicit (every non-trivial value is
constrained), at the cost of a constant-variable per constant — a
trade-off the STARK backend's quotient handles cleanly.

## Public inputs

`assert_public(x)` records `x` in declaration order; `split_witness`
extracts them, and every backend requires `public.len() ==
num_public_inputs()`. The Groth16 adapter maps input `0` to `1`, then
public variables in declaration order, then auxiliaries — matching the
order `Groth16::verify` expects.

## Extension surface

Gadgets should expose **all** handles a witness generator needs. The
range gadget returns `RangeChecked { value, bits }` precisely so
callers can supply bit values; the Poseidon gadget allocates every
intermediate state element so Merkle-path witnesses can be derived.
