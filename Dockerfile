# ─────────────────────────────────────────────────────────────
# ZEPHYR · builder image
# SPDX-License-Identifier: MIT
# ─────────────────────────────────────────────────────────────

# Build stage: compile the library, examples, and WASM bindings.
FROM rust:1.90-bookworm AS builder
WORKDIR /build

RUN rustup target add wasm32-unknown-unknown

COPY Cargo.toml rust-toolchain.toml ./
COPY src ./src
COPY benches ./benches
COPY examples ./examples
COPY tests ./tests

# Fetch dependencies without our code first (maximizes cache reuse).
RUN cargo fetch

# Full build with every feature.
RUN cargo build --release --features wasm
RUN cargo build --release --examples --all-features

# Final image: statically-linked tool and examples.
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /build/target/release/examples/range_proof /usr/local/bin/range_proof
COPY --from=builder /build/target/release/examples/merkle_membership /usr/local/bin/merkle_membership

ENTRYPOINT ["/usr/local/bin/range_proof"]
