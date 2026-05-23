FROM rust:1.95.0-slim-bookworm AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# ── Dependency cache layer ────────────────────────────────────────────────────
# Copy only the workspace + crate manifests, stub out sources, and do a release
# build of certifi-server so the heavy dependency tree is cached in its own
# layer. The stub files for the other workspace members must exist because
# Cargo resolves the whole workspace even when building a single member.
COPY Cargo.toml Cargo.lock ./
COPY crates/certifi-server/Cargo.toml ./crates/certifi-server/
COPY crates/certifi-types/Cargo.toml  ./crates/certifi-types/
COPY crates/certifi-client/Cargo.toml ./crates/certifi-client/
RUN mkdir -p crates/certifi-server/src \
             crates/certifi-types/src \
             crates/certifi-client/src/bin && \
    echo 'fn main() {}' > crates/certifi-server/src/main.rs && \
    : > crates/certifi-types/src/lib.rs && \
    : > crates/certifi-client/src/lib.rs && \
    echo 'fn main() {}' > crates/certifi-client/src/bin/cli.rs && \
    cargo build --release -p certifi-server && \
    rm -rf crates/certifi-server/src crates/certifi-types/src

# ── Real build ────────────────────────────────────────────────────────────────
# Both the server AND the types crate's real sources must be in place before
# the final build — the server depends on certifi-types, so an empty stub
# lib.rs here means `use certifi_types::CertificateView` fails to resolve.
COPY crates/certifi-types/src  ./crates/certifi-types/src
COPY crates/certifi-server/src ./crates/certifi-server/src
# docs/ is `include_str!`'d into the binary so the web admin's Docs page and
# `certifi-cli docs` can serve the same markdown that's checked into the repo,
# with no runtime filesystem dependency.
COPY docs                      ./docs
RUN touch crates/certifi-types/src/lib.rs \
          crates/certifi-server/src/main.rs && \
    cargo build --release -p certifi-server

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:13-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/certifi /usr/local/bin/certifi

RUN mkdir -p /data

ENV DATA_DIR=/data \
    LISTEN_ADDR=0.0.0.0:8080

EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/certifi"]
