#!/usr/bin/env bash
#
# Build certifi-cli inside a Docker container so users without a local Rust
# toolchain can still produce a binary. Output lands in dist/cli/<target>/.
#
# Usage:
#   scripts/build-cli.sh                  # builds linux-amd64 (default)
#   scripts/build-cli.sh linux-amd64
#   scripts/build-cli.sh linux-arm64
#
# Cross-builds use Docker's --platform flag. Running a non-native platform
# uses qemu emulation and is ~5-10x slower than a native build.
#
# This script can NOT produce macOS-native binaries — Docker on macOS runs
# Linux, so the output is always a Linux binary. For native macOS builds,
# install rustup and run:
#   cargo install --path crates/certifi-client
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET="${1:-linux-amd64}"

case "$TARGET" in
  linux-amd64) PLATFORM="linux/amd64" ;;
  linux-arm64) PLATFORM="linux/arm64" ;;
  -h|--help|help)
    sed -n '3,18p' "$0" | sed 's/^# //; s/^#//'
    exit 0
    ;;
  *)
    echo "Unknown target: $TARGET" >&2
    echo "Usage: $0 [linux-amd64|linux-arm64]" >&2
    exit 2
    ;;
esac

OUT_DIR="dist/cli/$TARGET"
mkdir -p "$OUT_DIR"

echo ">>> Building certifi-cli for $TARGET ($PLATFORM)"
echo "    (first run downloads the Rust image + crates; subsequent runs are fast)"

# A named volume keeps the crates.io registry cache between runs so we don't
# re-download dependencies every invocation.
docker run --rm \
  --platform="$PLATFORM" \
  -v "$(pwd):/build" \
  -v "certifi-cargo-cache:/usr/local/cargo/registry" \
  -w /build \
  rust:1.95.0-slim-bookworm \
  sh -c 'apt-get update >/dev/null && \
         apt-get install -y --no-install-recommends pkg-config libssl-dev >/dev/null && \
         cargo build --release -p certifi-client --bin certifi-cli'

# The build inside the container writes to /build/target/release/, which is
# the host's target/release/ via the bind mount.
cp target/release/certifi-cli "$OUT_DIR/certifi-cli"
chmod +x "$OUT_DIR/certifi-cli"

echo ""
echo ">>> Built: $OUT_DIR/certifi-cli"
ls -lh "$OUT_DIR/certifi-cli"
file "$OUT_DIR/certifi-cli" 2>/dev/null || true
