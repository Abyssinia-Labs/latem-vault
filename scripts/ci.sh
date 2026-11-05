#!/bin/sh
# The checks to pass before anything lands on main: rustfmt, then clippy and the tests on this
# Mac and in a Linux container. There's no hosted CI until the repo is public.
#
#   scripts/ci.sh          both
#   scripts/ci.sh macos    this Mac only
#   scripts/ci.sh linux    the Linux container only (needs Docker)
set -eu
cd "$(dirname "$0")/.."

# The Linux image runs the same Rust as this Mac, so both see the same lints.
rust_version=$(rustc --version | cut -d' ' -f2)

macos() {
    echo "== macOS: rustfmt, clippy, tests"
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --workspace --locked
}

linux() {
    echo "== Linux (rust:$rust_version-slim in Docker): clippy, tests"
    # The checkout is mounted read-only. Builds and downloaded crates live in Docker volumes,
    # so they last between runs and never touch this Mac's target directory.
    mkdir -p target
    docker run --rm \
        --volume "$PWD:/src:ro" \
        --volume openvault-ci-target:/src/target \
        --volume openvault-ci-registry:/usr/local/cargo/registry \
        --workdir /src \
        "rust:$rust_version-slim" \
        sh -euc '
            rustup component add clippy
            cargo clippy --workspace --all-targets --locked -- -D warnings
            cargo test --workspace --locked
        '
}

case "${1:-all}" in
    macos) macos ;;
    linux) linux ;;
    all) macos && linux ;;
    *)
        echo "usage: $0 [macos|linux]" >&2
        exit 2
        ;;
esac
echo "== All checks passed"
