#!/bin/sh
# The checks to pass before anything lands on main: rustfmt, then clippy and the tests on this
# Mac and in a Linux container, as built by default and with every feature (the coordinator is
# one, off by default). GitHub Actions runs the same checks (.github/workflows/ci.yml): the Linux
# ones on every pull request, and the macOS ones too on each push to main.
#
#   scripts/ci.sh             both
#   scripts/ci.sh macos       this Mac only
#   scripts/ci.sh linux       the Linux container only (needs Docker)
#   scripts/ci.sh linux-here  the Linux checks on this Linux machine, as CI and the container run them
set -eu
cd "$(dirname "$0")/.."

# The Linux image runs the same Rust as this Mac, so both see the same lints.
rust_version=$(rustc --version)
rust_version=$(echo "$rust_version" | cut -d' ' -f2)

macos() {
    echo "== macOS: rustfmt, clippy, tests, Swift bindings"
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    cargo test --workspace --locked
    cargo test --locked -p latem-vault-cli -p latem-vault-service --all-features
    # The Mac app's bindings, used from Swift against a service.
    scripts/swift-bindings.sh
}

linux_here() {
    echo "== Linux: clippy, tests"
    # latem-vault-ffi is for the Mac app, and the macOS checks test it. Linking its tests with
    # UniFFI's generator beside the others ran the container out of memory.
    cargo clippy --workspace --exclude latem-vault-ffi --all-targets --locked -- -D warnings
    cargo clippy --workspace --exclude latem-vault-ffi --all-targets --all-features --locked \
        -- -D warnings
    cargo test --workspace --exclude latem-vault-ffi --locked
    cargo test --locked -p latem-vault-cli -p latem-vault-service --all-features
}

linux() {
    echo "== Linux (rust:$rust_version-slim in Docker)"
    # The checkout is mounted read-only. Builds and downloaded crates live in Docker volumes,
    # so they last between runs and never touch this Mac's target directory.
    mkdir -p target
    docker run --rm \
        --volume "$PWD:/src:ro" \
        --volume openvault-ci-target:/src/target \
        --volume openvault-ci-registry:/usr/local/cargo/registry \
        --workdir /src \
        "rust:$rust_version-slim" \
        sh -euc 'rustup component add clippy && scripts/ci.sh linux-here'
}

case "${1:-all}" in
    macos) macos ;;
    linux) linux ;;
    linux-here) linux_here ;;
    # Not `macos && linux`: set -e is ignored inside a function called before &&, so a failed
    # check would still end in "All checks passed".
    all)
        macos
        linux
        ;;
    *)
        echo "usage: $0 [macos|linux|linux-here]" >&2
        exit 2
        ;;
esac
echo "== All checks passed"
