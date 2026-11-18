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

# The tests whose devices find each other with mDNS. A GitHub macOS runner can't send multicast:
# macOS asks a person before a program may use the local network, nobody is there to answer, and
# every send fails with "No route to host". So ci.yml's macOS job sets LATEM_VAULT_CI_NO_MULTICAST
# and skips these. The Linux job runs them, and so does this script on a Mac.
needs_multicast="
    a_device_joins_with_a_code
    approve_goes_through_the_service
    collections_says_when_this_device_may_read_none
    devices_join_through_the_service
    files_reach_the_other_devices
    scopes_change_with_an_admin_signature
    services_sync_a_joined_device
    endpoints_find_each_other
    endpoints_under_other_service_names_stay_apart
    discovery_starts_again_after_it_stops
"

macos() {
    echo "== macOS: rustfmt, clippy, tests, Swift bindings"
    cargo fmt --all --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
    set --
    if [ -n "${LATEM_VAULT_CI_NO_MULTICAST:-}" ]; then
        echo "== No multicast here: skipping the tests that need it:" $needs_multicast
        for name in $needs_multicast; do
            set -- "$@" --skip "$name"
        done
    fi
    # --no-fail-fast, so one run names every failing test rather than the first binary's.
    cargo test --workspace --locked --no-fail-fast -- "$@"
    cargo test --locked --no-fail-fast -p latem-vault-cli -p latem-vault-service --all-features -- "$@"
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
