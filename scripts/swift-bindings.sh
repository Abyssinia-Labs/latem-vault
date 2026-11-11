#!/bin/sh
# Builds openvault-ffi, generates its Swift bindings into target/swift, and runs a Swift program
# with them against a service in a temporary directory (scripts/ffi-smoke.swift). The Mac app's
# OpenVaultKit is built from the same library and bindings. macOS only.
set -eu
cd "$(dirname "$0")/.."

# The oldest macOS the app runs on (the MacBook's 26), for the C inside the library too. A target
# directory of its own, so this doesn't rebuild what other builds keep in target/.
export MACOSX_DEPLOYMENT_TARGET=26.0
export CARGO_TARGET_DIR=target/ffi
build=$CARGO_TARGET_DIR/debug
out=target/swift
cargo build --locked -p openvault-cli -p openvault-ffi
rm -rf "$out"
cargo run --locked -q -p openvault-ffi --bin uniffi-bindgen -- generate \
    --library "$build/libopenvault_ffi.dylib" --language swift --out-dir "$out"
# Top-level code has to be in main.swift. The static library, so the program doesn't depend on
# where the dylib is.
cp scripts/ffi-smoke.swift "$out/main.swift"
swiftc -module-name smoke -target "arm64-apple-macos$MACOSX_DEPLOYMENT_TARGET" \
    -Xcc -fmodule-map-file="$out/openvault_ffiFFI.modulemap" -I "$out" \
    "$out/openvault_ffi.swift" "$out/main.swift" \
    "$build/libopenvault_ffi.a" \
    -framework Security -framework SystemConfiguration -framework CoreFoundation \
    -framework LocalAuthentication \
    -o "$out/smoke"

home=$(mktemp -d)
cleanup() {
    [ -n "${service:-}" ] && kill "$service" 2>/dev/null && wait "$service" 2>/dev/null
    rm -rf "$home"
}
trap cleanup EXIT
export OPENVAULT_HOME="$home"
openvault=$build/openvault
# The phrase's numbered words run down columns, so each number is followed by its word.
phrase=$("$openvault" init --keys software --name smoke </dev/null | awk '
    { for (i = 1; i < NF; i++) if ($i ~ /^[0-9]+\.$/) word[$i + 0] = $(i + 1) }
    END { for (n = 1; n <= 24; n++) printf "%s%s", word[n], (n < 24 ? " " : "") }')
"$openvault" service </dev/null >"$home/service.log" 2>&1 &
service=$!
tries=0
until [ -S "$home/service.sock" ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 200 ]; then
        cat "$home/service.log" >&2
        exit 1
    fi
    sleep 0.1
done
version=$(cargo pkgid -p openvault-ffi | sed 's/.*[@#]//')
"$out/smoke" "$home" "$phrase" "$version"
