# OpenVault

OpenVault keeps secrets, variables and files encrypted on your own devices and syncs them between the devices you enroll. A new device joins with one approval on an admin device and gets only the collections it is scoped to. Devices reach each other on the LAN and over the internet, and nothing you own is stored on a server.

This repository holds the open-source core: the Rust service and CLI, the coordinator you can host yourself, and the local web UI for Linux and Windows.

## Status

Milestones M1, one device, and M2, devices on the same network, are done: devices join with a 6-digit code, sync directly over iroh, and can be revoked, and latem reads its builds' secrets from OpenVault. M3, reaching devices from outside the network, has its first stage built and paused: it is behind the cargo feature `coordinator`, off by default, so devices find each other on the local network only. The design is in [docs/design.md](docs/design.md), and the formats are in [docs/spec](docs/spec).

## Try it

```sh
cargo install --locked --path crates/cli         # the dependency versions in Cargo.lock

openvault init                                   # shows the recovery phrase once; asks for a passphrase without a Secure Enclave
openvault collections create latem               # Touch ID; the recovery phrase without a Secure Enclave
openvault set latem/prod/SENTRY_DSN --secret     # value from stdin; hidden when typed
openvault set latem/prod/REGION --var
openvault list latem
openvault get latem/prod/SENTRY_DSN
openvault run --collection latem --env prod -- ./deploy.sh
openvault devices                                # this vault's devices, and which are on this network
```

To add another device on the same network, run `openvault join` on it and `openvault approve` on the MacBook:

```sh
openvault join                                   # on the new device: shows a 6-digit code
openvault approve --read latem                   # on the MacBook: the code, a review, then Touch ID
```

The code and the review make sure the device you approve is the one in front of you. The new device gets the vault's membership log and the keys for the collections it may read. With `openvault service` running on both, their secrets follow within seconds, and so does every later change.

To change what a device may do with a collection, such as one created after it joined:

```sh
openvault scope Desktop ssh read                 # none, hold, read or write; Touch ID
```

Taking away `read` or `write` gives the collection a new key, as revoking does.

To remove a device, such as one that was lost:

```sh
openvault devices revoke Desktop                 # a review, then Touch ID
```

It stops syncing with the vault, and each collection it could read gets a new key, so nothing written afterwards reaches it. It keeps what it has already read, so the command ends with the secrets to change where they were issued.

`openvault run` passes every entry under `prod/` to the command as an environment variable, so `prod/SENTRY_DSN` becomes `SENTRY_DSN`. `--prefix` puts a prefix in front of every name. latem reads its secrets from `LATEM_SECRET_<NAME>`, so it runs like this:

```sh
openvault run --collection latem --env prod --prefix LATEM_SECRET_ -- latem …
```

To bring in a whole `NAME=value` file, such as latem's `secrets.env`:

```sh
openvault import-env ~/.latem/secrets.env --collection latem --env prod --var REGION
```

With `-` as the file it reads stdin, so the file can come straight from another machine without a plaintext copy landing on this one:

```sh
ssh mini 'cat ~/.latem/secrets.env' | openvault import-env - --collection latem --env prod
```

Every name becomes a secret unless it is given with `--var`. The file is read as latem reads it: no `export`, no `$` expansion, and in double quotes only `\n`, `\r`, `\t`, `\\` and `\"`. Nothing is written if any line fails to parse, or if a name already exists (unless you pass `--overwrite`).

`openvault service` holds the vault open until Ctrl-C. It finds this vault's other devices on the local network with mDNS, without relays or anything outside the network, and other commands go through it, so a passphrase is typed once rather than for every command. Without it, each command opens the vault itself.

The vault and this device's key file are kept in `~/.openvault`; set `OPENVAULT_HOME` to use another directory. On a Mac with a Secure Enclave, the device keys stay in it. Elsewhere they are kept in the key file, which only you can read, sealed with a passphrase that every command asks for on the terminal. `init --keys software` leaves the passphrase out, for a device that opens the vault with nobody there to type one, such as a container.

## Development

There's no hosted CI while the repository is private. Before anything lands on `main`, run:

```sh
scripts/ci.sh
```

It runs rustfmt, then clippy and the tests on this Mac and in a Linux container, which needs Docker. `scripts/ci.sh macos` or `scripts/ci.sh linux` runs one side only.

### Versions

Each build knows its version and the commit it was built from. `openvault --version` prints them, as in `openvault 0.2.0 (8edda7f)`, and `openvault service` logs the same line when it starts. A build made outside a git checkout shows `unknown` for the commit. One made with uncommitted changes shows the commit those changes are on.

Until 1.0, versions are `0.MINOR.PATCH`:
- **MINOR** goes up when the store version or a protocol changes, in the same commit. An older build refuses a newer store, and can't speak a newer protocol, so devices on the same minor version can share a vault. Two tests fail until both are changed together. 0.2 is M2: store version 6, `openvault/sync/1` and `openvault/join/1`. 0.3 adds M3's `openvault/coord/1`.
- **PATCH** goes up for any other release.

Each release is tagged on `main`, as `v0.2.0`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
