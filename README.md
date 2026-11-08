# OpenVault

OpenVault keeps secrets, variables and files encrypted on your own devices and syncs them between the devices you enroll. A new device joins with one approval on an admin device and gets only the collections it is scoped to. Devices reach each other on the LAN and over the internet, and nothing you own is stored on a server.

This repository holds the open-source core: the Rust service and CLI, the coordinator you can host yourself, and the local web UI for Linux and Windows.

## Status

Milestone M1, one device, is done: secrets and variables work on a single machine, with no sync yet. Creating a collection already asks for Touch ID, which was planned for M2. Next is M2: devices joining over the LAN and syncing. The design is in [docs/design.md](docs/design.md), and the formats are in [docs/spec](docs/spec).

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

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
