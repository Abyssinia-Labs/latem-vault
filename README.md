# OpenVault

OpenVault keeps secrets, variables and files encrypted on your own devices and syncs them between the devices you enroll. A new device joins with one approval on an admin device and gets only the collections it is scoped to. Devices reach each other on the LAN and over the internet, and nothing you own is stored on a server.

This repository holds the open-source core: the Rust service and CLI, the coordinator you can host yourself, and the local web UI for Linux and Windows.

## Status

Milestone M1, one device: secrets and variables work on a single machine, with no sync yet. Devices joining and syncing come in M2. The design is in [docs/design.md](docs/design.md), and the formats are in [docs/spec](docs/spec).

## Try it

```sh
cargo install --path crates/cli

openvault init                                   # shows the recovery phrase once
openvault collections create latem
openvault set latem/prod/SENTRY_DSN --secret     # value from stdin; hidden when typed
openvault set latem/prod/REGION --var
openvault list latem
openvault get latem/prod/SENTRY_DSN
openvault run --collection latem --env prod -- ./deploy.sh
```

`openvault run` passes every entry under `prod/` to the command as an environment variable, so `prod/SENTRY_DSN` becomes `SENTRY_DSN`.

The vault and this device's key file are kept in `~/.openvault`; set `OPENVAULT_HOME` to use another directory. On a Mac with a Secure Enclave, the device keys stay in it. Elsewhere they are kept in the key file, which only you can read.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
