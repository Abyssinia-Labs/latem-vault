# latem vault

latem vault keeps secrets, variables and files encrypted on your own devices and syncs them between the devices you enroll. A new device joins with one approval on an admin device and gets only the collections it is scoped to. Devices reach each other on the LAN and over the internet, and nothing you own is stored on a server.

This repository holds the open-source core: the Rust service and CLI, the coordinator you can host yourself, and the local web UI for Linux and Windows.

## Status

Milestones M1, one device, and M2, devices on the same network, are done: devices join with a 6-digit code, sync directly over iroh, and can be revoked, and latem reads its builds' secrets from latem vault. M3, reaching devices from outside the network, has its first stage built and paused: it is behind the cargo feature `coordinator`, off by default, so devices find each other on the local network only. M4, files, is done: files are kept encrypted in chunks, imported, read, opened in their apps and passed to commands, from the CLI and the Mac app, and their chunks reach the other devices that read the collection. latem's builds sign with keystores kept as files, a documents folder opens and saves on each machine, and a revoke lists the files a device could read. The design is in [docs/design.md](docs/design.md), and the formats are in [docs/spec](docs/spec).

## Try it

```sh
brew install abyssinia-labs/tap/latem-vault      # macOS and Linux, arm64 and x86-64
```

The command is `vault`. Its full name is `latem-vault`, and `lv` is the shortest form: all three run the same binary, and Homebrew and the release archives put in all three. HashiCorp Vault has a `vault` command too; where both are installed, `lv` is always latem vault.

Each [release](https://github.com/Abyssinia-Labs/latem-vault/releases) also has the binaries as archives, with a checksums file signed by [latem-vault.pub](latem-vault.pub) ([docs/release.md](docs/release.md)). To build from this checkout instead, `cargo install --locked --path crates/cli`, which puts in `latem-vault` only; `ln -s latem-vault ~/.cargo/bin/vault` adds a short name.

```sh
vault init                                         # shows the recovery phrase once; asks for a passphrase without a Secure Enclave
vault collections create latem                     # Touch ID; the recovery phrase without a Secure Enclave
vault set latem/prod/SENTRY_DSN --secret           # value from stdin; hidden when typed
vault set latem/prod/REGION --var
vault list latem
vault get latem/prod/SENTRY_DSN
vault run --collection latem --env prod -- ./deploy.sh
vault devices                                      # this vault's devices, and which are on this network
```

To add another device on the same network, run `vault join` on it and `vault approve` on the MacBook:

```sh
vault join                                         # on the new device: shows a 6-digit code
vault approve --read latem                         # on the MacBook: the code, a review, then Touch ID
```

The code and the review make sure the device you approve is the one in front of you. The new device gets the vault's membership log and the keys for the collections it may read. With `vault service` running on both, their secrets follow within seconds, and so does every later change.

To change what a device may do with a collection, such as one created after it joined:

```sh
vault scope Desktop ssh read                       # none, hold, read or write; Touch ID
```

Taking away `read` or `write` gives the collection a new key, as revoking does.

To remove a device, such as one that was lost:

```sh
vault devices revoke Desktop                       # a review, then Touch ID
```

It stops syncing with the vault, and each collection it could read gets a new key, so nothing written afterwards reaches it. It keeps what it has already read, so the command ends with the secrets to change where they were issued.

`vault run` passes every entry under `prod/` to the command as an environment variable, so `prod/SENTRY_DSN` becomes `SENTRY_DSN`. `--prefix` puts a prefix in front of every name. latem reads its secrets from `LATEM_SECRET_<NAME>`, so it runs like this:

```sh
vault run --collection latem --env prod --prefix LATEM_SECRET_ -- latem …
```

To bring in a whole `NAME=value` file, such as latem's `secrets.env`:

```sh
vault import-env ~/.latem/secrets.env --collection latem --env prod --var REGION
```

With `-` as the file it reads stdin, so the file can come straight from another machine without a plaintext copy landing on this one:

```sh
ssh mini 'cat ~/.latem/secrets.env' | vault import-env - --collection latem --env prod
```

Every name becomes a secret unless it is given with `--var`. The file is read as latem reads it: no `export`, no `$` expansion, and in double quotes only `\n`, `\r`, `\t`, `\\` and `\"`. Nothing is written if any line fails to parse, or if a name already exists (unless you pass `--overwrite`).

Files, such as a signing keystore or a folder of documents, are imported as file entries ([files.md](docs/spec/files.md)):

```sh
vault import ~/release --collection latem --into prod         # needs FileVault, or dm-crypt on Linux
vault list latem/prod                                          # files show their size
vault get latem/prod/upload.jks -o upload.jks                 # readable only by you
vault open latem/prod/notes.md                                # in its app; each save is a new version
vault run --collection latem --env prod -- ./gradlew bundleRelease   # UPLOAD_JKS is the keystore's path
```

A file of up to 64 KiB is kept in its record, like a secret. A larger one is cut into 1 MiB chunks, each encrypted, which are kept in `~/.latem-vault/chunks`. The originals stay where they were until you delete them. `run` writes the folder's files to a private temporary folder while the command runs, and deletes it after.

The service passes a file's chunks to the other devices that read its collection. A device keeps every file's chunks unless `vault placement <collection> on-demand` says to fetch them when a file is read; `get` and `run` fetch what's missing either way.

`vault service` holds the vault open until Ctrl-C. It finds this vault's other devices on the local network with mDNS, without relays or anything outside the network, and other commands go through it, so a passphrase is typed once rather than for every command. Without it, each command opens the vault itself.

The vault and this device's key file are kept in `~/.latem-vault`; set `LATEM_VAULT_HOME` to use another directory. On a Mac with a Secure Enclave, the device keys stay in it. Elsewhere they are kept in the key file, which only you can read, sealed with a passphrase that every command asks for on the terminal. `init --keys software` leaves the passphrase out, for a device that opens the vault with nobody there to type one, such as a container.

### Coming from openvault

Until 0.6, latem vault was OpenVault: the command was `openvault`, its directory `~/.openvault`, and its variables `OPENVAULT_HOME`, `OPENVAULT_LOG` and `OPENVAULT_MDNS_SERVICE`. On a device that has the old directory, run:

```sh
vault service install                            # stops openvault's service, moves the vault, starts latem vault's
```

Any other command moves it too, while no service runs for it. The move is one rename of `~/.openvault` to `~/.latem-vault`, so the key file and the Secure Enclave keys go with it. It waits, and the vault stays where it is, while openvault's service runs, while the Mac app's build looks only in the old directory, or while a latem older than 0.12.0 is installed, since that looks only in the old directory too. The command says which. The old variables are still read in 0.6, and go in a later release. Vaults, keys and devices on 0.5 and 0.6 are the same: the names inside a vault, its protocol IDs and its mDNS service stay `openvault` for ever (`crates/crypto/src/frozen.rs`).

## Development

Before anything lands on `main`, run:

```sh
scripts/ci.sh
```

It runs rustfmt, then clippy and the tests on this Mac and in a Linux container, which needs Docker. `scripts/ci.sh macos` or `scripts/ci.sh linux` runs one side only.

GitHub Actions runs the same checks ([ci.yml](.github/workflows/ci.yml)). A pull request gets the Linux side only, which is quick. The macOS side is slow, and runs on each push to `main`, so run `scripts/ci.sh macos` before merging and say so in the pull request.

### Versions

Each build knows its version and the commit it was built from. `vault --version` prints them, under the full name whichever one ran it, as in `latem-vault 0.2.0 (8edda7f)`, and `vault service` logs the same line when it starts. A build made outside a git checkout shows `unknown` for the commit. One made with uncommitted changes shows the commit those changes are on.

Until 1.0, versions are `0.MINOR.PATCH`:
- **MINOR** goes up when the store version or a protocol changes, in the same commit, or when the command or its directory is renamed. An older build refuses a newer store, and can't speak a newer protocol, so devices on the same minor version can share a vault. Two tests fail until both are changed together. 0.2 is M2: store version 6, `openvault/sync/1` and `openvault/join/1`. 0.3 adds M3's `openvault/coord/1`. 0.4 is store version 7, with files, and 0.5 adds `openvault/chunks/1`. 0.6 changes no store or protocol: it renames OpenVault to latem vault, with the `latem-vault` command and `~/.latem-vault`.
- **PATCH** goes up for any other release.

Each release is a tag on `main`, as `v0.6.0`, and pushing the tag is what publishes it: [release.yml](.github/workflows/release.yml) refuses a tag that isn't on `main` or that differs from the version in `Cargo.toml`, then builds, signs and publishes the release, and the Homebrew tap picks it up within the hour. [docs/release.md](docs/release.md) has the steps. Releases before 0.6.0 weren't tagged, apart from `v0.2.0` and `v0.2.1`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
