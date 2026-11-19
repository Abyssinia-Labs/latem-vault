# PinkVault

PinkVault keeps secrets, variables and files encrypted on your own devices and syncs them between the devices you enroll. A new device joins with one approval on an admin device and gets only the collections it is scoped to. Devices reach each other on the LAN and over the internet, and nothing you own is stored on a server.

This repository holds the open-source core: the Rust service and CLI, the coordinator you can host yourself, and the local web UI for Linux and Windows.

## Status

Milestones M1, one device, and M2, devices on the same network, are done: devices join with a 6-digit code, sync directly over iroh, and can be revoked, and latem reads its builds' secrets from PinkVault. M3, reaching devices from outside the network, has its first stage built and paused: it is behind the cargo feature `coordinator`, off by default, so devices find each other on the local network only. M4, files, is done: files are kept encrypted in chunks, imported, read, opened in their apps and passed to commands, from the CLI and the Mac app, and their chunks reach the other devices that read the collection. latem's builds sign with keystores kept as files, a documents folder opens and saves on each machine, and a revoke lists the files a device could read. The design is in [docs/design.md](docs/design.md), and the formats are in [docs/spec](docs/spec).

## Try it

```sh
brew install abyssinia-labs/tap/pinkvault      # macOS and Linux, arm64 and x86-64
```

The command is `pinkvault`, and `pink` is its short name: both run the same binary, and Homebrew and the release archives put in both. A service installed from Homebrew by 0.6.0 starts that version's own copy, which `brew upgrade` removes; `pinkvault service install` replaces it with one that starts through Homebrew's `opt` link, so later upgrades keep it running.

Each [release](https://github.com/Abyssinia-Labs/latem-vault/releases) also has the binaries as archives, with a checksums file signed by [pinkvault.pub](pinkvault.pub) ([docs/release.md](docs/release.md)). To build from this checkout instead, `cargo install --locked --path crates/cli`, which puts in `pinkvault` only; `ln -s pinkvault ~/.cargo/bin/pink` adds the short name.

```sh
pink init                                            # shows the recovery phrase once; asks for a passphrase without a Secure Enclave
pink collections create latem                        # Touch ID; the recovery phrase without a Secure Enclave
pink set latem/prod/SENTRY_DSN --secret              # value from stdin; hidden when typed
pink set latem/prod/REGION --var
pink list latem
pink get latem/prod/SENTRY_DSN
pink run --collection latem --env prod -- ./deploy.sh
pink devices                                         # this vault's devices, and which are on this network
```

To add another device on the same network, run `pink join` on it and `pink approve` on the MacBook:

```sh
pink join                                            # on the new device: shows a 6-digit code
pink approve --read latem                            # on the MacBook: the code, a review, then Touch ID
```

The code and the review make sure the device you approve is the one in front of you. The new device gets the vault's membership log and the keys for the collections it may read. With `pink service` running on both, their secrets follow within seconds, and so does every later change.

To change what a device may do with a collection, such as one created after it joined:

```sh
pink scope Desktop ssh read                          # none, hold, read or write; Touch ID
```

Taking away `read` or `write` gives the collection a new key, as revoking does.

To remove a device, such as one that was lost:

```sh
pink devices revoke Desktop                          # a review, then Touch ID
```

It stops syncing with the vault, and each collection it could read gets a new key, so nothing written afterwards reaches it. It keeps what it has already read, so the command ends with the secrets to change where they were issued.

`pink run` passes every entry under `prod/` to the command as an environment variable, so `prod/SENTRY_DSN` becomes `SENTRY_DSN`. `--prefix` puts a prefix in front of every name. latem reads its secrets from `LATEM_SECRET_<NAME>`, so it runs like this:

```sh
pink run --collection latem --env prod --prefix LATEM_SECRET_ -- latem …
```

To bring in a whole `NAME=value` file, such as latem's `secrets.env`:

```sh
pink import-env ~/.latem/secrets.env --collection latem --env prod --var REGION
```

With `-` as the file it reads stdin, so the file can come straight from another machine without a plaintext copy landing on this one:

```sh
ssh mini 'cat ~/.latem/secrets.env' | pink import-env - --collection latem --env prod
```

Every name becomes a secret unless it is given with `--var`. The file is read as latem reads it: no `export`, no `$` expansion, and in double quotes only `\n`, `\r`, `\t`, `\\` and `\"`. Nothing is written if any line fails to parse, or if a name already exists (unless you pass `--overwrite`).

Files, such as a signing keystore or a folder of documents, are imported as file entries ([files.md](docs/spec/files.md)):

```sh
pink import ~/release --collection latem --into prod            # needs FileVault, or dm-crypt on Linux
pink list latem/prod                                             # files show their size
pink get latem/prod/upload.jks -o upload.jks                    # readable only by you
pink open latem/prod/notes.md                                   # in its app; each save is a new version
pink run --collection latem --env prod -- ./gradlew bundleRelease   # UPLOAD_JKS is the keystore's path
```

A file of up to 64 KiB is kept in its record, like a secret. A larger one is cut into 1 MiB chunks, each encrypted, which are kept in `~/.pinkvault/chunks`. The originals stay where they were until you delete them. `run` writes the folder's files to a private temporary folder while the command runs, and deletes it after.

The service passes a file's chunks to the other devices that read its collection. A device keeps every file's chunks unless `pink placement <collection> on-demand` says to fetch them when a file is read; `get` and `run` fetch what's missing either way.

`pink service` holds the vault open until Ctrl-C. It finds this vault's other devices on the local network with mDNS, without relays or anything outside the network, and other commands go through it, so a passphrase is typed once rather than for every command. Without it, each command opens the vault itself.

The vault and this device's key file are kept in `~/.pinkvault`; set `PINKVAULT_HOME` to use another directory. On a Mac with a Secure Enclave, the device keys stay in it. Elsewhere they are kept in the key file, which only you can read, sealed with a passphrase that every command asks for on the terminal. `init --keys software` leaves the passphrase out, for a device that opens the vault with nobody there to type one, such as a container.

### Coming from latem vault or openvault

PinkVault was latem vault in 0.6, with the command `latem-vault`, the directory `~/.latem-vault` and the variables `LATEM_VAULT_HOME`, `LATEM_VAULT_LOG` and `LATEM_VAULT_MDNS_SERVICE`. Before 0.6 it was OpenVault: `openvault`, `~/.openvault` and `OPENVAULT_*`. On a device that has an old directory, update latem to 0.14.0 or later, then run:

```sh
pinkvault service install                        # stops the old service, moves the vault, starts PinkVault's
```

Any other command moves it too, while no service runs for it. The move is one rename of `~/.latem-vault`, or of `~/.openvault` where that never moved, to `~/.pinkvault`, so the key file and the Secure Enclave keys go with it. It waits, and the vault stays where it is, while an old service runs, while the Mac app's build is from before PinkVault, while a latem older than 0.14.0 is installed, since that doesn't look in `~/.pinkvault`, or while both old directories exist, since only you can say which is the vault. The command says which on stderr.

For one release, `latem-vault` and `openvault` still run PinkVault and say it has a new name, and the old variables are still read. Vaults, keys and devices on 0.5, 0.6 and 0.7 are the same: the names inside a vault, its protocol IDs and its mDNS service stay `openvault` for ever (`crates/crypto/src/frozen.rs`).

## Development

Before anything lands on `main`, run:

```sh
scripts/ci.sh
```

It runs rustfmt, then clippy and the tests on this Mac and in a Linux container, which needs Docker. `scripts/ci.sh macos` or `scripts/ci.sh linux` runs one side only.

GitHub Actions runs the same checks ([ci.yml](.github/workflows/ci.yml)). A pull request gets the Linux side only, which is quick. The macOS side is slow, and runs on each push to `main`, so run `scripts/ci.sh macos` before merging and say so in the pull request.

### Versions

Each build knows its version and the commit it was built from. `pinkvault --version` prints them, under the full name whichever one ran it, as in `pinkvault 0.2.0 (8edda7f)`, and `pink service` logs the same line when it starts. A build made outside a git checkout shows `unknown` for the commit. One made with uncommitted changes shows the commit those changes are on.

Until 1.0, versions are `0.MINOR.PATCH`:
- **MINOR** goes up when the store version or a protocol changes, in the same commit, or when the command or its directory is renamed. An older build refuses a newer store, and can't speak a newer protocol, so devices on the same minor version can share a vault. Two tests fail until both are changed together. 0.2 is M2: store version 6, `openvault/sync/1` and `openvault/join/1`. 0.3 adds M3's `openvault/coord/1`. 0.4 is store version 7, with files, and 0.5 adds `openvault/chunks/1`. 0.6 changes no store or protocol: it renames OpenVault to latem vault, with the `latem-vault` command and `~/.latem-vault`. 0.7 renames it again, to PinkVault, with the `pinkvault` command and `~/.pinkvault`.
- **PATCH** goes up for any other release.

Each release is a tag on `main`, as `v0.6.0`, and pushing the tag is what publishes it: [release.yml](.github/workflows/release.yml) refuses a tag that isn't on `main` or that differs from the version in `Cargo.toml`, then builds, signs and publishes the release, and the Homebrew tap picks it up within the hour. [docs/release.md](docs/release.md) has the steps. Releases before 0.6.0 weren't tagged, apart from `v0.2.0` and `v0.2.1`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
