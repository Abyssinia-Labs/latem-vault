# Cutting a release

The pipeline is [`.github/workflows/release.yml`](../.github/workflows/release.yml). This is the part a person does.

## What a release is

```
pinkvault_<version>_<os>_<arch>.tar.gz      the binary at the archive root, pink as a relative link to it, the licences and the README
pinkvault_<version>_checksums.txt           the sha256 of each archive
pinkvault_<version>_checksums.txt.minisig   a minisign signature over the checksums
```

`<version>` has no leading `v`; the tag does. The platforms are `darwin/arm64`, `darwin/amd64`, `linux/amd64` and `linux/arm64`. The Linux binaries are static (musl), so they run on any distribution.

The Homebrew tap's `bin/bump-pinkvault` ([Abyssinia-Labs/homebrew-tap](https://github.com/Abyssinia-Labs/homebrew-tap)) looks for exactly these names, so changing one means changing it there in the same release. 0.7.0 is the first release under these names: until the tap's script, formula and key copy are renamed to match (OV-17), it still looks for 0.6.0's `latem-vault_` names, so tag 0.7.0 only after that change.

One signature covers all four archives: it is over the checksums file, whose lines name each archive with its version. Its trusted comment is `pinkvault <tag>`, and the tap refuses a manifest whose comment names another release.

## The signing key

Releases are signed by key **`3AE5705FBEDAB5B2`**, generated on 2026-11-17 for PinkVault alone (latem's releases have their own key). Its public half is [`pinkvault.pub`](../pinkvault.pub) here, and a copy of it is `pinkvault.pub` in the tap. The secret half and its password are the `MINISIGN_SECRET_KEY` and `MINISIGN_PASSWORD` secrets on this repository's `release` environment, which only a `v*` tag can use. The maintainer keeps a copy of both outside any repository.

To rotate it, on a machine you trust:

```sh
minisign -G -p pinkvault.pub -s pinkvault.key       # asks for a password
gh secret set MINISIGN_SECRET_KEY --env release -R Abyssinia-Labs/latem-vault < pinkvault.key
gh secret set MINISIGN_PASSWORD --env release -R Abyssinia-Labs/latem-vault   # the password
```

Commit the new `pinkvault.pub` here, and the same file in the tap, before the first release it signs: the `sign` job verifies against the committed key, and the tap verifies against its copy. **Never commit `pinkvault.key`.** `.gitignore` covers `*.key`.

## Cutting one

1. On a branch, set the version in `Cargo.toml` (README, versions) and write `docs/release-notes/v<version>.md`: what changed, and what someone on the previous version has to do about it. The release fails without it.
2. Check it on a Mac with `scripts/ci.sh macos`, open the pull request, and merge it once its checks pass.
3. Tag the merge on `main` and push the tag:

   ```sh
   git switch main && git pull
   git tag -a v0.6.0 -m "v0.6.0"
   git push origin v0.6.0
   ```

Then the workflow, each job gating the next:

| Job | What it does |
|---|---|
| `version` | Refuses a tag that isn't `vMAJOR.MINOR.PATCH`, isn't the version in `Cargo.toml`, or isn't on `main` |
| `checks` | All of [`ci.yml`](../.github/workflows/ci.yml), on Linux and macOS, against the tagged tree |
| `build` | Each archive on a runner of its own platform, which then runs it: `--version` must print the release's version and commit, and a Linux binary must be static |
| `checksums` | The manifest, checked with `sha256sum -c` |
| `sign` | minisign over the manifest, then verifies the signature against the committed `pinkvault.pub` |
| `publish` | `gh release create`, with the notes file and a block saying how to check a download |

The tap's `bump-pinkvault` workflow checks for a new release hourly. It verifies the manifest against its `pinkvault.pub` before it writes a sha256 into `Formula/pinkvault.rb`, installs and tests the formula on macOS and Linux, and pushes it. To pick a release up at once:

```sh
gh workflow run bump-pinkvault.yml -R Abyssinia-Labs/homebrew-tap
```

## Rehearsing

`gh workflow run release.yml -R Abyssinia-Labs/latem-vault` runs `checks`, `build` and `checksums` on `main` and publishes nothing. Do it after changing the workflow and before the next tag.

## When it goes wrong

`publish` fails if the release already exists. To withdraw a release before anyone has installed it:

```sh
gh release delete v0.6.0 --yes -R Abyssinia-Labs/latem-vault
git push --delete origin v0.6.0
git tag -d v0.6.0
```

After anyone could have installed it, don't reuse the number: cut the next patch release.

A failed `sign` leaves the archives built and nothing published. Fix the secret and re-run the failed jobs.

## What it doesn't do

- The macOS binaries are ad-hoc signed by the linker, not with a Developer ID, and not notarized. That is enough to run from a terminal, which is how Homebrew installs them.
- The Linux binaries are tested on the runners that built them, which are Ubuntu; being static, they don't depend on its libraries.
