# Contributing to Pass Authenticators

Thanks for helping out! This document covers how changes get from a branch into a
published release. Everything in it follows from three facts:

1. Every PR is **squash-merged**, and the squash commit is the **PR title**. The
   PR description is not kept in the commit.
2. All crates are released **in lockstep** under one version, and each major line
   has its own branch: `1.x` (frame-contrib `2.x`) on `release/frame-contrib-v2`,
   and `2.x` (frame-contrib `3.x`) on `main`.
3. `CHANGELOG.md` is written from those same titles.

So **the PR title is the release note.** Most of this guide is about getting it
right.

## Development

CI runs the following, and a PR needs all of them to pass:

```sh
cargo fmt --all -- --check
cargo clippy --release --locked --all-features --workspace
cargo test --release --locked --all-features --workspace
```

The authenticators run inside a runtime, so CI also checks that they build `no_std`:

```sh
rustup target add wasm32v1-none
cargo check --locked --target wasm32v1-none --no-default-features --features runtime \
  -p pass-authenticators-webauthn -p pass-authenticators-substrate-keys \
  -p pass-authenticators-ethereum -p pass-authenticators-bitcoin \
  -p pass-authenticators-nostr -p pass-authenticators-solana -p pass-authenticators-ssh
```

## Which branch

- A fix or a backwards-compatible feature for runtimes on frame-contrib `2.x` goes to
  `release/frame-contrib-v2`. If it also applies to `main`, open a second PR there
  (or cherry-pick after merging).
- Everything else, and anything breaking, goes to `main`.

## PR titles

Titles must follow [Conventional Commits](https://www.conventionalcommits.org).
`lint-pr.yml` enforces this and won't let you merge otherwise:

```
<type>(<scope>)<!>: <description>
```

- **type** is one of `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`,
  `chore`, `style` or `revert`.
- **scope** is the authenticator, e.g. `webauthn`, `substrate-keys`, `ethereum` or
  `webauthn-verifier`. Use `deps` for dependency bumps. Leave it out for
  workspace-wide changes.
- **description** is imperative and lowercase, and reads well as a changelog entry
  for someone who uses the crate.
- **`!`** marks a breaking change. See below.

| Title | Next release | Changelog section |
| --- | --- | --- |
| `feat(webauthn)!: bind credentials to the rp id hash` | **major** | ⚠ Breaking changes |
| `feat(substrate-keys): add a registration payload builder` | minor | Added |
| `fix(webauthn): reject empty client data` | patch | Fixed |
| `perf(...)`, `refactor(...)`, `docs(...)`, `chore(...)` | patch | Performance / Changed / Documentation / Other |
| `test(...)`, `ci(...)`, `style(...)` | patch | *(not listed)* |

On `main`, a bump only happens when the commit touches a published crate's files.
`ci:` changes, or root-level `docs:`, never cause a release on their own.

### What counts as breaking (`!`)

Breaking means **client-visible**: a wallet, SDK or runtime integrator would have to
change something when it upgrades.

- **On-chain encodings:** the SCALE encoding of any type that goes on-chain or into
  an extrinsic: devices, device ids, registration and signature payloads,
  credentials, challenges. Reordering fields, changing a type, or changing how a
  challenge or signed message is built all break clients, even when the Rust code
  still compiles.
- **Metadata:** anything that changes the `TypeInfo` of those types, so clients have
  to regenerate their bindings.
- **A new Polkadot SDK line**, or a new frame-contrib major. These open a new major
  line of this repository.

A Rust API change that doesn't reach the chain or the metadata (a renamed helper, a
new trait bound on a mock) is not breaking by this definition. `cargo-semver-checks`
still runs on every release and raises the bump if it finds a Rust API break. It
**cannot** see encoding or metadata changes, and those are the ones that break
clients: the `!` is on you and your reviewer.

`release/frame-contrib-v2` takes **no** breaking changes: they go to `main`.

### Describe the migration in the PR

The PR description doesn't reach the branch, but the changelog links to the PR, so the
description is where the details go. For a `!` PR, include a **Migration** section
that says what a client or runtime integrator has to do.

## Changelog

`CHANGELOG.md` has one section per release.

On `main`, the release workflow writes it, so you **don't edit it in feature PRs**.

1. On every push to `main`, [release-plz](https://release-plz.dev) opens or updates a
   `chore: release vX.Y.Z` PR with the next version.
2. The same workflow generates that version's section with
   [git-cliff](https://git-cliff.org) (`cliff.toml`). The section covers every PR
   title merged since the last `vX.Y.Z` tag, with breaking changes listed first and
   each entry linked to its PR.
3. **Before merging the release PR, a maintainer curates the section.** Add the
   migration notes from the `!` PRs under their entries, reword unclear titles, and
   merge related entries.
4. Merging publishes the crates and creates the GitHub release. The release notes
   are the curated section, copied as is.

To preview the next section locally:

```sh
git cliff --unreleased --tag vX.Y.Z --strip all
```

On `release/frame-contrib-v2` (the manual `1.x` line), the maintainer writes the
section by hand in the release PR; see `RELEASING.md` on that branch.

## Adding a crate

Every crate is released together with the rest, so a new crate needs to be wired
into the workspace:

- In its `Cargo.toml`, set `version.workspace = true` (plus `authors`, `edition`,
  `license`, `readme` and `repository` from the workspace) and a `description`.
  CI fails if the crate is not on the workspace version.
- If other crates depend on it, add it to `[workspace.dependencies]` in the root
  `Cargo.toml` with both `path` and `version`.
- Add a `[[package]]` entry with `version_group = "pass-authenticators"` to
  `release-plz.toml`. Without it, the crate won't move in lockstep, and CI fails
  until you add it.
- Set `publish = false` if it should not go to crates.io, and add it to
  `release-plz.toml` with `release = false`.
