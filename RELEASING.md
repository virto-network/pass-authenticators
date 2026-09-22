# Releasing Pass Authenticators

This is the maintainer side of the process. For PR titles, what counts as a breaking
change, and how the changelog is written, see [CONTRIBUTING.md](./CONTRIBUTING.md).

All crates in this workspace are released **in lockstep**: they share a single
version (`[workspace.package].version`), a single `CHANGELOG.md` and a single
`vX.Y.Z` git tag. CI fails if a crate doesn't use the workspace version.

## Release lines

Each major line pairs with one major line of
[frame-contrib](https://github.com/virto-network/frame-contrib), and is released from
its own branch:

| Line | frame-contrib | Branch | How |
| --- | --- | --- | --- |
| `1.x` | `2.x` | `release/frame-contrib-v2` | **Manual** (this document) |
| `2.x` | `3.x` | `main` | Automated with release-plz (see `RELEASING.md` on `main`) |

| Change | Bump |
| --- | --- |
| New Polkadot SDK line, or a new frame-contrib major | **major** (only on `main`) |
| Client-visible break: on-chain encodings (devices, registrations, credentials) or metadata | **major** (only on `main`) |
| New feature, backwards compatible | minor |
| Fix, or SDK / frame-contrib patch or minor release | patch |

A `1.x` release must stay compatible with clients and runtimes on `1.0.0`: nothing
client-visible can break on this branch. Breaking work goes to `main`.

## Cutting a 1.x release

The `1.x` line has no release-plz. A release is one PR against
`release/frame-contrib-v2`, followed by a publish and a tag.

1. **Open a release PR** titled `chore(release): X.Y.Z`, which:
   - sets `[workspace.package].version` to `X.Y.Z` in `Cargo.toml`;
   - sets `version = "X.Y.Z"` on the internal `webauthn-verifier` entry of
     `[workspace.dependencies]`;
   - refreshes the lockfile: `cargo update -w`;
   - moves the `## [Unreleased]` entries into a new `## [X.Y.Z](…/releases/tag/vX.Y.Z)`
     section of `CHANGELOG.md`, written by hand from the PR titles since the last
     `v1.*` tag (`git log --oneline v1.A.B..HEAD`).
2. **Check that every crate packages** against crates.io (no git or path-only
   dependencies left, frame-contrib dependencies published):

   ```sh
   cargo package --workspace --locked
   ```

   It builds every crate from its packaged sources, the way crates.io will see
   them. If an internal dependency isn't on crates.io yet (the first release, or a
   crate that changed), `cargo package` can't resolve it; use `--no-verify` for that
   run and rely on CI.
3. **Merge** the PR.
4. **Publish** from the merge commit, with a crates.io token that has the
   `publish-new` and `publish-update` scopes:

   ```sh
   git switch release/frame-contrib-v2 && git pull
   cargo publish --workspace --locked
   ```

   `cargo publish --workspace` publishes in dependency order
   (`pass-authenticators-webauthn-verifier` first). With an older Cargo, publish one
   crate at a time in that order: `-p pass-authenticators-webauthn-verifier`, then
   `-p pass-authenticators-webauthn` and `-p pass-authenticators-substrate-keys`.
5. **Tag and release:**

   ```sh
   git tag -s vX.Y.Z -m vX.Y.Z   # or -a if you don't sign tags
   git push origin vX.Y.Z
   # The body of `## [X.Y.Z]`, up to the next `## [` heading.
   awk -v v="X.Y.Z" 'index($0, "## [" v "]") == 1 { on = 1; next } on && /^## \[/ { exit } on' \
     CHANGELOG.md > release-notes.md
   gh release create vX.Y.Z --title vX.Y.Z --notes-file release-notes.md --verify-tag
   ```

   `1.x` and `2.x` tags share the `v` prefix; the major number tells the lines apart.

### First publish

None of the crates exist on crates.io before `1.0.0`. crates.io rate-limits **new**
crates to a small burst, so three crates go through, but if a publish hits
`429 Too Many Requests`, wait and re-run: crates that are already published are
skipped.

## Upgrading dependencies on this branch

- **frame-contrib `2.x`:** bump `fc-traits-authn` and `fc-pallet-pass` together to
  the new `2.y.z` from crates.io. Never use a git dependency in a release: crates.io
  rejects it.
- **polkadot-sdk:** patch releases of `stable2606` only. A new SDK line means a new
  frame-contrib major, and that belongs on `main`.
