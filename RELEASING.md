# Releasing Pass Authenticators

This is the maintainer side of the process. For PR titles, what counts as a breaking
change, and how the changelog is written, see [CONTRIBUTING.md](./CONTRIBUTING.md).

All crates in this workspace are released **in lockstep**: they share a single
version (`[workspace.package].version`), a single `CHANGELOG.md` and a single
`vX.Y.Z` git tag. CI fails if a crate doesn't use the workspace version or is
missing from `release-plz.toml`.

## Release lines

Each major line pairs with one major line of
[frame-contrib](https://github.com/virto-network/frame-contrib), and is released from
its own branch:

| Line | frame-contrib | Branch | How |
| --- | --- | --- | --- |
| `1.x` | `2.x` | `release/frame-contrib-v2` | Manual (see `RELEASING.md` on that branch) |
| `2.x` | `3.x` | `main` | **Automated** with release-plz (this document) |

| Change | Bump |
| --- | --- |
| New Polkadot SDK line, or a new frame-contrib major | **major** |
| Client-visible break: on-chain encodings (devices, registrations, credentials) or metadata | **major** |
| New feature, backwards compatible | minor |
| Fix, or SDK / frame-contrib patch or minor release | patch |

The bump is computed from the PR titles on `main` (`!` → major, `feat` → minor,
anything else → patch). `cargo-semver-checks` can raise it, but it can't see
encoding or metadata changes. See
[What counts as breaking](./CONTRIBUTING.md#what-counts-as-breaking-).

A new frame-contrib major opens a new line here: when `main` moves to frame-contrib
`4.x`, first cut `release/frame-contrib-v3` from the last `2.x` release so `2.x` can
keep getting fixes by hand.

## Tags

`vX.Y.Z`, one per release, created by release-plz on `main` and by hand on
`release/frame-contrib-v2`. Both lines share the `v` prefix; the major number tells
them apart. Consumers should use the crates.io versions rather than git.

## Cutting a release

1. Merge PRs into `main` as usual.
2. [release-plz](https://release-plz.dev) keeps a `chore: release vX.Y.Z` PR open
   with the computed version, and the workflow writes that version's
   `CHANGELOG.md` section onto it with git-cliff (`cliff.toml`).
3. **Curate the changelog section right before merging.** Add migration notes under
   the breaking entries, taking them from each PR's *Migration* section. Any new
   push to `main` rebuilds the release PR and discards manual edits. If you push a
   hand-written section, the workflow leaves it alone.
4. Merge the release PR. The `Release` workflow:
   - publishes every published crate to crates.io in dependency order;
   - pushes `vX.Y.Z` and creates a GitHub release (marked as a prerelease for
     `-pre.N` versions) whose notes are the curated section.

Nothing can be published while the workspace has a git dependency (e.g. a
temporary frame-contrib `rev`): crates.io rejects it. Replace it with a published
version first.

### Prereleases

While frame-contrib `3.x` is a prerelease, so is this line (`2.0.0-pre.N`), and
release-plz bumps the prerelease number instead of the version. To leave the
prerelease, open a PR that sets `[workspace.package].version` and the
`webauthn-verifier` entry of `[workspace.dependencies]` to `2.0.0` (and depends on the
final frame-contrib `3.0.0`), with a `## [2.0.0]` section in `CHANGELOG.md`. release-plz
publishes a version that is set by hand and not on crates.io yet as is.

### One-time setup (repository settings)

- Secret `CARGO_REGISTRY_TOKEN`: a crates.io API token with the `publish-new` and
  `publish-update` scopes.
- `CRATES_IO_PUBLISH` = `true`, as a repository **variable** or a **secret**: enables
  the publishing job. Until it is set, only the release PR is maintained.
- Secret `RELEASE_PLZ_TOKEN` (recommended): a fine-grained PAT or GitHub App token
  with `contents` and `pull-requests` write access. PRs opened with the default
  `GITHUB_TOKEN` don't trigger CI, so without this secret the release PR never gets
  its checks.
- Settings → General → Pull Requests → "Default commit message" for squash merges:
  choose **Pull request title**. With "Default to commit title", a single-commit PR
  takes the commit's title, and a `!` that is only on the PR title is lost.

### First publish

`2.0.0-pre.1` is set by hand in the manifests and has a hand-written changelog
section. Once the one-time setup is done and `main` has no git dependencies, the
next push to `main` (or a re-run of the `Release` workflow) publishes it and tags
`v2.0.0-pre.1`. crates.io rate-limits **new** crates to a small burst followed by
roughly one per 10 minutes, and this line publishes 8 (3 of them already exist once
`1.0.0` is out). If the run hits `429 Too Many Requests`, re-run it later: crates that
are already published are skipped.

Publish `1.0.0` from `release/frame-contrib-v2` first when possible, so the crates'
first version on crates.io is the stable one.
