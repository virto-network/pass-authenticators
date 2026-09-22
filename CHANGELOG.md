# Changelog

All notable changes to this project are documented in this file. Every crate in the
workspace is released together under the same version. See
[CONTRIBUTING.md](./CONTRIBUTING.md#changelog) for how this file is maintained.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Only **client-visible** changes are breaking: on-chain encodings (device, registration
and credential types) and metadata. Every new Polkadot SDK line, and every new
frame-contrib major, is a major release too.

The `2.x` line is released from `main` and pairs with frame-contrib `3.x`. The `1.x`
line is released from
[`release/frame-contrib-v2`](https://github.com/virto-network/pass-authenticators/tree/release/frame-contrib-v2)
and pairs with frame-contrib `2.x`; its changelog lives on that branch.

## [Unreleased]

## [2.0.0-pre.1](https://github.com/virto-network/pass-authenticators/releases/tag/v2.0.0-pre.1)

Prerelease of the `2.x` line, the first published to crates.io. It pairs with
frame-contrib `3.0.0-pre.1` and targets polkadot-sdk `stable2606`. The changes below
are relative to [`1.0.0`](https://github.com/virto-network/pass-authenticators/blob/release/frame-contrib-v2/CHANGELOG.md).
**Device, registration and credential encodings of the WebAuthn and Substrate keys
authenticators are unchanged.**

Published crates:

- `pass-authenticators-webauthn`
- `pass-authenticators-webauthn-verifier`
- `pass-authenticators-substrate-keys`
- `pass-authenticators-ethereum` (new)
- `pass-authenticators-bitcoin` (new)
- `pass-authenticators-nostr` (new)
- `pass-authenticators-solana` (new)
- `pass-authenticators-ssh` (new)

### ⚠ Breaking changes

- Depend on `fc-traits-authn` and `fc-pallet-pass` `3.0.0-pre.1` from crates.io.
  Among other things, frame-contrib `3.x` changes `pallet-pass` calls and storage
  (per-device call filters); see its
  [changelog](https://github.com/virto-network/frame-contrib/blob/main/CHANGELOG.md).
- Substrate runtime dependencies (`sp-core`, `sp-io`, `sp-runtime`, `scale-info`,
  `frame`, and crypto helpers) are optional, behind each crate's `runtime` feature,
  which is on by default. Runtimes that use `default-features = false` must enable
  `runtime` to keep the `Authenticator` and `Device` types. Without it, the crates
  only expose the credential types, with the same SCALE encoding, for client use.
- The `webauthn-verifier` package is renamed `pass-authenticators-webauthn-verifier`.
  Keep using it under the `webauthn-verifier` dependency key with
  `package = "pass-authenticators-webauthn-verifier"`; the Rust crate name
  (`webauthn_verifier`) is unchanged.
- All crates now share one version and are released together. Depend on the same
  version of every `pass-authenticators-*` crate.

### Added

- New authenticators
  ([#17](https://github.com/virto-network/pass-authenticators/pull/17)):
  - `pass-authenticators-ethereum`: Ethereum accounts, verified with
    `personal_sign` (EIP-191) signatures.
  - `pass-authenticators-bitcoin`: Bitcoin keys, verified with signed messages
    (BIP-137).
  - `pass-authenticators-nostr`: Nostr keys, verified with BIP-340 Schnorr
    signatures.
  - `pass-authenticators-solana`: Solana wallets, verified with Ed25519
    signatures.
  - `pass-authenticators-ssh`: SSH Ed25519 keys, verified with `SSHSIG`
    signatures.

### Changed

- *(webauthn)* Use `url` from crates.io (`2.5.8`, `default-features = false`)
  instead of servo/rust-url's git repository. crates.io `url` supports `no_std` +
  `alloc` since `2.5.5`. URL parsing is unchanged.
