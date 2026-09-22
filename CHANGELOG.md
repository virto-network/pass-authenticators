# Changelog

All notable changes to this project are documented in this file. Every crate in the
workspace is released together under the same version. See
[CONTRIBUTING.md](./CONTRIBUTING.md#changelog) for how this file is maintained.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Only **client-visible** changes are breaking: on-chain encodings (device, registration
and credential types) and metadata. Every new Polkadot SDK line is a major release too.

The `1.x` line is released from the
[`release/frame-contrib-v2`](https://github.com/virto-network/pass-authenticators/tree/release/frame-contrib-v2)
branch and pairs with frame-contrib `2.x`. The `2.x` line is released from `main` and
pairs with frame-contrib `3.x`.

## [Unreleased]

## [1.0.0](https://github.com/virto-network/pass-authenticators/releases/tag/v1.0.0)

This is the first versioned release and the first to be published to crates.io.
Before it, the crates were consumed from git without tags, and their version
(`0.1.0`) never changed. Kreivo `0.17.0-pre.1` shipped
[`7f240c3`](https://github.com/virto-network/pass-authenticators/tree/7f240c3).

This release is `7f240c3` moved to polkadot-sdk `stable2606` and frame-contrib `2.x`
from crates.io. **Device, registration and credential encodings are unchanged**, so
clients that work with `7f240c3` keep working.

Crates:

- `pass-authenticators-webauthn`: WebAuthn (passkey) credentials as `pallet-pass`
  devices.
- `pass-authenticators-webauthn-verifier`: the `no_std` ES256 signature verifier used
  by the WebAuthn authenticator.
- `pass-authenticators-substrate-keys`: Substrate public keys (`MultiSignature`) as
  `pallet-pass` devices.

### ⚠ Breaking changes

- Update to polkadot-sdk `stable2606-2`, and depend on `fc-traits-authn` and
  `fc-pallet-pass` `2.x` from crates.io instead of frame-contrib's git repository.
- The `webauthn-verifier` package is renamed `pass-authenticators-webauthn-verifier`.
  Keep using it under the `webauthn-verifier` dependency key with
  `package = "pass-authenticators-webauthn-verifier"`; the Rust crate name
  (`webauthn_verifier`) is unchanged.
- All crates now share one version and are released together. Depend on the same
  version of every `pass-authenticators-*` crate.

### Changed

- *(pass-authenticators-webauthn)* Use `url` from crates.io (`2.5.8`,
  `default-features = false`) instead of servo/rust-url's git repository. crates.io
  `url` supports `no_std` + `alloc` since `2.5.5`. URL parsing is unchanged.
