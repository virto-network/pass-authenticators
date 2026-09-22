# Pass Authenticators

This repository contains several authenticators suitable for FRAME-Contrib's
[pallet-pass](https://github.com/virto-network/frame-contrib/tree/main/pallets/pass).

## Workspace

This workspace contains the following crates:

- [`pass-authenticators-webauthn`](authenticators/webauthn): This authenticator uses WebAuthn Credentials as devices,
  and validates its assertions.
- [`pass-authenticators-webauthn-verifier`](authenticators/webauthn/verifier): A `no_std` verifier for WebAuthn
  ES256 (P-256) signatures, used by `pass-authenticators-webauthn`.
- [`pass-authenticators-substrate-keys`](authenticators/substrate-keys): This authenticator uses Substrate-compatible
  public keys as devices, and validates its signatures.
- [`pass-authenticators-ethereum`](authenticators/ethereum): This authenticator uses Ethereum accounts as devices,
  and validates their `personal_sign` (EIP-191) signatures.
- [`pass-authenticators-bitcoin`](authenticators/bitcoin): This authenticator uses Bitcoin keys as devices, and
  validates their signed messages (BIP-137).
- [`pass-authenticators-nostr`](authenticators/nostr): This authenticator uses Nostr keys as devices, and validates
  their BIP-340 Schnorr signatures.
- [`pass-authenticators-solana`](authenticators/solana): This authenticator uses Solana wallets as devices, and
  validates their Ed25519 signatures.
- [`pass-authenticators-ssh`](authenticators/ssh): This authenticator uses SSH Ed25519 keys as devices, and validates
  their `SSHSIG` signatures.

Every authenticator has a `runtime` feature (on by default) with the `pallet-pass` integration. Without it, a crate
only exposes its credential types, with the same SCALE encoding, so clients can build them without the Substrate
runtime stack.

## Versions

The crates are published to [crates.io](https://crates.io/search?q=pass-authenticators) and released
**in lockstep**: they share one version, one [`CHANGELOG.md`](./CHANGELOG.md) and one `vX.Y.Z` tag. Each major
line of this repository pairs with one major line of
[frame-contrib](https://github.com/virto-network/frame-contrib):

| pass-authenticators | frame-contrib | polkadot-sdk | Branch |
| --- | --- | --- | --- |
| `1.x` | `2.x` | `stable2606` | [`release/frame-contrib-v2`](https://github.com/virto-network/pass-authenticators/tree/release/frame-contrib-v2) |
| `2.x` | `3.x` | `stable2606` | [`main`](https://github.com/virto-network/pass-authenticators/tree/main) |

Depend on the same version of every `pass-authenticators-*` crate, and on the matching `fc-*` version:

```toml
[dependencies]
pass-webauthn = { package = "pass-authenticators-webauthn", version = "2.0.0-pre.1", default-features = false, features = ["runtime"] }
pass-substrate-keys = { package = "pass-authenticators-substrate-keys", version = "2.0.0-pre.1", default-features = false, features = ["runtime"] }
```

See [RELEASING.md](./RELEASING.md) for how releases are made, and [CONTRIBUTING.md](./CONTRIBUTING.md) for PR
titles and what counts as a breaking change.
