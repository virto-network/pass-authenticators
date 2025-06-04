# Pass Authenticators

This repository contains several authenticators suitable for FRAME-Contrib's
[pallet-pass](https://github.com/virto-network/frame-contrib/tree/main/pallets/pass).

## Workspace

This workspace contains the following crates:

- [`pass-authenticators-webauthn`](authenticators/webauthn): This authenticator uses WebAuthn Credentials as devices,
  and validates its assertions.
- [`pass-authenticators-substrate-keys`](authenticators/substrate-keys): This authenticator uses Substrate-compatible
  public keys as devices, and validates its signatures.

