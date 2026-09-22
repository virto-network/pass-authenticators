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

## Versions

All crates are published to [crates.io](https://crates.io/search?q=pass-authenticators) and released
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
pass-webauthn = { package = "pass-authenticators-webauthn", version = "1.0.0", default-features = false, features = ["runtime"] }
pass-substrate-keys = { package = "pass-authenticators-substrate-keys", version = "1.0.0", default-features = false, features = ["runtime"] }
```

See [RELEASING.md](./RELEASING.md) for how releases are made, and [CONTRIBUTING.md](./CONTRIBUTING.md) for PR
titles and what counts as a breaking change.

## Verification weights and benchmarks

`fc-pallet-pass` charges what verifying an attestation (on `register`/`add_device`) or a credential (on every
extrinsic authenticated with `PassAuthenticate`) costs through `verification_weight`, which each authenticator
implements from its own benchmarks:

| Authenticator | Attestation | Credential |
| --- | --- | --- |
| `pass-authenticators-webauthn` | `verify_attestation(c, a)` | `verify_credential(c, a)` (includes the P-256 signature check) |
| `pass-authenticators-substrate-keys` | `verify_attestation_{sr25519,ed25519,ecdsa,eth}()` | `verify_credential_{sr25519,ed25519,ecdsa,eth}()` |

where `c` is the length of the client data (capped at 1024 bytes) and `a` the length of the authenticator data.
Substrate keys charge the weight of the signature's key type.

The weights live in each crate's `src/weights.rs`, and are runtime-independent: verifying touches no storage, and
the benchmarks run with their own challenger. **The committed weights are placeholders**, conservative estimates
pending a run on reference hardware.

### Running the benchmarks

Each authenticator has a benchmarking-only pallet, behind its `runtime-benchmarks` feature. To run them, add
them to a runtime's `define_benchmarks!` (they don't go in `construct_runtime!`):

```rust
frame_benchmarking::define_benchmarks!(
    // ...
    [pass_webauthn, pass_webauthn::benchmarking::Pallet::<Runtime>]
    [pass_substrate_keys, pass_substrate_keys::benchmarking::Pallet::<Runtime>]
);
```

Then, on reference hardware, build that runtime with `--features runtime-benchmarks` and regenerate the weights
with this repository's template:

```sh
for pallet in webauthn substrate-keys; do
  frame-omni-bencher v1 benchmark pallet \
    --runtime path/to/runtime.compact.compressed.wasm \
    --pallet "pass_${pallet//-/_}" --extrinsic '*' \
    --steps 50 --repeat 20 \
    --template .maintain/frame-weight-template.hbs \
    --output "authenticators/${pallet}/src/weights.rs"
done
```

`cargo test --features runtime-benchmarks` runs every benchmark once, as a test.

### Benchmark helpers

With `runtime-benchmarks`, the attestation and credential types implement `fc-traits-authn`'s
`DeviceAttestationBenchmarkHelper` and `CredentialBenchmarkHelper`, so `fc-pallet-pass`'s benchmarks can produce
valid inputs for any runtime using these authenticators. Runtimes only need to implement
`ChallengerBenchmarkHelper` for their challenger.
