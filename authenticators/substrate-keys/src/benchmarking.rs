//! Benchmarks for the cost of verifying [`KeyRegistration`]s and [`KeySignature`]s, and the
//! helpers that produce valid ones.
//!
//! The authenticator is not a pallet, so the benchmarks hang off a benchmarking-only [`Pallet`]
//! (in the fashion of `frame_system_benchmarking`), which runtimes add to their
//! `define_benchmarks!` without adding it to `construct_runtime!`:
//!
//! ```ignore
//! frame_benchmarking::define_benchmarks!(
//!     [pass_substrate_keys, pass_substrate_keys::benchmarking::Pallet::<Runtime>]
//! );
//! ```
//!
//! Each benchmark runs the whole of what `fc-pallet-pass` calls to verify an attestation
//! ([`Authenticator::verify_device`]) or a credential ([`UserAuthenticator::verify_user`]):
//! the authority and challenge checks, building the signed message, and verifying the
//! signature. The challenger is [`BenchChallenger`] (a BLAKE2-256 hash of the context and the
//! extrinsic context), so the resulting weights are independent of the runtime that runs them:
//! what a runtime's own challenger costs on top of that (e.g. storage reads) is not part of
//! what this authenticator reports.

use super::*;
use frame::benchmarking::prelude::*;
use frame_support::{parameter_types, storage::unhashed};
use sp_core::{ecdsa, ed25519, sr25519};
use sp_runtime::{
    traits::{BlakeTwo256, Hash, IdentifyAccount, Keccak256},
    MultiSigner,
};

fn blake2_256(data: &[u8]) -> [u8; 32] {
    BlakeTwo256::hash(data).0
}
use traits_authn::{
    Authenticator as _, AuthenticatorBenchmarkHelper, Challenger, ChallengerBenchmarkHelper,
    CredentialBenchmarkHelper, DeviceAttestationBenchmarkHelper, DeviceChallengeResponse, DeviceId,
    ExtrinsicContext, UserAuthenticator,
};

/// The key types a [`KeyRegistration`] can be signed with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum KeyType {
    Sr25519,
    Ed25519,
    Ecdsa,
    Eth,
}

/// Helpers that produce valid attestations and credentials for this authenticator, generating
/// (and remembering) a fresh key for every attestation, and signing inside the runtime.
///
/// Keys are derived from a counter kept in (unhashed) storage, and remembered by their
/// [`DeviceId`], so they only work within benchmarks and tests.
pub mod helpers {
    use super::*;
    use rand_core::{CryptoRng, RngCore};
    use schnorrkel::{context::attach_rng, signing_context, ExpansionMode, MiniSecretKey};

    const PREFIX: &[u8] = b":pass-authenticators:substrate-keys:benchmarks:";

    fn storage_key(suffix: &[u8]) -> [u8; 32] {
        blake2_256(&[PREFIX, suffix].concat())
    }

    fn next_seed() -> [u8; 32] {
        let key = storage_key(b"nonce");
        let nonce: u64 = unhashed::get_or_default(&key);
        unhashed::put(&key, &nonce.wrapping_add(1));
        blake2_256(&(PREFIX, nonce).encode())
    }

    /// A BLAKE2-based stream of bytes, seeded by what it's signing. It is only
    /// [`CryptoRng`] in name: these keys only ever sign benchmark and test messages.
    struct HashRng([u8; 32], usize);

    impl RngCore for HashRng {
        fn next_u32(&mut self) -> u32 {
            rand_core::impls::next_u32_via_fill(self)
        }
        fn next_u64(&mut self) -> u64 {
            rand_core::impls::next_u64_via_fill(self)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest.iter_mut() {
                if self.1 == self.0.len() {
                    self.0 = blake2_256(&self.0);
                    self.1 = 0;
                }
                *byte = self.0[self.1];
                self.1 += 1;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for HashRng {}

    // Keys are generated and used with the underlying crates rather than `sp_core`'s `Pair`s,
    // which need `sp-core/full_crypto` (and, for sr25519, an OS RNG) to sign, which a runtime
    // can't enable without breaking `sp-application-crypto`.

    fn sr25519(seed: &[u8; 32]) -> schnorrkel::Keypair {
        MiniSecretKey::from_bytes(seed)
            .expect("seed is 32 bytes long; qed")
            .expand_to_keypair(ExpansionMode::Ed25519)
    }

    fn secp256k1(seed: &[u8; 32]) -> k256::ecdsa::SigningKey {
        let mut candidate = *seed;
        loop {
            // Virtually every 32-byte string is a valid scalar.
            if let Ok(key) = k256::ecdsa::SigningKey::from_slice(&candidate) {
                return key;
            }
            candidate = blake2_256(&candidate);
        }
    }

    fn secp256k1_public(seed: &[u8; 32]) -> [u8; 33] {
        secp256k1(seed)
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed points are 33 bytes long; qed")
    }

    fn secp256k1_sign(seed: &[u8; 32], prehash: &[u8; 32]) -> [u8; 65] {
        let (signature, recovery_id) = secp256k1(seed)
            .sign_prehash_recoverable(prehash)
            .expect("prehash is 32 bytes long; qed");
        let mut raw = [0u8; 65];
        raw[..64].copy_from_slice(&signature.to_bytes());
        raw[64] = recovery_id.to_byte();
        raw
    }

    fn public(key_type: KeyType, seed: &[u8; 32]) -> AccountId32 {
        match key_type {
            KeyType::Sr25519 => AccountId32::new(sr25519(seed).public.to_bytes()),
            KeyType::Ed25519 => AccountId32::new(
                ed25519_zebra::VerificationKeyBytes::from(&ed25519_zebra::SigningKey::from(*seed))
                    .into(),
            ),
            KeyType::Ecdsa => {
                MultiSigner::Ecdsa(ecdsa::Public::from_raw(secp256k1_public(seed))).into_account()
            }
            KeyType::Eth => MultiSigner::Eth(ecdsa::KeccakPublic::from_raw(secp256k1_public(seed)))
                .into_account(),
        }
    }

    fn sign(key_type: KeyType, seed: &[u8; 32], message: &[u8]) -> MultiSignature {
        match key_type {
            KeyType::Sr25519 => {
                // Signing needs an RNG, which the runtime doesn't have: use a deterministic one.
                let rng = HashRng(blake2_256(&[&seed[..], message].concat()), 0);
                let transcript = attach_rng(signing_context(b"substrate").bytes(message), rng);
                MultiSignature::Sr25519(sr25519::Signature::from_raw(
                    sr25519(seed).sign(transcript).to_bytes(),
                ))
            }
            KeyType::Ed25519 => MultiSignature::Ed25519(ed25519::Signature::from_raw(
                ed25519_zebra::SigningKey::from(*seed).sign(message).into(),
            )),
            KeyType::Ecdsa => MultiSignature::Ecdsa(ecdsa::Signature::from_raw(secp256k1_sign(
                seed,
                &blake2_256(message),
            ))),
            KeyType::Eth => MultiSignature::Eth(ecdsa::KeccakSignature::from_raw(secp256k1_sign(
                seed,
                &Keccak256::hash(message).0,
            ))),
        }
    }

    /// Returns a valid [`KeyRegistration`] of a freshly generated key of type `key_type`,
    /// answering `challenge` (generated from `context`) for `authority_id`.
    pub fn key_registration<Cx: Encode>(
        key_type: KeyType,
        context: Cx,
        challenge: Challenge,
        authority_id: AuthorityId,
    ) -> KeyRegistration<Cx> {
        let seed = next_seed();
        let public = public(key_type, &seed);
        let message = SignedMessage {
            context,
            challenge,
            authority_id,
        };
        let signature = sign(key_type, &seed, message.message().as_ref());

        let device_id: &DeviceId = public.as_ref();
        unhashed::put(&storage_key(device_id), &(key_type, seed));

        KeyRegistration {
            public,
            message,
            signature,
        }
    }

    /// Returns a valid [`KeySignature`] for `user_id`, answering `challenge` (generated from
    /// `context`) for `authority_id`, signed with the key registered as `device_id` by
    /// [`key_registration`].
    pub fn key_signature<Cx: Encode>(
        user_id: HashedUserId,
        device_id: DeviceId,
        context: Cx,
        challenge: Challenge,
        authority_id: AuthorityId,
    ) -> KeySignature<Cx> {
        let (key_type, seed): (KeyType, [u8; 32]) = unhashed::get(&storage_key(&device_id))
            .expect("devices are registered through `key_registration`; qed");
        let message = SignedMessage {
            context,
            challenge,
            authority_id,
        };
        let signature = sign(key_type, &seed, message.message().as_ref());

        KeySignature {
            user_id,
            message,
            signature,
        }
    }
}

/// Registers a freshly generated sr25519 key, the key type most wallets use.
impl<Cx: Parameter + 'static> DeviceAttestationBenchmarkHelper<Cx> for KeyRegistration<Cx> {
    fn benchmark_attestation(authority: AuthorityId, context: Cx, challenge: Challenge) -> Self {
        helpers::key_registration(KeyType::Sr25519, context, challenge, authority)
    }
}

/// Signs with the key registered as `device_id`, whatever its type.
impl<Cx: Parameter + 'static> CredentialBenchmarkHelper<Cx> for KeySignature<Cx> {
    fn benchmark_credential(
        authority: AuthorityId,
        user_id: HashedUserId,
        device_id: DeviceId,
        context: Cx,
        challenge: Challenge,
    ) -> Self {
        helpers::key_signature(user_id, device_id, context, challenge, authority)
    }
}

/// The challenger the benchmarks run with: a BLAKE2-256 hash of the context and the extrinsic
/// context, without any storage access.
pub struct BenchChallenger;

impl Challenger for BenchChallenger {
    type Context = u32;

    fn generate(cx: &Self::Context, xtc: &impl ExtrinsicContext) -> Challenge {
        blake2_256(&(cx, xtc.as_ref()).encode())
    }
}

impl ChallengerBenchmarkHelper for BenchChallenger {
    fn benchmark_context() -> Self::Context {
        CONTEXT
    }
}

parameter_types! {
    pub const BenchAuthority: AuthorityId = *b"pass-authenticators/bench-authn\0";
}

// What verification costs is what these benchmarks measure, so it's irrelevant here.
type BenchAuthenticator = Authenticator<BenchChallenger, BenchAuthority, ()>;

const CONTEXT: u32 = 1;
const XTC: [u8; 32] = [0x42; 32];
const USER: HashedUserId = [0x11; 32];

/// A valid registration of a fresh `key_type` key: sr25519 comes from the authenticator's
/// [`AuthenticatorBenchmarkHelper`] (what `fc-pallet-pass`'s benchmarks use), and the other
/// key types from the same [`helpers`] underneath it.
fn attestation(key_type: KeyType) -> KeyRegistration<u32> {
    match key_type {
        KeyType::Sr25519 => BenchAuthenticator::device_attestation(&XTC),
        key_type => helpers::key_registration(
            key_type,
            CONTEXT,
            BenchChallenger::generate(&CONTEXT, &XTC),
            BenchAuthority::get(),
        ),
    }
}

fn device_and_credential(
    key_type: KeyType,
) -> (
    Device<BenchChallenger, BenchAuthority, ()>,
    KeySignature<u32>,
) {
    let attestation = attestation(key_type);
    let device_id = *attestation.device_id();
    let device =
        BenchAuthenticator::verify_device(attestation, &XTC).expect("attestation is valid; qed");
    let credential = BenchAuthenticator::credential(USER, device_id, &XTC);
    (device, credential)
}

/// The benchmarking-only pallet the benchmarks hang off.
pub struct Pallet<T: Config>(frame::deps::frame_system::Pallet<T>);

/// Nothing to configure: the benchmarks only need a `frame_system` runtime.
pub trait Config: frame::deps::frame_system::Config {}
impl<T: frame::deps::frame_system::Config> Config for T {}

#[benchmarks]
mod benchmarks {
    use super::*;

    #[benchmark]
    fn verify_attestation_sr25519() {
        let attestation = attestation(KeyType::Sr25519);
        let device;
        #[block]
        {
            device = BenchAuthenticator::verify_device(attestation, &XTC);
        }
        assert!(device.is_some());
    }

    #[benchmark]
    fn verify_attestation_ed25519() {
        let attestation = attestation(KeyType::Ed25519);
        let device;
        #[block]
        {
            device = BenchAuthenticator::verify_device(attestation, &XTC);
        }
        assert!(device.is_some());
    }

    #[benchmark]
    fn verify_attestation_ecdsa() {
        let attestation = attestation(KeyType::Ecdsa);
        let device;
        #[block]
        {
            device = BenchAuthenticator::verify_device(attestation, &XTC);
        }
        assert!(device.is_some());
    }

    #[benchmark]
    fn verify_attestation_eth() {
        let attestation = attestation(KeyType::Eth);
        let device;
        #[block]
        {
            device = BenchAuthenticator::verify_device(attestation, &XTC);
        }
        assert!(device.is_some());
    }

    #[benchmark]
    fn verify_credential_sr25519() {
        let (mut device, credential) = device_and_credential(KeyType::Sr25519);
        let result;
        #[block]
        {
            result = device.verify_user(&credential, &XTC);
        }
        assert!(result.is_some());
    }

    #[benchmark]
    fn verify_credential_ed25519() {
        let (mut device, credential) = device_and_credential(KeyType::Ed25519);
        let result;
        #[block]
        {
            result = device.verify_user(&credential, &XTC);
        }
        assert!(result.is_some());
    }

    #[benchmark]
    fn verify_credential_ecdsa() {
        let (mut device, credential) = device_and_credential(KeyType::Ecdsa);
        let result;
        #[block]
        {
            result = device.verify_user(&credential, &XTC);
        }
        assert!(result.is_some());
    }

    #[benchmark]
    fn verify_credential_eth() {
        let (mut device, credential) = device_and_credential(KeyType::Eth);
        let result;
        #[block]
        {
            result = device.verify_user(&credential, &XTC);
        }
        assert!(result.is_some());
    }

    impl_benchmark_test_suite!(
        Pallet,
        crate::benchmarking::mock::new_test_ext(),
        crate::benchmarking::mock::Test
    );
}

#[cfg(test)]
pub(crate) mod mock {
    use frame::testing_prelude::*;

    #[frame_construct_runtime]
    pub mod runtime {
        #[runtime::runtime]
        #[runtime::derive(RuntimeCall, RuntimeEvent, RuntimeError, RuntimeOrigin, RuntimeTask)]
        pub struct Test;

        #[runtime::pallet_index(0)]
        pub type System = frame_system;
    }

    #[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
    impl frame_system::Config for Test {
        type Block = MockBlock<Test>;
    }

    pub fn new_test_ext() -> TestExternalities {
        TestExternalities::default()
    }
}

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn helpers_produce_fresh_devices() {
        mock::new_test_ext().execute_with(|| {
            let a = attestation(KeyType::Sr25519);
            let b = attestation(KeyType::Sr25519);
            assert_ne!(a.device_id(), b.device_id());
        })
    }
}
