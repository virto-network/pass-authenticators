//! Benchmarks for the cost of verifying [`BtcRegistration`]s and [`BtcSignature`]s, and the helpers that
//! produce valid ones.
//!
//! The authenticator is not a pallet, so the benchmarks hang off a benchmarking-only [`Pallet`]
//! (in the fashion of `frame_system_benchmarking`), which runtimes add to their
//! `define_benchmarks!` without adding it to `construct_runtime!`:
//!
//! ```ignore
//! frame_benchmarking::define_benchmarks!(
//!     [pass_bitcoin, pass_bitcoin::benchmarking::Pallet::<Runtime>]
//! );
//! ```
//!
//! Each benchmark runs the whole of what `fc-pallet-pass` calls to verify an attestation
//! ([`Authenticator::verify_device`]) or a credential ([`UserAuthenticator::verify_user`]):
//! the authority and challenge checks, building the signed message, and recovering the signer (secp256k1, through the host) of its Bitcoin Signed Message (BIP-137) hash and hashing it (HASH160). Keys can be compressed or uncompressed, which recover differently, so each is benchmarked. Inputs have a
//! fixed size, so the benchmarks have no components. The challenger is [`BenchChallenger`] (a
//! BLAKE2-256 hash of the context and the extrinsic context), so the resulting weights are
//! independent of the runtime that runs them: what a runtime's own challenger costs on top of
//! that (e.g. storage reads) is not part of what this authenticator reports.

use super::*;
use frame::{
    benchmarking::prelude::*,
    deps::frame_support::{parameter_types, storage::unhashed},
};
use sp_io::hashing::blake2_256;
use traits_authn::{
    Authenticator as _, AuthenticatorBenchmarkHelper, Challenger, ChallengerBenchmarkHelper,
    CredentialBenchmarkHelper, DeviceAttestationBenchmarkHelper, DeviceChallengeResponse,
    ExtrinsicContext, UserAuthenticator,
};

/// Helpers that produce valid registrations and signatures for this authenticator, generating
/// (and remembering) a fresh key for every registration, and signing inside the runtime.
///
/// Keys are derived from a counter kept in (unhashed) storage, and remembered by their
/// [`DeviceId`], so they only work within benchmarks and tests.
pub mod helpers {
    use super::*;

    const PREFIX: &[u8] = b":pass-authenticators:bitcoin:benchmarks:";

    fn storage_key(suffix: &[u8]) -> [u8; 32] {
        blake2_256(&[PREFIX, suffix].concat())
    }

    fn next_seed() -> [u8; 32] {
        let key = storage_key(b"nonce");
        let nonce: u64 = unhashed::get_or_default(&key);
        unhashed::put(&key, &nonce.wrapping_add(1));
        blake2_256(&(PREFIX, nonce).encode())
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

    /// Signs `prehash`, returning `r || s` and the recovery id.
    fn sign_recoverable(seed: &[u8; 32], prehash: &[u8; 32]) -> ([u8; 64], u8) {
        let (signature, recovery_id) = secp256k1(seed)
            .sign_prehash_recoverable(prehash)
            .expect("prehash is 32 bytes long; qed");
        (signature.to_bytes().into(), recovery_id.to_byte())
    }

    /// The HASH160 of the key, compressed or not.
    fn public(seed: &[u8; 32], compressed: bool) -> BtcPubkeyHash {
        let point = secp256k1(seed).verifying_key().to_encoded_point(compressed);
        BtcPubkeyHash::from_hash160(crate::btc::hash160(point.as_bytes()))
    }

    fn sign<Cx: Encode>(
        seed: &[u8; 32],
        compressed: bool,
        message: &SignedMessage<Cx>,
    ) -> [u8; 65] {
        let (rs, recovery_id) = sign_recoverable(seed, &message.btc_message_hash());
        let mut signature = [0u8; 65];
        // BIP-137: 27-30 for uncompressed keys, 31-34 for compressed ones.
        signature[0] = if compressed { 31 } else { 27 } + recovery_id;
        signature[1..].copy_from_slice(&rs);
        signature
    }

    /// Returns a valid [`BtcRegistration`] of a freshly generated key (`compressed` or not),
    /// answering `challenge` (generated from `context`) for `authority_id`.
    pub fn registration<Cx: Encode>(
        compressed: bool,
        context: Cx,
        challenge: Challenge,
        authority_id: AuthorityId,
    ) -> BtcRegistration<Cx> {
        let seed = next_seed();
        let pubkey_hash = public(&seed, compressed);
        let message = SignedMessage {
            context,
            challenge,
            authority_id,
        };
        let signature = sign(&seed, compressed, &message);

        let device_id: &DeviceId = pubkey_hash.as_ref();
        unhashed::put(&storage_key(device_id), &(seed, compressed));

        BtcRegistration {
            pubkey_hash,
            message,
            signature,
        }
    }

    /// Returns a valid [`BtcSignature`] for `user_id`, answering `challenge` (generated from
    /// `context`) for `authority_id`, signed with the key registered as `device_id` by
    /// [`registration`].
    pub fn signature<Cx: Encode>(
        user_id: HashedUserId,
        device_id: DeviceId,
        context: Cx,
        challenge: Challenge,
        authority_id: AuthorityId,
    ) -> BtcSignature<Cx> {
        let (seed, compressed): ([u8; 32], bool) = unhashed::get(&storage_key(&device_id))
            .expect("devices are registered through `registration`; qed");
        let message = SignedMessage {
            context,
            challenge,
            authority_id,
        };
        let signature = sign(&seed, compressed, &message);

        BtcSignature {
            user_id,
            message,
            signature,
        }
    }
}

/// Registers a freshly generated compressed key, what current wallets use.
impl<Cx: Parameter + 'static> DeviceAttestationBenchmarkHelper<Cx> for BtcRegistration<Cx> {
    fn benchmark_attestation(authority: AuthorityId, context: Cx, challenge: Challenge) -> Self {
        helpers::registration(true, context, challenge, authority)
    }
}

/// Signs with the key registered as `device_id`, compressed or not.
impl<Cx: Parameter + 'static> CredentialBenchmarkHelper<Cx> for BtcSignature<Cx> {
    fn benchmark_credential(
        authority: AuthorityId,
        user_id: HashedUserId,
        device_id: DeviceId,
        context: Cx,
        challenge: Challenge,
    ) -> Self {
        helpers::signature(user_id, device_id, context, challenge, authority)
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

type BenchAuthenticator = Authenticator<BenchChallenger, BenchAuthority>;
type BenchDevice = Device<BenchChallenger, BenchAuthority>;

const CONTEXT: u32 = 1;
const XTC: [u8; 32] = [0x42; 32];
const USER: HashedUserId = [0x11; 32];

/// A valid registration of a fresh key: compressed keys come from the authenticator's
/// [`AuthenticatorBenchmarkHelper`] (what `fc-pallet-pass`'s benchmarks use), and uncompressed
/// ones from the same [`helpers`] underneath it.
fn attestation(compressed: bool) -> BtcRegistration<u32> {
    if compressed {
        BenchAuthenticator::device_attestation(&XTC)
    } else {
        helpers::registration(
            false,
            CONTEXT,
            BenchChallenger::generate(&CONTEXT, &XTC),
            BenchAuthority::get(),
        )
    }
}

/// A registered device, and a credential of it.
fn device_and_credential(compressed: bool) -> (BenchDevice, BtcSignature<u32>) {
    let attestation = attestation(compressed);
    let device_id = *attestation.device_id();
    let device =
        BenchAuthenticator::verify_device(attestation, &XTC).expect("attestation is valid; qed");
    (
        device,
        BenchAuthenticator::credential(USER, device_id, &XTC),
    )
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
    fn verify_attestation_compressed() {
        let attestation = attestation(true);
        let device;
        #[block]
        {
            device = BenchAuthenticator::verify_device(attestation, &XTC);
        }
        assert!(device.is_some());
    }

    #[benchmark]
    fn verify_attestation_uncompressed() {
        let attestation = attestation(false);
        let device;
        #[block]
        {
            device = BenchAuthenticator::verify_device(attestation, &XTC);
        }
        assert!(device.is_some());
    }

    #[benchmark]
    fn verify_credential_compressed() {
        let (mut device, credential) = device_and_credential(true);
        let result;
        #[block]
        {
            result = device.verify_user(&credential, &XTC);
        }
        assert!(result.is_some());
    }

    #[benchmark]
    fn verify_credential_uncompressed() {
        let (mut device, credential) = device_and_credential(false);
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
            let a = BenchAuthenticator::device_attestation(&XTC);
            let b = BenchAuthenticator::device_attestation(&XTC);
            assert_ne!(a.device_id(), b.device_id());
        })
    }

    #[test]
    fn authenticator_helpers_produce_inputs_that_verify() {
        mock::new_test_ext().execute_with(|| {
            let attestation = BenchAuthenticator::device_attestation(&XTC);
            let device_id = *attestation.device_id();
            let mut device = BenchAuthenticator::verify_device(attestation, &XTC)
                .expect("attestation is valid; qed");
            let credential = BenchAuthenticator::credential(USER, device_id, &XTC);
            assert!(device.verify_user(&credential, &XTC).is_some());
        })
    }
}
