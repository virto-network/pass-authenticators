//! Benchmarks for the cost of verifying WebAuthn [`Attestation`]s and [`Assertion`]s, and the
//! helpers that produce valid ones.
//!
//! The authenticator is not a pallet, so the benchmarks hang off a benchmarking-only [`Pallet`]
//! (in the fashion of `frame_system_benchmarking`), which runtimes add to their
//! `define_benchmarks!` without adding it to `construct_runtime!`:
//!
//! ```ignore
//! frame_benchmarking::define_benchmarks!(
//!     [pass_webauthn, pass_webauthn::benchmarking::Pallet::<Runtime>]
//! );
//! ```
//!
//! Each benchmark runs the whole of what `fc-pallet-pass` calls to verify an attestation
//! ([`Authenticator::verify_device`]) or a credential ([`UserAuthenticator::verify_user`]):
//! the authority and challenge checks, parsing the client data (JSON) and the authenticator
//! data (binary and CBOR), and, for credentials, checking the P-256 signature. The challenger is
//! [`BenchChallenger`] (a BLAKE2-256 hash of the context and the extrinsic context), so the
//! resulting weights are independent of the runtime that runs them: what a runtime's own
//! challenger costs on top of that (e.g. storage reads) is not part of what this authenticator
//! reports.
//!
//! Both benchmarks have two components:
//!
//! - `c`, the length of the client data, up to its 1024-byte cap. The padding is JSON escapes in
//!   the origin's path, which cost more to parse than plain characters (and, in attestations,
//!   than to percent-encode when parsing the origin as a URL).
//! - `a`, the length of the authenticator data, which isn't capped. The padding is a CBOR array
//!   of zeros (one item per byte), in the credential public key of an attestation, or in the
//!   extensions of an assertion.

use super::*;
use crate::runtime::{Authenticator, Device};
use frame::{
    benchmarking::prelude::*,
    deps::frame_support::{parameter_types, storage::unhashed},
    hashing::blake2_256,
};
use traits_authn::{
    Authenticator as _, AuthenticatorBenchmarkHelper, Challenge, Challenger,
    ChallengerBenchmarkHelper, CredentialBenchmarkHelper, DeviceAttestationBenchmarkHelper,
    DeviceChallengeResponse, ExtrinsicContext, UserAuthenticator,
};

pub use crate::runtime::{
    MAX_AUTHENTICATOR_DATA_LEN, MAX_CLIENT_DATA_LEN, MIN_ASSERTION_AUTHENTICATOR_DATA_LEN,
    MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN, MIN_CLIENT_DATA_LEN,
};

/// Helpers that produce valid attestations and assertions for this authenticator, generating
/// (and remembering) a fresh P-256 key for every attestation, and signing inside the runtime.
///
/// Keys are derived from a counter kept in (unhashed) storage, and remembered by their
/// [`DeviceId`], so they only work within benchmarks and tests.
pub mod helpers {
    use super::*;
    use alloc::{string::String, vec};
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use coset::{cbor::Value, iana, CborSerializable, CoseKeyBuilder};
    use frame::hashing::sha2_256;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    const PREFIX: &[u8] = b":pass-authenticators:webauthn:benchmarks:";

    /// The relying party the helpers' credentials are scoped to.
    pub const RP_DOMAIN: &str = "bench.pass.int";

    /// The DER (SubjectPublicKeyInfo) prefix of an uncompressed P-256 public key.
    const P256_SPKI_PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];

    /// The lengths of the client data and authenticator data to produce. The helpers never
    /// produce less than the minimum each needs, and pad up to the requested length (or at most
    /// a couple of bytes beyond it, where CBOR's length prefixes can't hit it exactly).
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Lengths {
        pub client_data: u32,
        pub authenticator_data: u32,
    }

    fn storage_key(suffix: &[u8]) -> [u8; 32] {
        blake2_256(&[PREFIX, suffix].concat())
    }

    fn next_nonce() -> u64 {
        let key = storage_key(b"nonce");
        let nonce: u64 = unhashed::get_or_default(&key);
        unhashed::put(&key, &nonce.wrapping_add(1));
        nonce
    }

    fn signing_key(seed: &[u8; 32]) -> SigningKey {
        let mut candidate = *seed;
        loop {
            // Virtually every 32-byte string is a valid scalar.
            if let Ok(key) = SigningKey::from_slice(&candidate) {
                return key;
            }
            candidate = blake2_256(&candidate);
        }
    }

    fn der_public_key(key: &SigningKey) -> DEREncodedPublicKey {
        let point = key.verifying_key().to_encoded_point(false);
        let mut der = [0u8; 91];
        der[..26].copy_from_slice(&P256_SPKI_PREFIX);
        der[26..].copy_from_slice(point.as_bytes());
        der
    }

    /// A CBOR array of zeros whose encoding takes `len` bytes (or, where the length prefix
    /// can't hit it exactly, the fewest bytes above it). `len` must be at least 1.
    fn padding(len: usize) -> Value {
        let items = match len {
            0..=24 => len.saturating_sub(1),
            25 => 24,
            26..=257 => len - 2,
            258 => 256,
            _ => len - 3,
        };
        Value::Array(vec![Value::Integer(0.into()); items])
    }

    fn client_data(request_type: &str, challenge: &Challenge, len: u32) -> Vec<u8> {
        let challenge = base64::encode_engine(challenge, &BASE64_URL_SAFE_NO_PAD);
        let json = |path: &str| {
            alloc::format!(
                r#"{{"type":"{request_type}","challenge":"{challenge}","origin":"https://{RP_DOMAIN}{path}","crossOrigin":false}}"#
            )
        };

        let bare = json("").len();
        let len = len as usize;
        if len <= bare {
            return json("").into_bytes();
        }

        // Pad the origin with a path of escaped spaces (`\u0020`, 6 bytes each), completed
        // with plain characters.
        let padding = len - bare - 1;
        let mut path = String::from("/");
        path.push_str(&"\\u0020".repeat(padding / 6));
        path.push_str(&"a".repeat(padding % 6));
        json(&path).into_bytes()
    }

    fn authenticator_data_header(flags: u8) -> Vec<u8> {
        let mut data = sha2_256(RP_DOMAIN.as_bytes()).to_vec();
        data.push(flags);
        // signCount: 0 means the authenticator doesn't keep one.
        data.extend_from_slice(&0u32.to_be_bytes());
        data
    }

    const USER_PRESENT: u8 = 0b0000_0001;
    const USER_VERIFIED: u8 = 0b0000_0100;
    const ATTESTED_CREDENTIAL_DATA: u8 = 0b0100_0000;
    const EXTENSION_DATA: u8 = 0b1000_0000;

    fn attestation_authenticator_data(
        credential_id: &[u8; 32],
        key: &SigningKey,
        len: u32,
    ) -> Vec<u8> {
        let mut data =
            authenticator_data_header(USER_PRESENT | USER_VERIFIED | ATTESTED_CREDENTIAL_DATA);
        // AAGUID
        data.extend_from_slice(&[0u8; 16]);
        data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(credential_id);

        let point = key.verifying_key().to_encoded_point(false);
        let cose_key = |padding: Value| {
            CoseKeyBuilder::new_ec2_pub_key(
                iana::EllipticCurve::P_256,
                point.x().expect("uncompressed point; qed").to_vec(),
                point.y().expect("uncompressed point; qed").to_vec(),
            )
            .algorithm(iana::Algorithm::ES256)
            .param(1000, padding)
            .build()
            .to_vec()
            .expect("encoding a COSE key doesn't fail; qed")
        };

        // Nothing may follow the credential public key (the parser rejects extensions next to
        // it), so the padding goes inside it, as an extra parameter.
        let unpadded = data.len() + cose_key(padding(1)).len();
        let padding_len = (len as usize).saturating_sub(unpadded) + 1;
        data.extend(cose_key(padding(padding_len)));
        data
    }

    fn assertion_authenticator_data(len: u32) -> Vec<u8> {
        let len = len as usize;
        if len <= MIN_ASSERTION_AUTHENTICATOR_DATA_LEN as usize {
            return authenticator_data_header(USER_PRESENT | USER_VERIFIED);
        }

        let mut data = authenticator_data_header(USER_PRESENT | USER_VERIFIED | EXTENSION_DATA);
        let extensions = padding(len - data.len())
            .to_vec()
            .expect("encoding CBOR doesn't fail; qed");
        data.extend(extensions);
        data
    }

    /// Returns a valid [`Attestation`] of a freshly generated P-256 key for `authority_id`,
    /// answering `challenge` (generated from `context`), with the requested `lengths`.
    pub fn attestation<Cx>(
        authority_id: AuthorityId,
        context: Cx,
        challenge: Challenge,
        lengths: Lengths,
    ) -> Attestation<Cx> {
        let credential_id = blake2_256(&(PREFIX, next_nonce()).encode());
        let seed = blake2_256(&[&credential_id[..], b"seed"].concat());
        let key = signing_key(&seed);
        let device_id = blake2_256(&credential_id);
        unhashed::put(&storage_key(&device_id), &seed);

        Attestation {
            meta: AttestationMeta {
                authority_id,
                device_id,
                context,
            },
            authenticator_data: attestation_authenticator_data(
                &credential_id,
                &key,
                lengths.authenticator_data,
            ),
            client_data: client_data("webauthn.create", &challenge, lengths.client_data)
                .try_into()
                .expect("helpers are never asked for more than 1024 bytes; qed"),
            public_key: der_public_key(&key),
        }
    }

    /// Returns a valid [`Assertion`] of `user_id` for `authority_id`, answering `challenge`
    /// (generated from `context`), signed with the key registered as `device_id` by
    /// [`attestation`], with the requested `lengths`.
    pub fn assertion<Cx>(
        authority_id: AuthorityId,
        user_id: HashedUserId,
        device_id: DeviceId,
        context: Cx,
        challenge: Challenge,
        lengths: Lengths,
    ) -> Assertion<Cx> {
        let seed: [u8; 32] = unhashed::get(&storage_key(&device_id))
            .expect("devices are registered through `attestation`; qed");
        let key = signing_key(&seed);

        let authenticator_data = assertion_authenticator_data(lengths.authenticator_data);
        let client_data = client_data("webauthn.get", &challenge, lengths.client_data);
        let signature: Signature =
            key.sign(&[&authenticator_data[..], &sha2_256(&client_data)].concat());

        Assertion {
            meta: AssertionMeta {
                authority_id,
                user_id,
                context,
            },
            authenticator_data,
            client_data: client_data
                .try_into()
                .expect("helpers are never asked for more than 1024 bytes; qed"),
            signature: signature.to_der().as_bytes().to_vec(),
        }
    }
}

/// Registers a freshly generated P-256 key, with the shortest client data and authenticator
/// data: `fc-pallet-pass` measures its own overhead with these inputs, and charges verifying
/// the actual attestation separately, through [`DeviceChallengeResponse::verification_weight`].
impl<Cx> DeviceAttestationBenchmarkHelper<Cx> for Attestation<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn benchmark_attestation(authority: AuthorityId, context: Cx, challenge: Challenge) -> Self {
        helpers::attestation(authority, context, challenge, helpers::Lengths::default())
    }
}

/// Signs with the key registered as `device_id`, with the shortest client data and
/// authenticator data (see the attestation helper for why).
impl<Cx> CredentialBenchmarkHelper<Cx> for Assertion<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn benchmark_credential(
        authority: AuthorityId,
        user_id: HashedUserId,
        device_id: DeviceId,
        context: Cx,
        challenge: Challenge,
    ) -> Self {
        helpers::assertion(
            authority,
            user_id,
            device_id,
            context,
            challenge,
            helpers::Lengths::default(),
        )
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

fn lengths(c: u32, a: u32) -> helpers::Lengths {
    helpers::Lengths {
        client_data: c,
        authenticator_data: a,
    }
}

fn attestation(lengths: helpers::Lengths) -> Attestation<u32> {
    helpers::attestation(
        BenchAuthority::get(),
        CONTEXT,
        BenchChallenger::generate(&CONTEXT, &XTC),
        lengths,
    )
}

/// A device registered through the authenticator's [`AuthenticatorBenchmarkHelper`] (what
/// `fc-pallet-pass`'s benchmarks use), and an assertion of it with the given `lengths`.
fn device_and_assertion(lengths: helpers::Lengths) -> (BenchDevice, Assertion<u32>) {
    let attestation = BenchAuthenticator::device_attestation(&XTC);
    let device_id = *attestation.device_id();
    let device =
        BenchAuthenticator::verify_device(attestation, &XTC).expect("attestation is valid; qed");
    let assertion = helpers::assertion(
        BenchAuthority::get(),
        USER,
        device_id,
        CONTEXT,
        BenchChallenger::generate(&CONTEXT, &XTC),
        lengths,
    );
    (device, assertion)
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
    fn verify_attestation(
        c: Linear<MIN_CLIENT_DATA_LEN, MAX_CLIENT_DATA_LEN>,
        a: Linear<MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN, MAX_AUTHENTICATOR_DATA_LEN>,
    ) {
        let attestation = attestation(lengths(c, a));
        let device;
        #[block]
        {
            device = BenchAuthenticator::verify_device(attestation, &XTC);
        }
        assert!(device.is_some());
    }

    #[benchmark]
    fn verify_credential(
        c: Linear<MIN_CLIENT_DATA_LEN, MAX_CLIENT_DATA_LEN>,
        a: Linear<MIN_ASSERTION_AUTHENTICATOR_DATA_LEN, MAX_AUTHENTICATOR_DATA_LEN>,
    ) {
        let (mut device, assertion) = device_and_assertion(lengths(c, a));
        let result;
        #[block]
        {
            result = device.verify_user(&assertion, &XTC);
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
    use traits_authn::UserChallengeResponse;

    #[test]
    fn helpers_produce_fresh_devices() {
        mock::new_test_ext().execute_with(|| {
            let a = BenchAuthenticator::device_attestation(&XTC);
            let b = BenchAuthenticator::device_attestation(&XTC);
            assert_ne!(a.device_id(), b.device_id());
        })
    }

    #[test]
    fn minimum_lengths_are_the_benchmarks_lower_bounds() {
        mock::new_test_ext().execute_with(|| {
            let (_, assertion) = device_and_assertion(helpers::Lengths::default());
            let attestation = attestation(helpers::Lengths::default());

            assert_eq!(
                attestation.client_data.len() as u32,
                MIN_CLIENT_DATA_LEN,
                "attestation client data"
            );
            assert_eq!(
                attestation.authenticator_data.len() as u32,
                MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN,
                "attestation authenticator data"
            );
            assert_eq!(
                assertion.authenticator_data.len() as u32,
                MIN_ASSERTION_AUTHENTICATOR_DATA_LEN,
                "assertion authenticator data"
            );
            assert!(assertion.client_data.len() as u32 <= MIN_CLIENT_DATA_LEN);
        })
    }

    #[test]
    fn helpers_hit_the_requested_lengths() {
        mock::new_test_ext().execute_with(|| {
            for c in (MIN_CLIENT_DATA_LEN..=MAX_CLIENT_DATA_LEN).step_by(7) {
                for a in (MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN..=MAX_AUTHENTICATOR_DATA_LEN)
                    .step_by(97)
                    .chain([256, 257, 258, 259, 260])
                {
                    let attestation = attestation(lengths(c, a));
                    assert_eq!(attestation.client_data.len() as u32, c);
                    let actual = attestation.authenticator_data.len() as u32;
                    assert!((a..=a + 2).contains(&actual), "a={a}, actual={actual}");
                    assert!(
                        BenchAuthenticator::verify_device(attestation, &XTC).is_some(),
                        "c={c}, a={a}"
                    );
                }
            }

            for a in (MIN_ASSERTION_AUTHENTICATOR_DATA_LEN..=MAX_AUTHENTICATOR_DATA_LEN)
                .step_by(13)
                .chain(37..=70)
            {
                let (mut device, assertion) = device_and_assertion(lengths(MAX_CLIENT_DATA_LEN, a));
                assert_eq!(assertion.client_data.len() as u32, MAX_CLIENT_DATA_LEN);
                let actual = assertion.authenticator_data.len() as u32;
                assert!((a..=a + 2).contains(&actual), "a={a}, actual={actual}");
                assert!(assertion.is_valid());
                assert!(device.verify_user(&assertion, &XTC).is_some(), "a={a}");
            }
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
