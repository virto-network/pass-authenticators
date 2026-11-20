use crate::mock::*;
use crate::{KeyRegistration, KeySignature, Sign, SignedMessage};
use frame::{
    deps::{
        sp_core::{sr25519, Pair},
        sp_keyring::sr25519::Keyring,
        sp_runtime::{str_array as s, MultiSignature},
    },
    testing_prelude::*,
    traits::TxBaseImplication,
};

use traits_authn::{Challenger, ExtrinsicContext, HashedUserId};

const USER: HashedUserId = s("alice");
parameter_types! {
    pub Alice: sr25519::Pair = Keyring::Alice.pair();
    pub UserAddress: AccountId = Pass::address_for(USER);
}

fn make_signature(xtc: &impl ExtrinsicContext) -> (SignedMessage<u64>, AccountId, MultiSignature) {
    let context = System::block_number();
    let message = SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: AuthorityId::get(),
    };
    let public = Alice::get().public().into();
    let signature = message.sign(Alice::get());

    (message, public, signature)
}

/// What a key signs, given the message it's asked to sign.
type Wrapping = fn(&[u8]) -> Vec<u8>;

/// The same as [`make_signature`], but the key signs `signed(message)` instead of the message.
fn make_signature_over(
    xtc: &impl ExtrinsicContext,
    signed: Wrapping,
) -> (SignedMessage<u64>, AccountId, MultiSignature) {
    let (message, public, _) = make_signature(xtc);
    let signature = Alice::get().sign(&signed(message.message().as_ref()));

    (message, public, signature.into())
}

/// What a browser wallet extension signs when it's asked to sign `message` as raw bytes.
fn wrapped(message: &[u8]) -> Vec<u8> {
    [b"<Bytes>".as_slice(), message, b"</Bytes>"].concat()
}

/// Wrappings of a message which aren't the one of browser wallet extensions.
const WRONG_WRAPPINGS: [(&str, Wrapping); 6] = [
    ("not closed", |m| [b"<Bytes>".as_slice(), m].concat()),
    ("not opened", |m| [m, b"</Bytes>".as_slice()].concat()),
    ("other case", |m| {
        [b"<bytes>".as_slice(), m, b"</bytes>"].concat()
    }),
    ("swapped tags", |m| {
        [b"</Bytes>".as_slice(), m, b"<Bytes>"].concat()
    }),
    ("padded", |m| {
        [b"<Bytes> ".as_slice(), m, b" </Bytes>"].concat()
    }),
    ("wrapped twice", |m| wrapped(&wrapped(m))),
];

mod wrapped_message {
    use super::*;
    use frame::deps::sp_core::{ecdsa, ed25519};
    use frame::deps::sp_runtime::MultiSigner;

    fn message() -> SignedMessage<u64> {
        SignedMessage {
            context: 1,
            challenge: [2u8; 32],
            authority_id: [3u8; 32],
        }
    }

    #[test]
    fn wraps_the_message_as_wallet_extensions_do() {
        let message = message();
        assert_eq!(
            message.wrapped_message().as_ref(),
            wrapped(message.message().as_ref())
        );
    }

    #[test]
    fn every_key_type_signs_either_form_and_no_other() {
        let message = message();
        let ed25519 = ed25519::Pair::from_seed(&[1u8; 32]);
        let ecdsa = ecdsa::Pair::from_seed(&[1u8; 32]);
        let eth = ecdsa::KeccakPair::from_seed(&[1u8; 32]);

        type Signer<'a> = (&'a str, AccountId, &'a dyn Fn(&[u8]) -> MultiSignature);
        let signers: [Signer; 4] = [
            ("sr25519", Alice::get().public().into(), &|m| {
                Alice::get().sign(m).into()
            }),
            ("ed25519", ed25519.public().into(), &|m| {
                ed25519.sign(m).into()
            }),
            (
                "ecdsa",
                MultiSigner::from(ecdsa.public()).into_account(),
                &|m| ecdsa.sign(m).into(),
            ),
            ("eth", MultiSigner::Eth(eth.public()).into_account(), &|m| {
                MultiSignature::Eth(eth.sign(m))
            }),
        ];

        for (key_type, signer, sign) in signers {
            let bare = message.message();
            assert!(
                message.is_signed_by(&sign(bare.as_ref()), &signer),
                "{key_type}: bare"
            );
            assert!(
                message.is_signed_by(&sign(&wrapped(bare.as_ref())), &signer),
                "{key_type}: wrapped"
            );
            for (wrapping, wrap) in WRONG_WRAPPINGS {
                assert!(
                    !message.is_signed_by(&sign(&wrap(bare.as_ref())), &signer),
                    "{key_type}: {wrapping}"
                );
            }
        }
    }
}

mod registration {
    use super::*;

    #[test]
    fn registration_fails_if_attestation_is_invalid() {
        new_test_ext().execute_with(|| {
            let (mut message, public, signature) = make_signature(&[]);

            // Alters "challenge", so this will fail
            message.challenge = [0u8; 32];

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    KeyRegistration {
                        message,
                        public,
                        signature,
                    }
                ),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }

    #[test]
    fn registration_works_if_attestation_is_valid() {
        new_test_ext().execute_with(|| {
            let (message, public, signature) = make_signature(&UserAddress::get().encode());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                KeyRegistration {
                    message,
                    public,
                    signature,
                }
            ));
        })
    }

    #[test]
    fn registration_works_if_attestation_signs_the_wrapped_message() {
        new_test_ext().execute_with(|| {
            let (message, public, signature) =
                make_signature_over(&UserAddress::get().encode(), wrapped);

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                KeyRegistration {
                    message,
                    public,
                    signature,
                }
            ));
        })
    }

    #[test]
    fn registration_fails_if_attestation_signs_a_wrong_wrapping() {
        new_test_ext().execute_with(|| {
            for (wrapping, wrap) in WRONG_WRAPPINGS {
                let (message, public, signature) =
                    make_signature_over(&UserAddress::get().encode(), wrap);

                assert_eq!(
                    Pass::register(
                        RuntimeOrigin::root(),
                        USER,
                        KeyRegistration {
                            message,
                            public,
                            signature,
                        }
                    ),
                    Err(pallet_pass::Error::<Test>::DeviceAttestationInvalid.into()),
                    "{wrapping}"
                );
            }
        })
    }
}

mod authentication {
    use super::*;

    fn new_test_ext() -> TestExternalities {
        let mut t = super::new_test_ext();
        t.execute_with(|| {
            let (message, public, signature) = make_signature(&UserAddress::get().encode());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                KeyRegistration {
                    message,
                    public,
                    signature
                }
            ));
        });
        t
    }

    #[test]
    fn authentication_fails_if_credentials_are_invalid() {
        new_test_ext().execute_with(|| {
            let (message, public, signature) = make_signature(&[]);

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                public.into(),
                KeySignature {
                    user_id: USER,
                    message,
                    signature,
                },
            );

            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();

            assert_noop!(
                ext.validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    0
                )
                .map(|_| ()),
                InvalidTransaction::BadSigner
            );
        })
    }

    #[test]
    fn authentication_works_if_credentials_are_valid() {
        new_test_ext().execute_with(|| {
            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();

            let (message, public, signature) = make_signature(
                &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
            );

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                public.into(),
                KeySignature {
                    user_id: USER,
                    message,
                    signature,
                },
            );

            assert_ok!(ext
                .validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    0
                )
                .map(|_| ()));
        })
    }

    /// Validates a `remark` authenticated by a credential where the key signs `signed(message)`.
    fn validate_signing(signed: Wrapping) -> Result<(), TransactionValidityError> {
        let extrinsic_version: u8 = 0;
        let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();

        let (message, public, signature) = make_signature_over(
            &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
            signed,
        );

        pallet_pass::PassAuthenticate::<Test>::from(
            public.into(),
            KeySignature {
                user_id: USER,
                message,
                signature,
            },
        )
        .validate_only(
            None.into(),
            &call,
            &call.get_dispatch_info(),
            call.encoded_size(),
            TransactionSource::External,
            0,
        )
        .map(|_| ())
    }

    #[test]
    fn authentication_works_if_credentials_sign_the_wrapped_message() {
        new_test_ext().execute_with(|| {
            assert_ok!(validate_signing(wrapped));
        })
    }

    #[test]
    fn authentication_fails_if_credentials_sign_a_wrong_wrapping() {
        new_test_ext().execute_with(|| {
            for (wrapping, wrap) in WRONG_WRAPPINGS {
                assert_eq!(
                    validate_signing(wrap),
                    Err(InvalidTransaction::BadSigner.into()),
                    "{wrapping}"
                );
            }
        })
    }
}

mod verification_weight {
    use super::*;
    use crate::WeightInfo as _;
    use frame::deps::sp_core::{ecdsa, ed25519};
    use traits_authn::{
        AuthenticatorWeightInfo, DeviceChallengeResponse, UserAuthenticator, UserChallengeResponse,
    };

    /// The weights the mock runtime binds...
    type Weights = crate::DefaultWeights<Test>;
    /// ...which are the ones this crate's benchmarks measured.
    type Measured = crate::SubstrateWeight<Test>;
    type Authn = <Test as pallet_pass::Config>::Authenticator;
    type Device = <Authn as traits_authn::Authenticator>::Device;

    fn signatures() -> [(MultiSignature, &'static str); 4] {
        let message = SignedMessage {
            context: 1u64,
            challenge: [0u8; 32],
            authority_id: AuthorityId::get(),
        };
        [
            (message.sign(Alice::get()), "sr25519"),
            (
                message.sign(ed25519::Pair::from_seed(&[1u8; 32])),
                "ed25519",
            ),
            (message.sign(ecdsa::Pair::from_seed(&[1u8; 32])), "ecdsa"),
            (
                MultiSignature::Eth(
                    ecdsa::KeccakPair::from_seed(&[1u8; 32]).sign(message.message().as_ref()),
                ),
                "eth",
            ),
        ]
    }

    #[test]
    fn attestation_weight_covers_every_key_type() {
        let (message, public, _) = new_test_ext().execute_with(|| make_signature(&[]));
        let benchmarked = [
            Measured::verify_attestation_sr25519(),
            Measured::verify_attestation_ed25519(),
            Measured::verify_attestation_ecdsa(),
            Measured::verify_attestation_eth(),
        ];
        for (signature, key_type) in signatures() {
            let registration = KeyRegistration {
                public: public.clone(),
                message: message.clone(),
                signature,
            };
            assert_eq!(registration.weight_components(), (0, 0), "{key_type}");

            let weight = <Authn as traits_authn::Authenticator>::verification_weight(&registration);
            assert!(weight.ref_time() > 0, "{key_type}");
            assert_eq!(
                weight,
                <Weights as AuthenticatorWeightInfo>::verify_device(0, 0),
                "{key_type}"
            );
            for b in benchmarked {
                assert!(weight.all_gte(b), "{key_type}");
            }
        }
    }

    #[test]
    fn credential_weight_covers_every_key_type() {
        let (message, _, _) = new_test_ext().execute_with(|| make_signature(&[]));
        let benchmarked = [
            Measured::verify_credential_sr25519(),
            Measured::verify_credential_ed25519(),
            Measured::verify_credential_ecdsa(),
            Measured::verify_credential_eth(),
        ];
        for (signature, key_type) in signatures() {
            let credential = KeySignature {
                user_id: USER,
                message: message.clone(),
                signature,
            };
            assert_eq!(credential.weight_components(), (0, 0), "{key_type}");

            let weight = <Device as UserAuthenticator>::verification_weight(&credential);
            assert!(weight.ref_time() > 0, "{key_type}");
            assert_eq!(
                weight,
                <Weights as AuthenticatorWeightInfo>::verify_user(0, 0),
                "{key_type}"
            );
            for b in benchmarked {
                assert!(weight.all_gte(b), "{key_type}");
            }
        }
    }

    #[test]
    fn unit_weights_are_the_measured_ones() {
        use crate::WeightInfo;
        assert_eq!(
            <() as WeightInfo>::verify_attestation_sr25519(),
            Measured::verify_attestation_sr25519()
        );
        assert_eq!(
            <() as WeightInfo>::verify_attestation_ed25519(),
            Measured::verify_attestation_ed25519()
        );
        assert_eq!(
            <() as WeightInfo>::verify_attestation_ecdsa(),
            Measured::verify_attestation_ecdsa()
        );
        assert_eq!(
            <() as WeightInfo>::verify_attestation_eth(),
            Measured::verify_attestation_eth()
        );
        assert_eq!(
            <() as WeightInfo>::verify_credential_sr25519(),
            Measured::verify_credential_sr25519()
        );
        assert_eq!(
            <() as WeightInfo>::verify_credential_ed25519(),
            Measured::verify_credential_ed25519()
        );
        assert_eq!(
            <() as WeightInfo>::verify_credential_ecdsa(),
            Measured::verify_credential_ecdsa()
        );
        assert_eq!(
            <() as WeightInfo>::verify_credential_eth(),
            Measured::verify_credential_eth()
        );
    }

    /// A runtime's own run of the benchmarks, with made-up numbers far from the measured ones,
    /// where a different key type is the costliest for registrations and for signatures.
    struct OwnWeights;
    impl crate::WeightInfo for OwnWeights {
        fn verify_attestation_sr25519() -> Weight {
            Weight::from_parts(1_000, 1)
        }
        fn verify_attestation_ed25519() -> Weight {
            Weight::from_parts(9_000_000_000, 2)
        }
        fn verify_attestation_ecdsa() -> Weight {
            Weight::from_parts(3_000, 3)
        }
        fn verify_attestation_eth() -> Weight {
            Weight::from_parts(4_000, 4)
        }
        fn verify_credential_sr25519() -> Weight {
            Weight::from_parts(5_000, 5)
        }
        fn verify_credential_ed25519() -> Weight {
            Weight::from_parts(6_000, 6)
        }
        fn verify_credential_ecdsa() -> Weight {
            Weight::from_parts(7_000, 7)
        }
        fn verify_credential_eth() -> Weight {
            Weight::from_parts(8_000_000_000, 8)
        }
    }

    #[test]
    fn a_runtimes_own_weights_flow_through_the_adapter() {
        type Own = crate::Weights<OwnWeights>;
        type OwnAuthn = crate::Authenticator<BlockChallenger, AuthorityId, Own>;
        type OwnDevice = <OwnAuthn as traits_authn::Authenticator>::Device;

        // The costliest key type, as for the measured weights (`Weight::max` is per component).
        let device = Weight::from_parts(9_000_000_000, 4);
        let user = Weight::from_parts(8_000_000_000, 8);
        assert_eq!(
            <Own as AuthenticatorWeightInfo>::verify_device(0, 0),
            device
        );
        assert_eq!(<Own as AuthenticatorWeightInfo>::verify_user(0, 0), user);

        // It's what an authenticator bound to them charges, instead of the measured weights.
        let (message, public, _) = new_test_ext().execute_with(|| make_signature(&[]));
        for (signature, key_type) in signatures() {
            let registration = KeyRegistration {
                public: public.clone(),
                message: message.clone(),
                signature: signature.clone(),
            };
            assert_eq!(
                <OwnAuthn as traits_authn::Authenticator>::verification_weight(&registration),
                device,
                "{key_type}"
            );
            assert_ne!(
                <Authn as traits_authn::Authenticator>::verification_weight(&registration),
                device,
                "{key_type}"
            );

            let credential = KeySignature {
                user_id: USER,
                message: message.clone(),
                signature,
            };
            assert_eq!(
                <OwnDevice as UserAuthenticator>::verification_weight(&credential),
                user,
                "{key_type}"
            );
            assert_ne!(
                <Device as UserAuthenticator>::verification_weight(&credential),
                user,
                "{key_type}"
            );
        }
    }
}

/// The helpers `fc-pallet-pass`'s benchmarks use produce inputs the pallet accepts.
#[cfg(feature = "runtime-benchmarks")]
mod benchmark_helpers {
    use super::*;
    use traits_authn::{AuthenticatorBenchmarkHelper, DeviceChallengeResponse};

    type Authenticator =
        crate::Authenticator<BlockChallenger, AuthorityId, crate::DefaultWeights<Test>>;

    #[test]
    fn helpers_register_and_authenticate() {
        new_test_ext().execute_with(|| {
            let attestation = Authenticator::device_attestation(&UserAddress::get().encode());
            let device_id = *attestation.device_id();
            assert_ok!(Pass::register(RuntimeOrigin::root(), USER, attestation));

            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();
            let credential = Authenticator::credential(
                USER,
                device_id,
                &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
            );

            assert_ok!(
                pallet_pass::PassAuthenticate::<Test>::from(device_id, credential)
                    .validate_only(
                        None.into(),
                        &call,
                        &call.get_dispatch_info(),
                        call.encoded_size(),
                        TransactionSource::External,
                        0
                    )
                    .map(|_| ())
            );
        })
    }
}
