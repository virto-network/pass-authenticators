use crate::mock::*;
use crate::{
    btc::recover_btc_pubkey_hash, BtcPubkeyHash, BtcRegistration, BtcSignature, SignedMessage,
};
use frame::{
    deps::sp_core::{ecdsa, Pair},
    testing_prelude::*,
    traits::TxBaseImplication,
};
use sp_io::hashing::sha2_256;
use traits_authn::{Challenger, ExtrinsicContext, HashedUserId};

const USER: HashedUserId = *b"satoshi\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
parameter_types! {
    pub BtcKey: ecdsa::Pair = ecdsa::Pair::from_seed(&[2u8; 32]);
    pub UserAddress: AccountId = Pass::address_for(USER);
}

/// Derive BtcPubkeyHash from a key pair using real HASH160.
fn btc_pubkey_hash_of(pair: &ecdsa::Pair) -> BtcPubkeyHash {
    use ripemd::{Digest, Ripemd160};
    let dummy_msg = [0u8; 32];
    let sig = pair.sign_prehashed(&dummy_msg);
    let pubkey = sp_io::crypto::secp256k1_ecdsa_recover_compressed(&sig.0, &dummy_msg)
        .ok()
        .expect("recovery works");
    let sha = sha2_256(&pubkey);
    let mut hasher = Ripemd160::new();
    hasher.update(sha);
    let h160: [u8; 20] = hasher.finalize().into();
    BtcPubkeyHash::from_hash160(h160)
}

fn make_signature(xtc: &impl ExtrinsicContext) -> (SignedMessage<u64>, BtcPubkeyHash, [u8; 65]) {
    let context = System::block_number();
    let message = SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: AuthorityId::get(),
    };
    let pair = BtcKey::get();
    let pubkey_hash = btc_pubkey_hash_of(&pair);
    let signature = message.sign(&pair);

    (message, pubkey_hash, signature)
}

mod registration {
    use super::*;

    #[test]
    fn registration_fails_if_attestation_is_invalid() {
        new_test_ext().execute_with(|| {
            let (mut message, pubkey_hash, signature) = make_signature(&[]);
            message.challenge = [0u8; 32];

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    BtcRegistration {
                        pubkey_hash,
                        message,
                        signature,
                    }
                ),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }

    #[test]
    fn registration_fails_with_wrong_pubkey_hash() {
        new_test_ext().execute_with(|| {
            let (message, _pubkey_hash, signature) = make_signature(&UserAddress::get().encode());
            let wrong = BtcPubkeyHash::from_hash160([0xAB; 20]);

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    BtcRegistration {
                        pubkey_hash: wrong,
                        message,
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
            let (message, pubkey_hash, signature) = make_signature(&UserAddress::get().encode());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                BtcRegistration {
                    pubkey_hash,
                    message,
                    signature,
                }
            ));
        })
    }
}

mod authentication {
    use super::*;

    fn new_test_ext() -> TestExternalities {
        let mut t = super::new_test_ext();
        t.execute_with(|| {
            let (message, pubkey_hash, signature) = make_signature(&UserAddress::get().encode());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                BtcRegistration {
                    pubkey_hash,
                    message,
                    signature,
                }
            ));
        });
        t
    }

    #[test]
    fn authentication_fails_if_credentials_are_invalid() {
        new_test_ext().execute_with(|| {
            let (message, pubkey_hash, signature) = make_signature(&[]);

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                pubkey_hash.as_ref().clone(),
                BtcSignature {
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

            let (message, pubkey_hash, signature) = make_signature(
                &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
            );

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                pubkey_hash.as_ref().clone(),
                BtcSignature {
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
}

mod btc_signing {
    use super::*;

    #[test]
    fn recover_works_with_compressed_flag() {
        new_test_ext().execute_with(|| {
            let pair = BtcKey::get();
            let message = b"hello bitcoin";
            let hash = crate::btc::bitcoin_message_hash(message);
            let raw = pair.sign_prehashed(&hash);
            // BIP-137 compressed format
            let mut sig = [0u8; 65];
            sig[0] = 31 + raw.0[64];
            sig[1..].copy_from_slice(&raw.0[..64]);

            let recovered = recover_btc_pubkey_hash(&hash, &sig).expect("should recover");
            let expected = btc_pubkey_hash_of(&pair);
            assert_eq!(recovered, expected);
        })
    }

    #[test]
    fn recover_fails_with_invalid_flag() {
        new_test_ext().execute_with(|| {
            let pair = BtcKey::get();
            let hash = crate::btc::bitcoin_message_hash(b"test");
            let raw = pair.sign_prehashed(&hash);
            let mut sig = [0u8; 65];
            sig[0] = 99; // Invalid flag
            sig[1..].copy_from_slice(&raw.0[..64]);

            assert!(recover_btc_pubkey_hash(&hash, &sig).is_none());
        })
    }

    #[test]
    fn recover_rejects_raw_recovery_id() {
        new_test_ext().execute_with(|| {
            let pair = BtcKey::get();
            let hash = crate::btc::bitcoin_message_hash(b"test");
            let raw = pair.sign_prehashed(&hash);
            // Use raw recovery id (0) instead of BIP-137 flag — must be rejected
            let mut sig = [0u8; 65];
            sig[0] = 0;
            sig[1..].copy_from_slice(&raw.0[..64]);

            assert!(recover_btc_pubkey_hash(&hash, &sig).is_none());
        })
    }

    #[test]
    fn recover_works_with_uncompressed_flag() {
        new_test_ext().execute_with(|| {
            use ripemd::{Digest, Ripemd160};
            let pair = BtcKey::get();
            let hash = crate::btc::bitcoin_message_hash(b"hello uncompressed");
            let raw = pair.sign_prehashed(&hash);

            // BIP-137 uncompressed format: flag 27 + recovery_id
            let mut sig = [0u8; 65];
            sig[0] = 27 + raw.0[64];
            sig[1..].copy_from_slice(&raw.0[..64]);

            let recovered = recover_btc_pubkey_hash(&hash, &sig).expect("should recover");

            // Derive expected hash from uncompressed pubkey
            let pubkey_uncompressed = sp_io::crypto::secp256k1_ecdsa_recover(&raw.0, &hash)
                .ok()
                .unwrap();
            let mut full = [0u8; 65];
            full[0] = 0x04;
            full[1..].copy_from_slice(&pubkey_uncompressed);
            let sha = sha2_256(&full);
            let mut hasher = Ripemd160::new();
            hasher.update(sha);
            let expected_h160: [u8; 20] = hasher.finalize().into();

            assert_eq!(recovered, BtcPubkeyHash::from_hash160(expected_h160));
        })
    }

    #[test]
    fn recover_fails_with_zero_signature() {
        new_test_ext().execute_with(|| {
            let hash = crate::btc::bitcoin_message_hash(b"test");
            let sig = [0u8; 65];
            assert!(recover_btc_pubkey_hash(&hash, &sig).is_none());
        })
    }

    #[test]
    fn recover_accepts_boundary_flags() {
        new_test_ext().execute_with(|| {
            let pair = BtcKey::get();
            let hash = crate::btc::bitcoin_message_hash(b"boundary");
            let raw = pair.sign_prehashed(&hash);

            // Flag 34 is the maximum valid compressed flag (31 + 3)
            // Only test if recovery_id <= 3
            if raw.0[64] <= 1 {
                let mut sig = [0u8; 65];
                sig[0] = 31 + raw.0[64]; // Valid compressed flag
                sig[1..].copy_from_slice(&raw.0[..64]);
                assert!(recover_btc_pubkey_hash(&hash, &sig).is_some());
            }

            // Flag 35 must always be rejected
            let mut sig = [0u8; 65];
            sig[0] = 35;
            sig[1..].copy_from_slice(&raw.0[..64]);
            assert!(recover_btc_pubkey_hash(&hash, &sig).is_none());

            // Flag 26 must be rejected
            sig[0] = 26;
            assert!(recover_btc_pubkey_hash(&hash, &sig).is_none());
        })
    }
}

mod verification_weight {
    use super::*;
    use crate::WeightInfo as _;
    use frame_support::weights::Weight;
    use traits_authn::{
        AuthenticatorWeightInfo, DeviceChallengeResponse, UserAuthenticator, UserChallengeResponse,
    };

    /// The weights the mock runtime binds...
    type Weights = crate::DefaultWeights<Test>;
    /// ...which are the ones in this crate's `weights.rs`.
    type Measured = crate::SubstrateWeight<Test>;
    type Authn = <Test as pallet_pass::Config>::Authenticator;
    type Device = <Authn as traits_authn::Authenticator>::Device;

    /// A registration or a signature is fixed-size, and whether its key is compressed isn't
    /// something the weight components can tell apart: both forms are charged the costliest.
    #[test]
    fn weights_cover_both_key_forms() {
        let attestations = [
            Measured::verify_attestation_compressed(),
            Measured::verify_attestation_uncompressed(),
        ];
        let credentials = [
            Measured::verify_credential_compressed(),
            Measured::verify_credential_uncompressed(),
        ];
        new_test_ext().execute_with(|| {
            // BIP-137: flags 31-34 are for compressed keys, and 27-30 for uncompressed ones.
            for flag in [27, 31] {
                let (message, pubkey_hash, mut signature) = make_signature(&[]);
                signature[0] = flag;

                let registration = BtcRegistration {
                    pubkey_hash,
                    message: message.clone(),
                    signature,
                };
                assert_eq!(registration.weight_components(), (0, 0), "flag {flag}");
                let weight =
                    <Authn as traits_authn::Authenticator>::verification_weight(&registration);
                assert!(weight.ref_time() > 0, "flag {flag}");
                assert_eq!(
                    weight,
                    <Weights as AuthenticatorWeightInfo>::verify_device(0, 0),
                    "flag {flag}"
                );
                for b in attestations {
                    assert!(weight.all_gte(b), "flag {flag}");
                }

                let credential = BtcSignature {
                    user_id: USER,
                    message,
                    signature,
                };
                assert_eq!(credential.weight_components(), (0, 0), "flag {flag}");
                let weight = <Device as UserAuthenticator>::verification_weight(&credential);
                assert!(weight.ref_time() > 0, "flag {flag}");
                assert_eq!(
                    weight,
                    <Weights as AuthenticatorWeightInfo>::verify_user(0, 0),
                    "flag {flag}"
                );
                for b in credentials {
                    assert!(weight.all_gte(b), "flag {flag}");
                }
            }
        })
    }

    #[test]
    fn unit_weights_are_the_same_as_substrate_weight() {
        assert_eq!(
            <() as crate::WeightInfo>::verify_attestation_compressed(),
            Measured::verify_attestation_compressed()
        );
        assert_eq!(
            <() as crate::WeightInfo>::verify_attestation_uncompressed(),
            Measured::verify_attestation_uncompressed()
        );
        assert_eq!(
            <() as crate::WeightInfo>::verify_credential_compressed(),
            Measured::verify_credential_compressed()
        );
        assert_eq!(
            <() as crate::WeightInfo>::verify_credential_uncompressed(),
            Measured::verify_credential_uncompressed()
        );
    }

    /// A runtime's own run of the benchmarks, with made-up numbers far from the ones here,
    /// where the uncompressed form is the costliest for registrations and the compressed one for
    /// credentials.
    struct OwnWeights;
    impl crate::WeightInfo for OwnWeights {
        fn verify_attestation_compressed() -> Weight {
            Weight::from_parts(1_000, 1)
        }
        fn verify_attestation_uncompressed() -> Weight {
            Weight::from_parts(2_000, 2)
        }
        fn verify_credential_compressed() -> Weight {
            Weight::from_parts(4_000, 4)
        }
        fn verify_credential_uncompressed() -> Weight {
            Weight::from_parts(3_000, 3)
        }
    }

    #[test]
    fn a_runtime_can_bind_its_own_weights() {
        type Own = crate::Weights<OwnWeights>;
        assert_eq!(
            <Own as AuthenticatorWeightInfo>::verify_device(0, 0),
            OwnWeights::verify_attestation_uncompressed()
        );
        assert_eq!(
            <Own as AuthenticatorWeightInfo>::verify_user(0, 0),
            OwnWeights::verify_credential_compressed()
        );
    }
}

/// The helpers `fc-pallet-pass`'s benchmarks use produce inputs the pallet accepts.
#[cfg(feature = "runtime-benchmarks")]
mod benchmark_helpers {
    use super::*;
    use frame::traits::TxBaseImplication;
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
