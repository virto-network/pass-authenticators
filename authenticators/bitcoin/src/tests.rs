use crate::mock::*;
use crate::{
    btc::recover_btc_pubkey_hash, BtcPubkeyHash, BtcRegistration, BtcSignature, Sign, SignedMessage,
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

/// Derive BtcPubkeyHash from a key pair (matching our hash160 implementation).
fn btc_pubkey_hash_of(pair: &ecdsa::Pair) -> BtcPubkeyHash {
    let dummy_msg = [0u8; 32];
    let sig = pair.sign_prehashed(&dummy_msg);
    let pubkey = sp_io::crypto::secp256k1_ecdsa_recover_compressed(&sig.0, &dummy_msg)
        .ok()
        .expect("recovery works");
    // Our hash160 implementation: first 20 bytes of SHA256(SHA256(data))
    let hash = sha2_256(&sha2_256(&pubkey));
    let mut h160 = [0u8; 20];
    h160.copy_from_slice(&hash[..20]);
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
}
