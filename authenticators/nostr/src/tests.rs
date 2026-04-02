use crate::mock::*;
use crate::{NostrPubkey, NostrRegistration, NostrSignature, Sign, SignedMessage};
use frame::testing_prelude::*;
use frame::traits::TxBaseImplication;
use traits_authn::{Challenger, ExtrinsicContext, HashedUserId};

const USER: HashedUserId = *b"nostr_user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
parameter_types! {
    pub UserAddress: AccountId = Pass::address_for(USER);
}

fn nostr_keypair() -> (k256::schnorr::SigningKey, NostrPubkey) {
    let sk = k256::schnorr::SigningKey::from_bytes(&[4u8; 32]).expect("valid key");
    let vk = sk.verifying_key();
    let pubkey = NostrPubkey(vk.to_bytes().into());
    (sk, pubkey)
}

fn make_signature(xtc: &impl ExtrinsicContext) -> (SignedMessage<u64>, NostrPubkey, [u8; 64]) {
    let context = System::block_number();
    let message = SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: AuthorityId::get(),
    };
    let (sk, pubkey) = nostr_keypair();
    let signature = message.sign(&sk);

    (message, pubkey, signature)
}

mod registration {
    use super::*;

    #[test]
    fn registration_fails_if_attestation_is_invalid() {
        new_test_ext().execute_with(|| {
            let (mut message, pubkey, signature) = make_signature(&[]);
            message.challenge = [0u8; 32];

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    NostrRegistration {
                        pubkey,
                        message,
                        signature,
                    }
                ),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }

    #[test]
    fn registration_fails_with_wrong_pubkey() {
        new_test_ext().execute_with(|| {
            let (message, _pubkey, signature) = make_signature(&UserAddress::get().encode());
            // Use a different key's pubkey
            let other_sk = k256::schnorr::SigningKey::from_bytes(&[5u8; 32]).expect("valid key");
            let wrong = NostrPubkey(other_sk.verifying_key().to_bytes().into());

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    NostrRegistration {
                        pubkey: wrong,
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
            let (message, pubkey, signature) = make_signature(&UserAddress::get().encode());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                NostrRegistration {
                    pubkey,
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
            let (message, pubkey, signature) = make_signature(&UserAddress::get().encode());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                NostrRegistration {
                    pubkey,
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
            let (message, pubkey, signature) = make_signature(&[]);

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                pubkey.as_ref().clone(),
                NostrSignature {
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

            let (message, pubkey, signature) = make_signature(
                &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
            );

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                pubkey.as_ref().clone(),
                NostrSignature {
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

mod schnorr_verification {
    use super::*;

    #[test]
    fn verify_works_with_valid_signature() {
        new_test_ext().execute_with(|| {
            let (sk, pubkey) = nostr_keypair();
            let msg_hash = sp_io::hashing::sha2_256(b"hello nostr");
            use k256::schnorr::signature::hazmat::PrehashSigner;
            let sig: k256::schnorr::Signature = sk.sign_prehash(&msg_hash).expect("sign ok");
            let sig_bytes: [u8; 64] = sig.to_bytes().into();

            assert!(crate::schnorr::verify_schnorr(
                &pubkey, &msg_hash, &sig_bytes
            ));
        })
    }

    #[test]
    fn verify_fails_with_wrong_pubkey() {
        new_test_ext().execute_with(|| {
            let (sk, _pubkey) = nostr_keypair();
            let other_sk = k256::schnorr::SigningKey::from_bytes(&[5u8; 32]).expect("valid key");
            let wrong_pubkey = NostrPubkey(other_sk.verifying_key().to_bytes().into());

            let msg_hash = sp_io::hashing::sha2_256(b"hello nostr");
            use k256::schnorr::signature::hazmat::PrehashSigner;
            let sig: k256::schnorr::Signature = sk.sign_prehash(&msg_hash).expect("sign ok");
            let sig_bytes: [u8; 64] = sig.to_bytes().into();

            assert!(!crate::schnorr::verify_schnorr(
                &wrong_pubkey,
                &msg_hash,
                &sig_bytes
            ));
        })
    }
}
