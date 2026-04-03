use crate::mock::*;
use crate::{Sign, SignedMessage, SolPubkey, SolRegistration, SolSignature};
use frame::{
    deps::sp_core::{ed25519, Pair},
    testing_prelude::*,
    traits::TxBaseImplication,
};
use traits_authn::{Challenger, ExtrinsicContext, HashedUserId};

const USER: HashedUserId = *b"phantom\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
parameter_types! {
    pub SolKey: ed25519::Pair = ed25519::Pair::from_seed(&[3u8; 32]);
    pub UserAddress: AccountId = Pass::address_for(USER);
}

fn sol_pubkey_of(pair: &ed25519::Pair) -> SolPubkey {
    SolPubkey(pair.public().0)
}

fn make_signature(xtc: &impl ExtrinsicContext) -> (SignedMessage<u64>, SolPubkey, [u8; 64]) {
    let context = System::block_number();
    let message = SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: AuthorityId::get(),
    };
    let pair = SolKey::get();
    let pubkey = sol_pubkey_of(&pair);
    let signature = message.sign(&pair);

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
                    SolRegistration {
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
            let wrong = SolPubkey([0xAB; 32]);

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    SolRegistration {
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
                SolRegistration {
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
                SolRegistration {
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
                SolSignature {
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
                SolSignature {
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

mod edge_cases {
    use super::*;

    #[test]
    fn verify_fails_with_zero_pubkey() {
        new_test_ext().execute_with(|| {
            let pair = SolKey::get();
            let payload = b"test message";
            let sig = pair.sign(payload);

            let zero_pubkey = SolPubkey([0u8; 32]);
            assert!(!crate::sol::verify_ed25519(&zero_pubkey, payload, &sig.0));
        })
    }

    #[test]
    fn verify_fails_with_zero_signature() {
        new_test_ext().execute_with(|| {
            let pair = SolKey::get();
            let pubkey = sol_pubkey_of(&pair);
            let sig = [0u8; 64];
            assert!(!crate::sol::verify_ed25519(&pubkey, b"test", &sig));
        })
    }

    #[test]
    fn verify_fails_with_tampered_signature() {
        new_test_ext().execute_with(|| {
            let pair = SolKey::get();
            let pubkey = sol_pubkey_of(&pair);
            let payload = b"tampered test";
            let mut sig = pair.sign(payload).0;
            sig[0] ^= 0x01;

            assert!(!crate::sol::verify_ed25519(&pubkey, payload, &sig));
        })
    }
}
