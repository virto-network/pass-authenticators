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
            let (message, public, signature) = make_signature(&[]);

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
}

mod authentication {
    use super::*;

    fn new_test_ext() -> TestExternalities {
        let mut t = super::new_test_ext();
        t.execute_with(|| {
            let (message, public, signature) = make_signature(&[]);

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
}
