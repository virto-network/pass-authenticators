use crate::mock::*;
use crate::{Sign, SignedMessage, SshPubkey, SshRegistration, SshSignature};
use frame::{
    deps::sp_core::{ed25519, Pair},
    testing_prelude::*,
    traits::TxBaseImplication,
};
use traits_authn::{Challenger, ExtrinsicContext, HashedUserId};

const USER: HashedUserId = *b"dev_user\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
parameter_types! {
    pub SshKey: ed25519::Pair = ed25519::Pair::from_seed(&[5u8; 32]);
    pub UserAddress: AccountId = Pass::address_for(USER);
}

fn ssh_pubkey_of(pair: &ed25519::Pair) -> SshPubkey {
    SshPubkey(pair.public().0)
}

fn make_signature(xtc: &impl ExtrinsicContext) -> (SignedMessage<u64>, SshPubkey, [u8; 64]) {
    let context = System::block_number();
    let message = SignedMessage {
        context,
        challenge: BlockChallenger::generate(&context, xtc),
        authority_id: AuthorityId::get(),
    };
    let pair = SshKey::get();
    let pubkey = ssh_pubkey_of(&pair);
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
                    SshRegistration {
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
            let wrong = SshPubkey([0xAB; 32]);

            assert_noop!(
                Pass::register(
                    RuntimeOrigin::root(),
                    USER,
                    SshRegistration {
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
                SshRegistration {
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
                SshRegistration {
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
                SshSignature {
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
                SshSignature {
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

mod sshsig_format {
    use super::*;

    #[test]
    fn signed_data_contains_magic_preamble() {
        new_test_ext().execute_with(|| {
            let (message, _, _) = make_signature(&[]);
            let data = message.ssh_signed_data();
            assert_eq!(&data[..6], b"SSHSIG");
        })
    }

    #[test]
    fn signed_data_contains_namespace() {
        new_test_ext().execute_with(|| {
            let (message, _, _) = make_signature(&[]);
            let data = message.ssh_signed_data();
            // After preamble (6), namespace length (4 bytes BE), then namespace
            let ns_len = u32::from_be_bytes(data[6..10].try_into().unwrap()) as usize;
            assert_eq!(&data[10..10 + ns_len], b"pallet-pass");
        })
    }
}
