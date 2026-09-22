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
}

mod verification_weight {
    use super::*;
    use crate::WeightInfo;
    use frame::deps::sp_core::{ecdsa, ed25519};
    use traits_authn::{DeviceChallengeResponse, UserChallengeResponse};

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
    fn attestation_weight_is_non_zero_and_covers_the_benchmark() {
        let (message, public, _) = new_test_ext().execute_with(|| make_signature(&[]));
        for ((signature, key_type), benchmarked) in signatures().into_iter().zip([
            <() as WeightInfo>::verify_attestation_sr25519(),
            <() as WeightInfo>::verify_attestation_ed25519(),
            <() as WeightInfo>::verify_attestation_ecdsa(),
            <() as WeightInfo>::verify_attestation_eth(),
        ]) {
            let weight = KeyRegistration {
                public: public.clone(),
                message: message.clone(),
                signature,
            }
            .verification_weight();
            assert!(weight.ref_time() > 0, "{key_type}");
            assert!(weight.all_gte(benchmarked), "{key_type}");
        }
    }

    #[test]
    fn credential_weight_is_non_zero_and_covers_the_benchmark() {
        let (message, _, _) = new_test_ext().execute_with(|| make_signature(&[]));
        for ((signature, key_type), benchmarked) in signatures().into_iter().zip([
            <() as WeightInfo>::verify_credential_sr25519(),
            <() as WeightInfo>::verify_credential_ed25519(),
            <() as WeightInfo>::verify_credential_ecdsa(),
            <() as WeightInfo>::verify_credential_eth(),
        ]) {
            let weight = KeySignature {
                user_id: USER,
                message: message.clone(),
                signature,
            }
            .verification_weight();
            assert!(weight.ref_time() > 0, "{key_type}");
            assert!(weight.all_gte(benchmarked), "{key_type}");
        }
    }
}

/// The helpers `fc-pallet-pass`'s benchmarks use produce inputs the pallet accepts.
#[cfg(feature = "runtime-benchmarks")]
mod benchmark_helpers {
    use super::*;
    use traits_authn::{AuthenticatorBenchmarkHelper, DeviceChallengeResponse};

    type Authenticator = crate::Authenticator<BlockChallenger, AuthorityId, crate::WeightInfo<Test>>;

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
