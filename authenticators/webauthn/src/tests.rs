use crate::mock::*;
use frame::{deps::sp_runtime::str_array as s, testing_prelude::*};
use traits_authn::HashedUserId;

pub const USER: HashedUserId = s("the_user");

mod attestation {
    use super::*;

    #[test]
    fn registration_fails_if_attestation_is_invalid() {
        new_test_ext(1).execute_with(|client| {
            let (_, mut attestation) =
                client.attestation(USER, System::block_number(), &[], AuthorityId::get());

            // Alters "challenge", so this will fail
            attestation.client_data = String::from_utf8(attestation.client_data)
                .map(|client_data| {
                    client_data
                        .replace("challenge", "chellang")
                        .as_bytes()
                        .to_vec()
                })
                .expect("`client_data` is a buffer representation of a utf-8 encoded json");

            assert_noop!(
                Pass::register(RuntimeOrigin::root(), USER, attestation),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }

    #[test]
    fn registration_works_if_attestation_is_valid() {
        new_test_ext(1).execute_with(|client| {
            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                client
                    .attestation(USER, System::block_number(), &[], AuthorityId::get())
                    .1
            ));
        })
    }
}

mod assertion {
    use super::*;
    use frame::traits::TxBaseImplication;
    use traits_authn::DeviceChallengeResponse;

    #[test]
    fn authentication_fails_if_credentials_are_invalid() {
        new_test_ext(2).execute_with(|client| {
            let (credential_id, attestation) =
                client.attestation(USER, System::block_number(), &[], AuthorityId::get());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                attestation.clone()
            ));

            let assertion = client.assertion(
                credential_id,
                System::block_number(),
                &[],
                AuthorityId::get(),
            );

            let ext =
                pallet_pass::PassAuthenticate::<Test>::from(*attestation.device_id(), assertion);

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
        new_test_ext(2).execute_with(|client| {
            let (credential_id, attestation) =
                client.attestation(USER, System::block_number(), &[], AuthorityId::get());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                attestation.clone()
            ));

            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();

            let assertion = client.assertion(
                credential_id,
                System::block_number(),
                &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
                AuthorityId::get(),
            );

            let ext =
                pallet_pass::PassAuthenticate::<Test>::from(*attestation.device_id(), assertion);

            assert_ok!(ext
                .validate_only(
                    None.into(),
                    &call,
                    &call.get_dispatch_info(),
                    call.encoded_size(),
                    TransactionSource::External,
                    extrinsic_version,
                )
                .map(|_| ()));
        })
    }
}
