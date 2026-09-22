use crate::mock::*;
use frame::{deps::sp_runtime::str_array as s, testing_prelude::*};
use traits_authn::HashedUserId;

pub const USER: HashedUserId = s("the_user");

parameter_types! {
    pub UserAddress: AccountId = Pass::address_for(USER);
}

mod attestation {
    use super::*;

    #[test]
    fn registration_fails_if_attestation_is_invalid() {
        new_test_ext(1, false).execute_with(|client| {
            let (_, mut attestation) = client.attestation(
                USER,
                System::block_number(),
                &UserAddress::get().encode(),
                AuthorityId::get(),
            );

            // Alters "challenge", so this will fail
            let c_data = String::from_utf8(attestation.client_data.into())
                .map(|client_data| {
                    client_data
                        .replace("challenge", "chellang")
                        .as_bytes()
                        .to_vec()
                })
                .expect("`client_data` is a buffer representation of a utf-8 encoded json");
            attestation.client_data =
                BoundedVec::try_from(c_data).expect("c_data is long enough; qed");

            assert_noop!(
                Pass::register(RuntimeOrigin::root(), USER, attestation),
                pallet_pass::Error::<Test>::DeviceAttestationInvalid,
            );
        })
    }

    #[test]
    fn registration_works_if_attestation_is_valid() {
        new_test_ext(1, false).execute_with(|client| {
            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                client
                    .attestation(
                        USER,
                        System::block_number(),
                        &UserAddress::get().encode(),
                        AuthorityId::get()
                    )
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
        new_test_ext(2, false).execute_with(|client| {
            let (credential_id, attestation) = client.attestation(
                USER,
                System::block_number(),
                &UserAddress::get().encode(),
                AuthorityId::get(),
            );

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
        new_test_ext(2, false).execute_with(|client| {
            let (credential_id, attestation) = client.attestation(
                USER,
                System::block_number(),
                &UserAddress::get().encode(),
                AuthorityId::get(),
            );

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

    #[test]
    fn authentication_works_when_sing_count_changes() {
        new_test_ext(3, true).execute_with(|client| {
            let (credential_id, attestation) = client.attestation(
                USER,
                System::block_number(),
                &UserAddress::get().encode(),
                AuthorityId::get(),
            );

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                attestation.clone()
            ));

            let extrinsic_version: u8 = 0;
            let call: RuntimeCall = frame_system::Call::remark { remark: vec![] }.into();

            let first_assertion = client.assertion(
                credential_id.clone(),
                System::block_number(),
                &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
                AuthorityId::get(),
            );

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                *attestation.device_id(),
                first_assertion,
            );

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

            let second_assertion = client.assertion(
                credential_id,
                System::block_number(),
                &TxBaseImplication((extrinsic_version, call.clone())).using_encoded(blake2_256),
                AuthorityId::get(),
            );

            // Asserts that sign count changes
            assert_eq!(second_assertion.authenticator_data[33..37], [0, 0, 0, 2]);

            let ext = pallet_pass::PassAuthenticate::<Test>::from(
                *attestation.device_id(),
                second_assertion,
            );

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

mod verification_weight {
    use super::*;
    use crate::{
        WeightInfo, MAX_CLIENT_DATA_LEN, MIN_ASSERTION_AUTHENTICATOR_DATA_LEN,
        MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN, MIN_CLIENT_DATA_LEN,
    };
    use traits_authn::{DeviceChallengeResponse, UserChallengeResponse};

    /// An attestation and an assertion, as produced by a real (software) passkey.
    fn inputs() -> (
        crate::Attestation<BlockNumberFor<Test>>,
        crate::Assertion<BlockNumberFor<Test>>,
    ) {
        new_test_ext(2, false).execute_with(|client| {
            let (credential_id, attestation) =
                client.attestation(USER, System::block_number(), &[], AuthorityId::get());
            let assertion = client.assertion(
                credential_id,
                System::block_number(),
                &[],
                AuthorityId::get(),
            );
            (attestation, assertion)
        })
    }

    fn client_data(len: u32) -> BoundedVec<u8, ConstU32<1024>> {
        vec![b'a'; len as usize].try_into().unwrap()
    }

    #[test]
    fn attestation_weight_is_non_zero_and_at_least_the_benchmarks_floor() {
        let (attestation, _) = inputs();
        let weight = attestation.verification_weight();
        assert!(weight.ref_time() > 0);
        assert!(weight.all_gte(<() as WeightInfo>::verify_attestation(
            MIN_CLIENT_DATA_LEN,
            MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN,
        )));
    }

    #[test]
    fn credential_weight_is_non_zero_and_at_least_the_benchmarks_floor() {
        let (_, assertion) = inputs();
        let weight = assertion.verification_weight();
        assert!(weight.ref_time() > 0);
        assert!(weight.all_gte(<() as WeightInfo>::verify_credential(
            MIN_CLIENT_DATA_LEN,
            MIN_ASSERTION_AUTHENTICATOR_DATA_LEN,
        )));
    }

    #[test]
    fn attestation_weight_grows_with_input_length() {
        let (mut attestation, _) = inputs();

        attestation.client_data = client_data(512);
        let short = attestation.verification_weight();
        attestation.client_data = client_data(MAX_CLIENT_DATA_LEN);
        let long = attestation.verification_weight();
        assert!(long.ref_time() > short.ref_time());
        assert_eq!(
            long,
            <() as WeightInfo>::verify_attestation(
                MAX_CLIENT_DATA_LEN,
                (attestation.authenticator_data.len() as u32)
                    .max(MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN)
            )
        );

        attestation.authenticator_data = vec![0; 1_000];
        let short = attestation.verification_weight();
        attestation.authenticator_data = vec![0; 10_000];
        let long = attestation.verification_weight();
        assert!(long.ref_time() > short.ref_time());
        assert_eq!(
            long,
            <() as WeightInfo>::verify_attestation(MAX_CLIENT_DATA_LEN, 10_000)
        );
    }

    #[test]
    fn credential_weight_grows_with_input_length() {
        let (_, mut assertion) = inputs();

        assertion.client_data = client_data(512);
        let short = assertion.verification_weight();
        assertion.client_data = client_data(MAX_CLIENT_DATA_LEN);
        let long = assertion.verification_weight();
        assert!(long.ref_time() > short.ref_time());

        assertion.authenticator_data = vec![0; 1_000];
        let short = assertion.verification_weight();
        assertion.authenticator_data = vec![0; 10_000];
        let long = assertion.verification_weight();
        assert!(long.ref_time() > short.ref_time());
        assert_eq!(
            long,
            <() as WeightInfo>::verify_credential(MAX_CLIENT_DATA_LEN, 10_000)
        );
    }

    #[test]
    fn short_inputs_are_charged_the_benchmarks_floor() {
        let (mut attestation, mut assertion) = inputs();
        attestation.client_data = client_data(1);
        attestation.authenticator_data = vec![];
        assertion.client_data = client_data(1);
        assertion.authenticator_data = vec![];

        assert_eq!(
            attestation.verification_weight(),
            <() as WeightInfo>::verify_attestation(
                MIN_CLIENT_DATA_LEN,
                MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN
            )
        );
        assert_eq!(
            assertion.verification_weight(),
            <() as WeightInfo>::verify_credential(
                MIN_CLIENT_DATA_LEN,
                MIN_ASSERTION_AUTHENTICATOR_DATA_LEN
            )
        );
    }
}

/// The helpers `fc-pallet-pass`'s benchmarks use produce inputs the pallet accepts.
#[cfg(feature = "runtime-benchmarks")]
mod benchmark_helpers {
    use super::*;
    use frame::traits::TxBaseImplication;
    use traits_authn::{AuthenticatorBenchmarkHelper, DeviceChallengeResponse};

    type Authenticator = crate::Authenticator<BlockChallenger, AuthorityId>;

    #[test]
    fn helpers_register_and_authenticate() {
        new_test_ext(0, false).execute_with(|_| {
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
