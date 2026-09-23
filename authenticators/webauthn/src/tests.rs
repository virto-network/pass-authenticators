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
    use crate::WeightInfo as _;
    use crate::{
        MAX_CLIENT_DATA_LEN, MIN_ASSERTION_AUTHENTICATOR_DATA_LEN,
        MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN, MIN_CLIENT_DATA_LEN,
    };
    use traits_authn::{
        AuthenticatorWeightInfo, DeviceChallengeResponse, UserAuthenticator, UserChallengeResponse,
    };

    /// The weights the mock runtime binds...
    type Weights = crate::DefaultWeights<Test>;
    /// ...which are the ones this crate's benchmarks measured.
    type Measured = crate::SubstrateWeight<Test>;
    type Authn = <Test as pallet_pass::Config>::Authenticator;
    type Device = <Authn as traits_authn::Authenticator>::Device;

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

    /// What `fc-pallet-pass` charges for verifying `attestation`.
    fn attestation_weight(attestation: &crate::Attestation<BlockNumberFor<Test>>) -> Weight {
        <Authn as traits_authn::Authenticator>::verification_weight(attestation)
    }

    /// What `fc-pallet-pass` charges for verifying `assertion`.
    fn assertion_weight(assertion: &crate::Assertion<BlockNumberFor<Test>>) -> Weight {
        <Device as UserAuthenticator>::verification_weight(assertion)
    }

    #[test]
    fn verify_device_maps_onto_verify_attestation() {
        assert_eq!(
            <Weights as AuthenticatorWeightInfo>::verify_device(300, 500),
            Measured::verify_attestation(300, 500)
        );
        // Never below the shortest inputs benchmarked...
        assert_eq!(
            <Weights as AuthenticatorWeightInfo>::verify_device(0, 0),
            Measured::verify_attestation(
                MIN_CLIENT_DATA_LEN,
                MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN
            )
        );
        // ...and client data is never longer than its cap, while authenticator data can be.
        assert_eq!(
            <Weights as AuthenticatorWeightInfo>::verify_device(10_000, 10_000),
            Measured::verify_attestation(MAX_CLIENT_DATA_LEN, 10_000)
        );
    }

    #[test]
    fn verify_user_maps_onto_verify_credential() {
        assert_eq!(
            <Weights as AuthenticatorWeightInfo>::verify_user(300, 500),
            Measured::verify_credential(300, 500)
        );
        assert_eq!(
            <Weights as AuthenticatorWeightInfo>::verify_user(0, 0),
            Measured::verify_credential(MIN_CLIENT_DATA_LEN, MIN_ASSERTION_AUTHENTICATOR_DATA_LEN)
        );
        assert_eq!(
            <Weights as AuthenticatorWeightInfo>::verify_user(10_000, 10_000),
            Measured::verify_credential(MAX_CLIENT_DATA_LEN, 10_000)
        );
    }

    #[test]
    fn unit_weights_are_the_measured_ones() {
        for (c, a) in [
            (MIN_CLIENT_DATA_LEN, 37),
            (300, 500),
            (MAX_CLIENT_DATA_LEN, 10_000),
        ] {
            assert_eq!(
                <() as crate::WeightInfo>::verify_attestation(c, a),
                Measured::verify_attestation(c, a)
            );
            assert_eq!(
                <() as crate::WeightInfo>::verify_credential(c, a),
                Measured::verify_credential(c, a)
            );
        }
    }

    /// A runtime's own run of the benchmarks, with made-up numbers far from the measured ones.
    struct OwnWeights;
    impl crate::WeightInfo for OwnWeights {
        fn verify_attestation(c: u32, a: u32) -> Weight {
            Weight::from_parts(1_000_000 * u64::from(c) + u64::from(a), 11)
        }
        fn verify_credential(c: u32, a: u32) -> Weight {
            Weight::from_parts(2_000_000 * u64::from(c) + u64::from(a), 22)
        }
    }

    #[test]
    fn a_runtimes_own_weights_flow_through_the_adapter() {
        type Own = crate::Weights<OwnWeights>;
        type OwnAuthn = crate::Authenticator<BlockChallenger, AuthorityId, Own>;
        type OwnDevice = <OwnAuthn as traits_authn::Authenticator>::Device;

        // The same mapping onto the benchmarks as for the measured weights...
        for (c, a) in [(0, 0), (300, 500), (10_000, 10_000)] {
            assert_eq!(
                <Own as AuthenticatorWeightInfo>::verify_device(c, a),
                OwnWeights::verify_attestation(
                    c.clamp(MIN_CLIENT_DATA_LEN, MAX_CLIENT_DATA_LEN),
                    a.max(MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN)
                ),
                "c={c}, a={a}"
            );
            assert_eq!(
                <Own as AuthenticatorWeightInfo>::verify_user(c, a),
                OwnWeights::verify_credential(
                    c.clamp(MIN_CLIENT_DATA_LEN, MAX_CLIENT_DATA_LEN),
                    a.max(MIN_ASSERTION_AUTHENTICATOR_DATA_LEN)
                ),
                "c={c}, a={a}"
            );
        }

        // ...and it's what an authenticator bound to them charges, instead of the measured ones.
        let (attestation, assertion) = inputs();
        let (c, a) = attestation.weight_components();
        let charged = <OwnAuthn as traits_authn::Authenticator>::verification_weight(&attestation);
        assert_eq!(
            charged,
            OwnWeights::verify_attestation(
                c.clamp(MIN_CLIENT_DATA_LEN, MAX_CLIENT_DATA_LEN),
                a.max(MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN)
            )
        );
        assert_ne!(charged, attestation_weight(&attestation));

        let (c, a) = assertion.weight_components();
        let charged = <OwnDevice as UserAuthenticator>::verification_weight(&assertion);
        assert_eq!(
            charged,
            OwnWeights::verify_credential(
                c.clamp(MIN_CLIENT_DATA_LEN, MAX_CLIENT_DATA_LEN),
                a.max(MIN_ASSERTION_AUTHENTICATOR_DATA_LEN)
            )
        );
        assert_ne!(charged, assertion_weight(&assertion));
    }

    #[test]
    fn weight_components_are_the_submitted_lengths() {
        let (attestation, assertion) = inputs();
        assert_eq!(
            attestation.weight_components(),
            (
                attestation.client_data.len() as u32,
                attestation.authenticator_data.len() as u32
            )
        );
        assert_eq!(
            assertion.weight_components(),
            (
                assertion.client_data.len() as u32,
                assertion.authenticator_data.len() as u32
            )
        );
    }

    #[test]
    fn attestation_weight_is_charged_on_the_submitted_lengths() {
        let (mut attestation, _) = inputs();
        assert!(attestation_weight(&attestation).ref_time() > 0);
        for (c, a) in [(1, 0), (512, 1_000), (MAX_CLIENT_DATA_LEN, 10_000)] {
            attestation.client_data = client_data(c);
            attestation.authenticator_data = vec![0; a as usize];
            assert_eq!(
                attestation_weight(&attestation),
                Measured::verify_attestation(
                    c.max(MIN_CLIENT_DATA_LEN),
                    a.max(MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN),
                ),
                "c={c}, a={a}"
            );
        }
    }

    #[test]
    fn credential_weight_is_charged_on_the_submitted_lengths() {
        let (_, mut assertion) = inputs();
        assert!(assertion_weight(&assertion).ref_time() > 0);
        for (c, a) in [(1, 0), (512, 1_000), (MAX_CLIENT_DATA_LEN, 10_000)] {
            assertion.client_data = client_data(c);
            assertion.authenticator_data = vec![0; a as usize];
            assert_eq!(
                assertion_weight(&assertion),
                Measured::verify_credential(
                    c.max(MIN_CLIENT_DATA_LEN),
                    a.max(MIN_ASSERTION_AUTHENTICATOR_DATA_LEN),
                ),
                "c={c}, a={a}"
            );
        }
    }

    #[test]
    fn weights_grow_with_input_length() {
        let (mut attestation, mut assertion) = inputs();

        // On the benchmark runner, verifying an attestation didn't grow with its client data
        // (the fit for `c` came out flat), so a longer one must only never be cheaper.
        attestation.client_data = client_data(512);
        let short = attestation_weight(&attestation);
        attestation.client_data = client_data(MAX_CLIENT_DATA_LEN);
        assert!(attestation_weight(&attestation).ref_time() >= short.ref_time());

        attestation.authenticator_data = vec![0; 1_000];
        let short = attestation_weight(&attestation);
        attestation.authenticator_data = vec![0; 10_000];
        assert!(attestation_weight(&attestation).ref_time() > short.ref_time());

        assertion.client_data = client_data(512);
        let short = assertion_weight(&assertion);
        assertion.client_data = client_data(MAX_CLIENT_DATA_LEN);
        assert!(assertion_weight(&assertion).ref_time() > short.ref_time());

        assertion.authenticator_data = vec![0; 1_000];
        let short = assertion_weight(&assertion);
        assertion.authenticator_data = vec![0; 10_000];
        assert!(assertion_weight(&assertion).ref_time() > short.ref_time());
    }

    #[test]
    fn pallet_pass_charges_the_attestation_weight_on_register() {
        let (attestation, _) = inputs();
        let verification = attestation_weight(&attestation);
        let call_weight = RuntimeCall::Pass(pallet_pass::Call::register {
            user: USER,
            attestation,
        })
        .get_dispatch_info()
        .call_weight;
        assert!(call_weight.all_gte(verification));
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
