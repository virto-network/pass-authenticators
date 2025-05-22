//! Test environment for pass webauthn.

use frame::{
    deps::sp_runtime::str_array as s,
    hashing,
    testing_prelude::*,
    traits::{ConstU32, EqualPrivilegeOnly},
};
use traits_authn::{util::AuthorityFromPalletId, Challenger, ExtrinsicContext, HashedUserId};

use crate::Authenticator;

mod authenticator_client;

use authenticator_client::*;

#[frame_construct_runtime]
pub mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeTask,
        RuntimeHoldReason,
        RuntimeFreezeReason
    )]
    pub struct Test;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;
    #[runtime::pallet_index(1)]
    pub type Scheduler = pallet_scheduler;
    #[runtime::pallet_index(2)]
    pub type Pass = pallet_pass;

    #[runtime::pallet_index(10)]
    pub type Balances = pallet_balances;
}

pub type Block = frame_system::mocking::MockBlock<Test>;
pub type AccountId = <Test as frame_system::Config>::AccountId;

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountData = pallet_balances::AccountData<AccountId>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

parameter_types! {
    pub MaxWeight: weights::Weight = weights::Weight::MAX;
}

impl pallet_scheduler::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeOrigin = RuntimeOrigin;
    type PalletsOrigin = OriginCaller;
    type RuntimeCall = RuntimeCall;
    type MaximumWeight = MaxWeight;
    type ScheduleOrigin = EnsureRoot<AccountId>;
    type OriginPrivilegeCmp = EqualPrivilegeOnly;
    type MaxScheduledPerBlock = ConstU32<256>;
    type WeightInfo = ();
    type Preimages = ();
    type BlockNumberProvider = System;
}

parameter_types! {
  pub PassPalletId: PalletId = PalletId(*b"pass_web");
  pub NeverPays: Option<pallet_pass::DepositInformation<Test>> = None;
}

type AuthorityId = AuthorityFromPalletId<PassPalletId>;

pub struct BlockChallenger;

impl Challenger for BlockChallenger {
    type Context = BlockNumberFor<Test>;

    fn generate(ctx: &Self::Context, xtc: &impl ExtrinsicContext) -> traits_authn::Challenge {
        <Test as frame_system::Config>::Hashing::hash(&((ctx, xtc.as_ref()).encode())).0
    }
}

pub struct SumAddressGenerator;
impl AddressGenerator<Test, ()> for SumAddressGenerator {
    fn generate_address(id: HashedUserId) -> AccountId {
        id.iter()
            .map(|b| *b as u64)
            .reduce(Saturating::saturating_add)
            .unwrap()
    }
}

impl pallet_pass::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type PalletsOrigin = OriginCaller;
    type RuntimeCall = RuntimeCall;
    type WeightInfo = ();
    type RegisterOrigin = EnsureRootWithSuccess<Self::AccountId, ConstU64<0>>;
    type AddressGenerator = SumAddressGenerator;
    type Balances = Balances;
    type Authenticator = Authenticator<BlockChallenger, AuthorityId>;
    type Scheduler = Scheduler;
    type BlockNumberProvider = System;
    type RegistrarConsideration = ();
    type DeviceConsideration = ();
    type SessionKeyConsideration = ();
    type PalletId = PassPalletId;
    type MaxSessionDuration = ConstU64<10>;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = Helper;
}

#[cfg(feature = "runtime-benchmarks")]
use hashing::blake2_256;
use pallet_pass::AddressGenerator;

#[cfg(feature = "runtime-benchmarks")]
pub struct Helper;
#[cfg(feature = "runtime-benchmarks")]
impl pallet_pass::BenchmarkHelper<Test> for Helper {
    fn device_attestation(
        _: traits_authn::DeviceId,
        xtc: &impl ExtrinsicContext,
    ) -> pallet_pass::DeviceAttestationOf<Test, ()> {
        WebAuthnClient::new("https://pass_web.pass.int", 1)
            .attestation(
                blake2_256(b"USER_ID"),
                System::block_number(),
                xtc,
                AuthorityId::get(),
            )
            .1
    }

    fn credential(
        user_id: HashedUserId,
        xtc: &impl ExtrinsicContext,
    ) -> pallet_pass::CredentialOf<Test, ()> {
        let mut client = WebAuthnClient::new("https://helper.pass.int", 2);
        let (credential_id, _) =
            client.attestation(user_id, System::block_number(), xtc, AuthorityId::get());
        client.assertion(
            credential_id.as_slice(),
            System::block_number(),
            xtc,
            AuthorityId::get(),
        )
    }
}

struct TestExt(pub TestExternalities, pub WebAuthnClient);
impl TestExt {
    pub fn execute_with<R>(&mut self, execute: impl FnOnce(&mut WebAuthnClient) -> R) -> R {
        self.0.execute_with(|| execute(&mut self.1))
    }
}

fn new_test_ext(times: usize) -> TestExt {
    let mut t = TestExternalities::default();
    t.execute_with(|| {
        System::set_block_number(1);
    });
    TestExt(t, WebAuthnClient::new("https://pass_web.pass.int", times))
}

const USER: HashedUserId = s("the_user");

use traits_authn::composite_prelude::Get;

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
    use traits_authn::DeviceChallengeResponse;
    use crate::tests::sp_api_hidden_includes_construct_runtime::hidden_include::sp_runtime::traits::TxBaseImplication;
    use super::*;

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
