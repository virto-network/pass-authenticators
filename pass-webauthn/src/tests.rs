//! Test environment for pass webauthn.

use frame_support::traits::{ConstU32, EqualPrivilegeOnly};
use frame_support::{
    assert_noop, assert_ok, derive_impl, parameter_types,
    sp_runtime::{str_array as s, traits::Hash},
    traits::ConstU64,
    PalletId,
};
use frame_system::{pallet_prelude::BlockNumberFor, Config, EnsureRoot, EnsureRootWithSuccess};
use traits_authn::{util::AuthorityFromPalletId, Challenger, HashedUserId};

use crate::Authenticator;

mod authenticator_client;

use authenticator_client::*;

#[frame_support::runtime]
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
pub type AccountId = <Test as Config>::AccountId;

#[derive_impl(frame_system::config_preludes::TestDefaultConfig as frame_system::DefaultConfig)]
impl Config for Test {
    type BaseCallFilter = frame_support::traits::Everything;
    type Block = Block;
    type AccountData = pallet_balances::AccountData<AccountId>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig as pallet_balances::DefaultConfig
)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

parameter_types! {
    pub MaxWeight: frame_support::weights::Weight = frame_support::weights::Weight::MAX;
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
}

parameter_types! {
  pub PassPalletId: PalletId = PalletId(*b"pass_web");
  pub NeverPays: Option<pallet_pass::DepositInformation<Test>> = None;
}

type AuthorityId = AuthorityFromPalletId<PassPalletId>;

pub struct BlockChallenger;

impl Challenger for BlockChallenger {
    type Context = BlockNumberFor<Test>;

    fn generate(ctx: &Self::Context) -> traits_authn::Challenge {
        <Test as Config>::Hashing::hash(&ctx.to_le_bytes()).0
    }
}

impl pallet_pass::Config for Test {
    type RuntimeEvent = RuntimeEvent;
    type RuntimeCall = RuntimeCall;
    type Currency = Balances;
    type WeightInfo = ();
    type Authenticator = Authenticator<BlockChallenger, AuthorityId>;
    type PalletsOrigin = OriginCaller;
    type PalletId = PassPalletId;
    type MaxSessionDuration = ConstU64<10>;
    type RegisterOrigin = EnsureRootWithSuccess<Self::AccountId, NeverPays>;
    type Scheduler = Scheduler;
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper = Helper;
}

#[cfg(feature = "runtime-benchmarks")]
use sp_io::hashing::blake2_256;
#[cfg(feature = "runtime-benchmarks")]
pub struct Helper;
#[cfg(feature = "runtime-benchmarks")]
impl pallet_pass::BenchmarkHelper<Test> for Helper {
    fn register_origin() -> frame_system::pallet_prelude::OriginFor<Test> {
        RuntimeOrigin::root()
    }

    fn device_attestation(_: traits_authn::DeviceId) -> pallet_pass::DeviceAttestationOf<Test, ()> {
        WebAuthnClient::new("https://pass_web.pass.int", 1)
            .attestation(
                blake2_256(b"USER_ID"),
                System::block_number(),
                AuthorityId::get(),
            )
            .1
    }

    fn credential(user_id: HashedUserId) -> pallet_pass::CredentialOf<Test, ()> {
        let mut client = WebAuthnClient::new("https://helper.pass.int", 2);
        let (credential_id, _) =
            client.attestation(user_id, System::block_number(), AuthorityId::get());
        client.assertion(
            credential_id.as_slice(),
            System::block_number(),
            AuthorityId::get(),
        )
    }
}

struct TestExt(pub sp_io::TestExternalities, pub WebAuthnClient);
impl TestExt {
    pub fn execute_with<R>(&mut self, execute: impl FnOnce(&mut WebAuthnClient) -> R) -> R {
        self.0.execute_with(|| execute(&mut self.1))
    }
}

fn new_test_ext(times: usize) -> TestExt {
    let mut t = sp_io::TestExternalities::default();
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
                client.attestation(USER, System::block_number(), AuthorityId::get());

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
                    .attestation(USER, System::block_number(), AuthorityId::get())
                    .1
            ));
        })
    }
}

mod assertion {
    use traits_authn::DeviceChallengeResponse;

    use super::*;

    #[test]
    fn authentication_fails_if_credentials_are_invalid() {
        new_test_ext(2).execute_with(|client| {
            let (credential_id, attestation) =
                client.attestation(USER, System::block_number(), AuthorityId::get());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                attestation.clone()
            ));

            let mut assertion =
                client.assertion(credential_id, System::block_number(), AuthorityId::get());
            assertion.signature = [assertion.signature, b"Whoops".to_vec()].concat();

            assert_noop!(
                Pass::authenticate(
                    RuntimeOrigin::signed(1),
                    *(attestation.device_id()),
                    assertion,
                    None
                ),
                pallet_pass::Error::<Test>::CredentialInvalid
            );
        })
    }

    #[test]
    fn authentication_works_if_credentials_are_valid() {
        new_test_ext(2).execute_with(|client| {
            let (credential_id, attestation) =
                client.attestation(USER, System::block_number(), AuthorityId::get());

            assert_ok!(Pass::register(
                RuntimeOrigin::root(),
                USER,
                attestation.clone()
            ));

            assert_ok!(Pass::authenticate(
                RuntimeOrigin::signed(1),
                *(attestation.device_id()),
                client.assertion(credential_id, System::block_number(), AuthorityId::get()),
                None
            ));
        })
    }
}
