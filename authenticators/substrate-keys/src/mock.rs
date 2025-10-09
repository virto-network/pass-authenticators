use frame::{
    deps::sp_runtime::MultiSignature,
    testing_prelude::*,
    traits::{EqualPrivilegeOnly, Verify},
};
use traits_authn::{
    util::AuthorityFromPalletId,
    {Challenger, ExtrinsicContext},
};

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

pub type Block = MockBlock<Test>;

pub type Signature = MultiSignature;
pub type AccountPublic = <Signature as Verify>::Signer;
pub type AccountId = <AccountPublic as IdentifyAccount>::AccountId;

pub type Balance = <Test as pallet_balances::Config>::Balance;

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
    type Block = Block;
    type AccountId = AccountId;
    type Lookup = IdentityLookup<Self::AccountId>;
    type AccountData = pallet_balances::AccountData<Balance>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Test {
    type AccountStore = System;
}

parameter_types! {
    pub MaxWeight: Weight = Weight::MAX;
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
  pub PassPalletId: PalletId = PalletId(*b"pass_sub");
  pub NeverPays: Option<pallet_pass::DepositInformation<Test>> = None;
  pub RootAccount: AccountId = AccountId::new([0x0; 32]);
}

pub type AuthorityId = AuthorityFromPalletId<PassPalletId>;

pub struct BlockChallenger;
impl Challenger for BlockChallenger {
    type Context = BlockNumberFor<Test>;

    fn generate(ctx: &Self::Context, xtc: &impl ExtrinsicContext) -> traits_authn::Challenge {
        <Test as frame_system::Config>::Hashing::hash(&((ctx, xtc.as_ref()).encode())).0
    }
}

impl pallet_pass::Config for Test {
    type PalletsOrigin = OriginCaller;
    type WeightInfo = ();
    type RegisterOrigin = EnsureRootWithSuccess<Self::AccountId, RootAccount>;
    type AddressGenerator = ();
    type Balances = Balances;
    type Authenticator = crate::Authenticator<BlockChallenger, AuthorityId>;
    type Scheduler = Scheduler;
    type BlockNumberProvider = System;
    type RegistrarConsideration = ();
    type DeviceConsideration = ();
    type SessionKeyConsideration = ();
    type PalletId = PassPalletId;
    type MaxDevicesPerAccount = ConstU32<1>;
    type MaxSessionsPerAccount = ConstU32<1>;
    type MaxSessionDuration = ConstU64<10>;
}

pub fn new_test_ext() -> TestExternalities {
    let mut t = TestExternalities::default();
    t.execute_with(|| {
        System::set_block_number(1);
    });
    t
}
