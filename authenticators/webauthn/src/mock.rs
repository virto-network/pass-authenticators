//! Test environment for pass webauthn.

use crate::{AssertionMeta, Authenticator, DEREncodedPublicKey};
use frame::{
    testing_prelude::*,
    traits::{ConstU32, EqualPrivilegeOnly},
};
use futures::executor::block_on;
use pallet_pass::AddressGenerator;
use passkey_authenticator::MockUserValidationMethod;
use passkey_client::{Client, DefaultClientData};
use passkey_types::ctap2::Aaguid;
use passkey_types::webauthn::{
    AttestationConveyancePreference, AttestationStatementFormatIdentifiers,
    CredentialCreationOptions, CredentialRequestOptions, PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    PublicKeyCredentialUserEntity, UserVerificationRequirement,
};
use passkey_types::{Bytes, Passkey};
use traits_authn::{util::AuthorityFromPalletId, Challenger, ExtrinsicContext, HashedUserId};
use url_evil::Url;

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
  pub PassPalletId: PalletId = PalletId(*b"pass_web");
  pub NeverPays: Option<pallet_pass::DepositInformation<Test>> = None;
}

pub type AuthorityId = AuthorityFromPalletId<PassPalletId>;

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
}

pub struct WebAuthnClient {
    origin: Url,
    client: Client<Option<Passkey>, MockUserValidationMethod, public_suffix::PublicSuffixList>,
}

impl WebAuthnClient {
    pub fn new(origin: &'static str, times: usize) -> Self {
        // Create Authenticator
        let authenticator = passkey_authenticator::Authenticator::new(
            Aaguid::new_empty(),
            None,
            MockUserValidationMethod::verified_user(times),
        );
        Self {
            origin: Url::parse(origin).expect("invalid url provided"),
            client: Client::new(authenticator),
        }
    }

    pub fn create_credential_sync(
        &mut self,
        user_id: HashedUserId,
        challenge: impl Into<Bytes>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, DEREncodedPublicKey), ()> {
        let creation_options = CredentialCreationOptions {
            public_key: PublicKeyCredentialCreationOptions {
                rp: PublicKeyCredentialRpEntity {
                    id: None,
                    name: self.origin.domain().unwrap().into(),
                },
                user: PublicKeyCredentialUserEntity {
                    id: user_id.as_slice().into(),
                    display_name: "".into(),
                    name: "".into(),
                },
                challenge: challenge.into(),
                pub_key_cred_params: vec![PublicKeyCredentialParameters {
                    ty: PublicKeyCredentialType::PublicKey,
                    alg: coset::iana::Algorithm::ES256,
                }],
                timeout: None,
                exclude_credentials: None,
                authenticator_selection: None,
                hints: None,
                attestation: AttestationConveyancePreference::Direct,
                attestation_formats: Some(vec![AttestationStatementFormatIdentifiers::Packed]),
                extensions: None,
            },
        };

        // Register the credential and block until result
        let result = block_on(self.client.register(
            &self.origin,
            creation_options,
            DefaultClientData,
        ))
        .map_err(|_| ())?;

        let public_key: DEREncodedPublicKey = result
            .response
            .public_key
            .map(|pk| {
                Decode::decode(&mut TrailingZeroInput::new(&*pk))
                    .expect("Invalid public key length")
            })
            .ok_or(())?;

        Ok((
            result.raw_id.into(),
            result.response.authenticator_data.into(),
            result.response.client_data_json.into(),
            public_key,
        ))
    }

    pub fn authenticate_credential_sync(
        &mut self,
        credential_id: impl Into<Bytes>,
        challenge: impl Into<Bytes>,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>), ()> {
        let request_options = CredentialRequestOptions {
            public_key: PublicKeyCredentialRequestOptions {
                challenge: challenge.into(), // Provided as input
                rp_id: Some(self.origin.domain().unwrap().into()),
                allow_credentials: Some(vec![PublicKeyCredentialDescriptor {
                    ty: PublicKeyCredentialType::PublicKey,
                    id: credential_id.into(),
                    transports: None,
                }]),
                timeout: None,
                user_verification: UserVerificationRequirement::default(),
                hints: None,
                attestation: AttestationConveyancePreference::None,
                attestation_formats: None,
                extensions: None,
            },
        };

        // Assuming you have already initialized `client`
        let result = block_on(self.client.authenticate(
            &self.origin,
            request_options,
            DefaultClientData,
        ))
        .map_err(|_| ())?;

        // Extracting required fields
        let user_handle = result
            .response
            .user_handle
            .map(|user_handle| user_handle.into())
            .ok_or(())?;
        let authenticator_data = result.response.authenticator_data.to_vec();
        let client_data = result.response.client_data_json.to_vec();
        let signature = result.response.signature.to_vec();

        Ok((user_handle, authenticator_data, client_data, signature))
    }

    pub fn attestation(
        &mut self,
        user_id: HashedUserId,
        context: BlockNumberFor<Test>,
        xtc: &impl ExtrinsicContext,
        authority_id: traits_authn::AuthorityId,
    ) -> (Vec<u8>, crate::Attestation<BlockNumberFor<Test>>) {
        let challenge = BlockChallenger::generate(&context, xtc);

        let (credential_id, authenticator_data, client_data, public_key) = self
            .create_credential_sync(user_id, challenge.as_slice())
            .expect("Failed creating credential");

        (
            credential_id.clone(),
            crate::Attestation {
                meta: crate::AttestationMeta {
                    authority_id,
                    device_id: blake2_256(&credential_id),
                    context,
                },
                authenticator_data,
                client_data: BoundedVec::try_from(client_data)
                    .expect("client_data is long enough; qed"),
                public_key,
            },
        )
    }

    pub fn assertion(
        &mut self,
        credential_id: impl Into<Bytes>,
        context: BlockNumberFor<Test>,
        xtc: &impl ExtrinsicContext,
        authority_id: traits_authn::AuthorityId,
    ) -> crate::Assertion<BlockNumberFor<Test>> {
        let challenge = BlockChallenger::generate(&context, xtc);

        let (user_handle, authenticator_data, client_data, signature) = self
            .authenticate_credential_sync(credential_id, challenge.as_slice())
            .expect("Failed retrieving credential");

        crate::Assertion {
            meta: AssertionMeta {
                authority_id,
                user_id: Decode::decode(&mut TrailingZeroInput::new(&user_handle)).expect("`user_handle` corresponds to the `user_id` inserted when creating credential; qed"),
                context,
            },
            authenticator_data,
            client_data: BoundedVec::try_from(client_data).expect("client_data is long enough; qed"),
            signature,
        }
    }
}

pub struct TestExt(pub TestExternalities, pub WebAuthnClient);
impl TestExt {
    pub fn execute_with<R>(&mut self, execute: impl FnOnce(&mut WebAuthnClient) -> R) -> R {
        self.0.execute_with(|| execute(&mut self.1))
    }
}

pub fn new_test_ext(times: usize) -> TestExt {
    let mut t = TestExternalities::default();
    t.execute_with(|| {
        System::set_block_number(1);
    });
    TestExt(t, WebAuthnClient::new("https://pass_web.pass.int", times))
}
