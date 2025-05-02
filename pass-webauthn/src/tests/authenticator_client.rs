use super::*;

use codec::Decode;
use frame::deps::sp_runtime::traits::TrailingZeroInput;
use frame_system::pallet_prelude::BlockNumberFor;
use futures::executor::block_on;

use passkey_authenticator::{Authenticator, MockUserValidationMethod};
use passkey_client::{Client, DefaultClientData};
use passkey_types::{ctap2::Aaguid, webauthn::*, Bytes, Passkey};

use hashing::blake2_256;
use traits_authn::{AuthorityId, Challenger, HashedUserId};
use url_evil::Url;

use crate::{AssertionMeta, DEREncodedPublicKey};

use super::{BlockChallenger, Test};

pub struct WebAuthnClient {
    origin: Url,
    client: Client<Option<Passkey>, MockUserValidationMethod, public_suffix::PublicSuffixList>,
}

impl WebAuthnClient {
    pub fn new(origin: &'static str, times: usize) -> Self {
        // Create Authenticator
        let authenticator = Authenticator::new(
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
        authority_id: AuthorityId,
    ) -> (Vec<u8>, crate::Attestation<BlockNumberFor<Test>>) {
        let challenge = BlockChallenger::generate(&context);

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
                client_data,
                public_key,
            },
        )
    }

    pub fn assertion(
        &mut self,
        credential_id: impl Into<Bytes>,
        context: BlockNumberFor<Test>,
        authority_id: AuthorityId,
    ) -> crate::Assertion<BlockNumberFor<Test>> {
        let challenge = BlockChallenger::generate(&context);

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
            client_data,
            signature,
        }
    }
}
