use codec::Decode;
use frame_support::{sp_runtime::traits::TrailingZeroInput, Parameter};
use serde_json::Value;
use sp_io::hashing::blake2_256;
use traits_authn::{
    util::VerifyCredential, AuthorityId, Challenge, Challenger, DeviceChallengeResponse, DeviceId,
    HashedUserId, UserChallengeResponse,
};
use verifier::webauthn_verify;

use crate::{Attestation, Credential, CxOf, Device, DeviceInfo};

impl<Cx> Attestation<Cx>
where
    Cx: Parameter,
{
    fn challenge(&self) -> Challenge {
        || -> Result<AuthorityId, ()> {
            let client_data_json =
                serde_json::from_slice::<Value>(&self.client_data).map_err(|_| ())?;

            let challenge_str =
                base64::decode(client_data_json["challenge"].as_str().ok_or(())?.as_bytes())
                    .map_err(|_| ())?;
            Decode::decode(&mut TrailingZeroInput::new(&challenge_str)).map_err(|_| ())?
        }()
        .unwrap_or_default()
    }
}

#[cfg(any(feature = "runtime", test))]
impl<Cx> DeviceChallengeResponse<Cx> for Attestation<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn is_valid(&self) -> bool {
        webauthn_verify(
            self.authenticator_data.as_ref(),
            &self.client_data,
            &self.signature,
            &self.public_key,
        )
        .is_ok()
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.context, self.challenge())
    }

    fn authority(&self) -> AuthorityId {
        || -> Result<AuthorityId, ()> {
            let client_data_json =
                serde_json::from_slice::<Value>(&self.client_data).map_err(|_| ())?;

            let origin = client_data_json["origin"].as_str().ok_or(())?;
            let (_, domain) = origin.split_once("//").ok_or(())?;
            let (rp_id_subdomain, _) = domain.split_once(".").ok_or(())?;

            Decode::decode(&mut TrailingZeroInput::new(rp_id_subdomain.as_bytes()))
                .map_err(|_| ())?
        }()
        .unwrap_or_default()
    }

    fn device_id(&self) -> &DeviceId {
        &self.credential_id
    }
}

#[cfg(any(feature = "runtime", test))]
impl<Ch, A> From<Attestation<CxOf<Ch>>> for Device<Ch, A>
where
    Ch: Challenger,
    CxOf<Ch>: Parameter + Copy + 'static,
{
    fn from(value: Attestation<CxOf<Ch>>) -> Self {
        Device::new(DeviceInfo {
            device_id: value.device_id().clone(),
            public_key: value.public_key,
        })
    }
}

impl<Cx> VerifyCredential<Credential<Cx>> for DeviceInfo {
    fn verify(&self, credential: &Credential<Cx>) -> Option<()> {
        webauthn_verify(
            &credential.authenticator_data,
            &credential.client_data,
            &credential.signature,
            &self.public_key,
        )
        .ok()
    }
}

#[cfg(any(feature = "runtime", test))]
impl AsRef<DeviceId> for DeviceInfo {
    fn as_ref(&self) -> &DeviceId {
        &self.device_id
    }
}

impl<Cx> Credential<Cx>
where
    Cx: Parameter,
{
    fn challenge(&self) -> Challenge {
        todo!("Extract `challenge`, format into `Challenge` format (that is, [u8; 32])");
    }
}

#[cfg(any(feature = "runtime", test))]
impl<Cx> UserChallengeResponse<Cx> for Credential<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    // TODO: @jgutierrezre please check if there are necessary validations involved here.
    fn is_valid(&self) -> bool {
        true
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.context, self.challenge())
    }

    fn authority(&self) -> AuthorityId {
        todo!("Extract `rp_id`, format into `AuthorityId` format (that is, [u8; 32])");
    }

    fn user_id(&self) -> HashedUserId {
        todo!("Extract `user_id`, format into `HashedUserId` format (that is, [u8; 32])");
    }
}
