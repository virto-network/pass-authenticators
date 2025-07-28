use super::*;
use crate::runtime::client_data::RawClientData;

impl<Cx> Attestation<Cx>
where
    Cx: Parameter,
{
    fn challenge(&self) -> Challenge {
        TryInto::<RawClientData>::try_into(self.client_data.to_vec())
            .map(|client_data| client_data.challenge().unwrap_or_default())
            .unwrap_or_default()
    }
}

#[cfg(any(feature = "runtime", test))]
impl<Cx> DeviceChallengeResponse<Cx> for Attestation<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn is_valid(&self) -> bool {
        TryInto::<RawClientData>::try_into(self.client_data.to_vec()).is_ok_and(|client_data| {
            client_data
                .request_type()
                .eq(&String::from("webauthn.create"))
        })

        // TODO: Implement the rest of GUV-2, once having resolved the conversation around it.
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.meta.context, self.challenge())
    }

    /// WebAuthn RpID should be a subdomain of the origin that is calling the create credentials request.
    /// Therefore, `authority` should be a URL-safe name, so it can be allocated in a valid URL domain.
    fn authority(&self) -> AuthorityId {
        self.meta.authority_id
    }

    fn device_id(&self) -> &DeviceId {
        &self.meta.device_id
    }
}
