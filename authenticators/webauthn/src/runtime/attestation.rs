use super::*;
use crate::runtime::authenticator_data::AuthenticatorFlags;
use authenticator_data::AuthenticatorData;
use client_data::RawClientData;
use frame::deps::sp_core::hexdisplay::AsBytesRef;
use frame::hashing::sha2_256;
use url::Url;

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
        let Ok(client_data): Result<RawClientData, _> = self.client_data.to_vec().try_into() else {
            return false;
        };
        let Ok(authenticator_data): Result<AuthenticatorData, _> =
            self.authenticator_data.as_bytes_ref().try_into()
        else {
            return false;
        };

        let rp_id_hash = {
            let Ok(origin_url) = Url::parse(&client_data.origin) else {
                return false;
            };
            let Some(domain) = origin_url.domain() else {
                return false;
            };

            sha2_256(domain.as_bytes())
        };

        // clientData.type == "webauthn.create"
        client_data
            .request_type()
            .eq(&String::from("webauthn.create"))
            // rpIdHash == sha256(origin.domain)
            && authenticator_data.rp_id_hash == rp_id_hash
            // if !BE, then !BS
            && (
                authenticator_data
                    .flags
                    .contains(AuthenticatorFlags::BACKUP_ELEGIBILITY) ||
                !authenticator_data
                    .flags
                    .contains(AuthenticatorFlags::BACKUP_STATE)
            )
            // UP && UV
            && authenticator_data
                .flags
                .contains(AuthenticatorFlags::USER_PRESENT)
            && authenticator_data
                .flags
                .contains(AuthenticatorFlags::USER_VERIFIED)
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
