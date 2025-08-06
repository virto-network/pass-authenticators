use super::*;
use crate::runtime::authenticator_data::{AuthenticatorData, AuthenticatorFlags};
use crate::runtime::client_data::RawClientData;
use frame::deps::sp_core::hexdisplay::AsBytesRef;
use traits_authn::{HashedUserId, UserChallengeResponse};

impl<Cx> Assertion<Cx>
where
    Cx: Parameter,
{
    fn challenge(&self) -> Challenge {
        TryInto::<RawClientData>::try_into(self.client_data.to_vec())
            .map(|client_data| client_data.challenge().unwrap_or_default())
            .unwrap_or_default()
    }
}

impl<Cx> UserChallengeResponse<Cx> for Assertion<Cx>
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

        // clientData.type == "webauthn.create"
        client_data.request_type().eq(&String::from("webauthn.get"))
            // Check UP
            && authenticator_data
                .flags
                .contains(AuthenticatorFlags::USER_PRESENT)
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.meta.context, self.challenge())
    }

    fn authority(&self) -> AuthorityId {
        self.meta.authority_id
    }

    fn user_id(&self) -> HashedUserId {
        self.meta.user_id
    }
}
