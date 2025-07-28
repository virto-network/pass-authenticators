use super::*;
use crate::runtime::client_data::RawClientData;
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
        TryInto::<RawClientData>::try_into(self.client_data.to_vec())
            .is_ok_and(|client_data| client_data.request_type().eq(&String::from("webauthn.get")))
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
