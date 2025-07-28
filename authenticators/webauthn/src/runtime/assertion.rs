use super::*;
use traits_authn::{HashedUserId, UserChallengeResponse};

impl<Cx> Assertion<Cx>
where
    Cx: Parameter,
{
    fn challenge(&self) -> Challenge {
        helpers::find_challenge_from_client_data(self.client_data.to_vec()).unwrap_or_default()
    }
}

impl<Cx> UserChallengeResponse<Cx> for Assertion<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    fn is_valid(&self) -> bool {
        true
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
