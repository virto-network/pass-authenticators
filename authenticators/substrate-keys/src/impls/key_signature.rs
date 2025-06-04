use super::*;
use traits_authn::UserChallengeResponse;

impl<Cx: Parameter + 'static> UserChallengeResponse<Cx> for KeySignature<Cx> {
    fn is_valid(&self) -> bool {
        // `KeySignature` structure is assumed well-constructed, therefore valid. Signature
        // verification is a task assigned to the device.
        true
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.message.context.clone(), self.message.challenge)
    }

    fn authority(&self) -> AuthorityId {
        self.message.authority_id
    }

    fn user_id(&self) -> HashedUserId {
        self.user_id
    }
}
