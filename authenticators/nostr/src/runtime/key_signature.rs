use super::*;
use crate::schnorr::verify_schnorr;
use traits_authn::UserChallengeResponse;

impl<Cx: Parameter + Encode + 'static> UserChallengeResponse<Cx> for NostrSignature<Cx> {
    fn is_valid(&self) -> bool {
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

impl<Cx: Encode> VerifyCredential<NostrSignature<Cx>> for NostrPubkey {
    fn verify(&mut self, credential: &NostrSignature<Cx>) -> Option<()> {
        log::debug!(
            target: LOG_TARGET,
            "Verifying Nostr signature for {:?}",
            self,
        );
        let hash = credential.message.message_hash();
        verify_schnorr(self, &hash, &credential.signature).then_some(())
    }
}
