use super::*;
use crate::sol::verify_ed25519;
use traits_authn::UserChallengeResponse;

impl<Cx: Parameter + Encode + 'static> UserChallengeResponse<Cx> for SolSignature<Cx> {
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

impl<Cx: Encode> VerifyCredential<SolSignature<Cx>> for SolPubkey {
    fn verify(&mut self, credential: &SolSignature<Cx>) -> Option<()> {
        log::debug!(
            target: LOG_TARGET,
            "Verifying Solana signature for {:?}",
            self,
        );
        let payload = credential.message.payload();
        verify_ed25519(self, &payload, &credential.signature).then_some(())
    }
}
