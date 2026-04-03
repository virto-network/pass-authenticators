use super::*;
use crate::ssh::verify_ssh_ed25519;
use traits_authn::UserChallengeResponse;

impl<Cx: Parameter + Encode + 'static> UserChallengeResponse<Cx> for SshSignature<Cx> {
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

impl<Cx: Encode> VerifyCredential<SshSignature<Cx>> for SshPubkey {
    fn verify(&mut self, credential: &SshSignature<Cx>) -> Option<()> {
        log::debug!(
            target: LOG_TARGET,
            "Verifying SSH Ed25519 signature for {:?}",
            self,
        );
        let signed_data = credential.message.ssh_signed_data();
        verify_ssh_ed25519(self, &signed_data, &credential.signature).then_some(())
    }
}
