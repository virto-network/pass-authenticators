use super::*;
use crate::eth::recover_eth_address;
use traits_authn::UserChallengeResponse;

impl<Cx: Parameter + Encode + 'static> UserChallengeResponse<Cx> for EthSignature<Cx> {
    fn is_valid(&self) -> bool {
        // Signature validation is deferred to the device's verify_credential.
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

    /// A signature is over a fixed-size message: it has no client data or authenticator data,
    /// so both components are zero (see [`crate::Weights`]).
    fn weight_components(&self) -> (u32, u32) {
        (0, 0)
    }
}

impl<Cx: Encode> VerifyCredential<EthSignature<Cx>> for EthAddress {
    fn verify(&mut self, credential: &EthSignature<Cx>) -> Option<()> {
        self.is_well_formed().then_some(())?;
        log::debug!(
            target: LOG_TARGET,
            "Verifying Ethereum signature for {:?}",
            self,
        );
        let hash = credential.message.eth_message_hash();
        let recovered = recover_eth_address(&hash, &credential.signature)?;
        (recovered == *self).then_some(())
    }
}
