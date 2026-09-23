use super::*;
use sp_runtime::traits::Verify;
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

    /// A signature is over a fixed-size message: it has no client data or authenticator data,
    /// so both components are zero. What verifying it costs depends only on
    /// the key type, which [`crate::WeightInfo`] covers by charging the costliest one.
    fn weight_components(&self) -> (u32, u32) {
        (0, 0)
    }
}

impl<Cx: Parameter> VerifyCredential<KeySignature<Cx>> for AccountId32 {
    fn verify(&mut self, credential: &KeySignature<Cx>) -> Option<()> {
        log::debug!(target: LOG_TARGET, "Verifying signature of {self:?} for the message {:?} with signature {:?}",
            credential.message.message().as_ref(),
            credential.signature.encode(),
        );
        credential
            .signature
            .verify(credential.message.message().as_ref(), self)
            .then_some(())
    }
}
