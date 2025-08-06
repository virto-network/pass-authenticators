use super::*;

use sp_runtime::traits::Verify;

impl<Ch: Challenger, AuthId> From<KeyRegistration<CxOf<Ch>>> for Device<Ch, AuthId> {
    fn from(substrate_signature: KeyRegistration<CxOf<Ch>>) -> Self {
        Self::new(substrate_signature.public)
    }
}

impl<Cx: Parameter + 'static> DeviceChallengeResponse<Cx> for KeyRegistration<Cx> {
    fn is_valid(&self) -> bool {
        self.signature
            .verify(self.message.message().as_ref(), &self.public)
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.message.context.clone(), self.message.challenge)
    }

    fn authority(&self) -> AuthorityId {
        self.message.authority_id
    }

    fn device_id(&self) -> &DeviceId {
        self.public.as_ref()
    }
}

impl<Cx: Parameter> VerifyCredential<KeySignature<Cx>> for AccountId32 {
    fn verify(&mut self, credential: &KeySignature<Cx>) -> Option<()> {
        credential
            .signature
            .verify(credential.message.message().as_ref(), self)
            .then_some(())
    }
}
