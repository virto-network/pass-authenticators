use super::*;

use sp_runtime::traits::Verify;

impl<Ch: Challenger, AuthId, W> From<KeyRegistration<CxOf<Ch>>> for Device<Ch, AuthId, W> {
    fn from(substrate_signature: KeyRegistration<CxOf<Ch>>) -> Self {
        Self::new(substrate_signature.public)
    }
}

impl<Cx: Parameter + 'static> DeviceChallengeResponse<Cx> for KeyRegistration<Cx> {
    fn is_valid(&self) -> bool {
        log::debug!(target: LOG_TARGET, "Verifying registration of {:?} for the message {:?} with signature {:?}",
            self.public,
            self.message.message().as_ref(),
            self.signature.encode(),
        );
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

    /// A registration is a fixed-size message and signature: it has no client data or
    /// authenticator data, so both components are zero. What verifying it costs depends only on
    /// the key type, which [`crate::WeightInfo`] covers by charging the costliest one.
    fn weight_components(&self) -> (u32, u32) {
        (0, 0)
    }
}
