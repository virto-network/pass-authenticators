use super::*;
use crate::sol::verify_ed25519;

impl<Ch: Challenger, AuthId> From<SolRegistration<CxOf<Ch>>> for Device<Ch, AuthId> {
    fn from(reg: SolRegistration<CxOf<Ch>>) -> Self {
        Self::new(reg.pubkey)
    }
}

impl<Cx: Parameter + Encode + 'static> DeviceChallengeResponse<Cx> for SolRegistration<Cx> {
    fn is_valid(&self) -> bool {
        log::debug!(
            target: LOG_TARGET,
            "Verifying Solana registration of {:?}",
            self.pubkey,
        );
        let payload = self.message.payload();
        verify_ed25519(&self.pubkey, &payload, &self.signature)
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.message.context.clone(), self.message.challenge)
    }

    fn authority(&self) -> AuthorityId {
        self.message.authority_id
    }

    fn device_id(&self) -> &DeviceId {
        self.pubkey.as_ref()
    }
}
