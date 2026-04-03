use super::*;
use crate::schnorr::verify_schnorr;

impl<Ch: Challenger, AuthId> From<NostrRegistration<CxOf<Ch>>> for Device<Ch, AuthId> {
    fn from(reg: NostrRegistration<CxOf<Ch>>) -> Self {
        Self::new(reg.pubkey)
    }
}

impl<Cx: Parameter + Encode + 'static> DeviceChallengeResponse<Cx> for NostrRegistration<Cx> {
    fn is_valid(&self) -> bool {
        log::debug!(
            target: LOG_TARGET,
            "Verifying Nostr registration of {:?}",
            self.pubkey,
        );
        let hash = self.message.message_hash();
        verify_schnorr(&self.pubkey, &hash, &self.signature)
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
