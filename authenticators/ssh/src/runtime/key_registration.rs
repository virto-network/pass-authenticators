use super::*;
use crate::ssh::verify_ssh_ed25519;

impl<Ch: Challenger, AuthId> From<SshRegistration<CxOf<Ch>>> for Device<Ch, AuthId> {
    fn from(reg: SshRegistration<CxOf<Ch>>) -> Self {
        Self::new(reg.pubkey)
    }
}

impl<Cx: Parameter + Encode + 'static> DeviceChallengeResponse<Cx> for SshRegistration<Cx> {
    fn is_valid(&self) -> bool {
        log::debug!(
            target: LOG_TARGET,
            "Verifying SSH Ed25519 registration of {:?}",
            self.pubkey,
        );
        let signed_data = self.message.ssh_signed_data();
        verify_ssh_ed25519(&self.pubkey, &signed_data, &self.signature)
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
