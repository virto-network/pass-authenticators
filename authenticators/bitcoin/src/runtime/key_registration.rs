use super::*;
use crate::btc::recover_btc_pubkey_hash;

impl<Ch: Challenger, AuthId, W> From<BtcRegistration<CxOf<Ch>>> for Device<Ch, AuthId, W> {
    fn from(reg: BtcRegistration<CxOf<Ch>>) -> Self {
        Self::new(reg.pubkey_hash)
    }
}

impl<Cx: Parameter + Encode + 'static> DeviceChallengeResponse<Cx> for BtcRegistration<Cx> {
    fn is_valid(&self) -> bool {
        log::debug!(
            target: LOG_TARGET,
            "Verifying Bitcoin registration of {:?}",
            self.pubkey_hash,
        );
        let hash = self.message.btc_message_hash();
        match recover_btc_pubkey_hash(&hash, &self.signature) {
            Some(recovered) => {
                let valid = recovered == self.pubkey_hash;
                if !valid {
                    log::debug!(
                        target: LOG_TARGET,
                        "Pubkey hash mismatch: recovered {:?}, expected {:?}",
                        recovered, self.pubkey_hash,
                    );
                }
                valid
            }
            None => {
                log::debug!(target: LOG_TARGET, "Failed to recover Bitcoin pubkey hash");
                false
            }
        }
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.message.context.clone(), self.message.challenge)
    }

    fn authority(&self) -> AuthorityId {
        self.message.authority_id
    }

    fn device_id(&self) -> &DeviceId {
        self.pubkey_hash.as_ref()
    }

    /// A registration is a fixed-size message and signature: it has no client data or
    /// authenticator data, so both components are zero (see [`crate::Weights`]).
    fn weight_components(&self) -> (u32, u32) {
        (0, 0)
    }
}
