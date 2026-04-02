use super::*;
use crate::eth::recover_eth_address;

impl<Ch: Challenger, AuthId> From<EthRegistration<CxOf<Ch>>> for Device<Ch, AuthId> {
    fn from(reg: EthRegistration<CxOf<Ch>>) -> Self {
        Self::new(reg.address)
    }
}

impl<Cx: Parameter + Encode + 'static> DeviceChallengeResponse<Cx> for EthRegistration<Cx> {
    fn is_valid(&self) -> bool {
        log::debug!(
            target: LOG_TARGET,
            "Verifying Ethereum registration of {:?} with signature",
            self.address,
        );
        let hash = self.message.eth_message_hash();
        match recover_eth_address(&hash, &self.signature) {
            Some(recovered) => {
                let valid = recovered == self.address;
                if !valid {
                    log::debug!(
                        target: LOG_TARGET,
                        "Address mismatch: recovered {:?}, expected {:?}",
                        recovered, self.address,
                    );
                }
                valid
            }
            None => {
                log::debug!(target: LOG_TARGET, "Failed to recover Ethereum address");
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
        self.address.as_ref()
    }
}
