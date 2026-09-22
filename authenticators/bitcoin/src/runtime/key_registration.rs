use super::*;
use crate::btc::recover_btc_pubkey_hash;

impl<Ch: Challenger, AuthId> From<BtcRegistration<CxOf<Ch>>> for Device<Ch, AuthId> {
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

    /// The benchmarked cost of verifying this registration, which depends on whether its key is
    /// compressed (BIP-137 flags 31-34) or not (27-30).
    fn verification_weight(&self) -> Weight {
        match self.signature[0] {
            27..=30 => <() as crate::WeightInfo>::verify_attestation_uncompressed(),
            _ => <() as crate::WeightInfo>::verify_attestation_compressed(),
        }
    }
}
