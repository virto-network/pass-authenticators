use super::*;
use crate::btc::recover_btc_pubkey_hash;
use traits_authn::UserChallengeResponse;

impl<Cx: Parameter + Encode + 'static> UserChallengeResponse<Cx> for BtcSignature<Cx> {
    fn is_valid(&self) -> bool {
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

    /// The benchmarked cost of verifying this signature, which depends on whether its key is
    /// compressed (BIP-137 flags 31-34) or not (27-30).
    fn verification_weight(&self) -> Weight {
        match self.signature[0] {
            27..=30 => <() as crate::WeightInfo>::verify_credential_uncompressed(),
            _ => <() as crate::WeightInfo>::verify_credential_compressed(),
        }
    }
}

impl<Cx: Encode> VerifyCredential<BtcSignature<Cx>> for BtcPubkeyHash {
    fn verify(&mut self, credential: &BtcSignature<Cx>) -> Option<()> {
        log::debug!(
            target: LOG_TARGET,
            "Verifying Bitcoin signature for {:?}",
            self,
        );
        let hash = credential.message.btc_message_hash();
        let recovered = recover_btc_pubkey_hash(&hash, &credential.signature)?;
        (recovered == *self).then_some(())
    }
}
