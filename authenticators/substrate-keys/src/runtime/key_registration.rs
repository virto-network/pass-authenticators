use super::*;

use crate::weights::WeightInfo;
use sp_runtime::traits::Verify;

impl<Ch: Challenger, AuthId> From<KeyRegistration<CxOf<Ch>>> for Device<Ch, AuthId> {
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

    /// The benchmarked cost of verifying a registration signed with this key type.
    fn verification_weight(&self) -> Weight {
        match self.signature {
            MultiSignature::Sr25519(_) => <() as WeightInfo>::verify_attestation_sr25519(),
            MultiSignature::Ed25519(_) => <() as WeightInfo>::verify_attestation_ed25519(),
            MultiSignature::Ecdsa(_) => <() as WeightInfo>::verify_attestation_ecdsa(),
            MultiSignature::Eth(_) => <() as WeightInfo>::verify_attestation_eth(),
        }
    }
}
