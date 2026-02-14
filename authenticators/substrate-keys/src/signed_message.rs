use super::*;
use sp_core::{ecdsa, ed25519, sr25519, Pair};

impl<Cx: Encode> SignedMessage<Cx> {
    pub fn message(&self) -> impl AsRef<[u8]> {
        [
            self.context.encode().as_ref(),
            &self.challenge[..],
            &self.authority_id[..],
        ]
        .concat()
    }
}

#[cfg(feature = "full-crypto")]
impl<Cx: Encode> Sign<sr25519::Pair, Cx> for SignedMessage<Cx> {
    fn sign(&self, signer: sr25519::Pair) -> MultiSignature {
        MultiSignature::from(signer.sign(self.message().as_ref()))
    }
}

#[cfg(feature = "full-crypto")]
impl<Cx: Encode> Sign<ed25519::Pair, Cx> for SignedMessage<Cx> {
    fn sign(&self, signer: ed25519::Pair) -> MultiSignature {
        MultiSignature::from(signer.sign(self.message().as_ref()))
    }
}

#[cfg(feature = "full-crypto")]
impl<Cx: Encode> Sign<ecdsa::Pair, Cx> for SignedMessage<Cx> {
    fn sign(&self, signer: ecdsa::Pair) -> MultiSignature {
        MultiSignature::from(signer.sign(self.message().as_ref()))
    }
}
