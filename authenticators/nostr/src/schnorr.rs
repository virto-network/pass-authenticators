use super::*;
use k256::schnorr::signature::hazmat::PrehashVerifier;

extern crate alloc;
use alloc::vec::Vec;

impl<Cx: Encode> SignedMessage<Cx> {
    /// The raw payload bytes (SCALE-encoded context || challenge || authority_id).
    pub fn payload(&self) -> Vec<u8> {
        [
            self.context.encode().as_ref(),
            &self.challenge[..],
            &self.authority_id[..],
        ]
        .concat()
    }

    /// Compute the BIP-340 tagged hash for signing.
    /// Uses SHA256 of the raw payload (Nostr signs message hashes).
    pub fn message_hash(&self) -> [u8; 32] {
        let payload = self.payload();
        sp_io::hashing::sha2_256(&payload)
    }
}

/// Verify a BIP-340 Schnorr signature against a Nostr x-only public key.
pub fn verify_schnorr(pubkey: &NostrPubkey, message_hash: &[u8; 32], signature: &[u8; 64]) -> bool {
    let Ok(vk) = k256::schnorr::VerifyingKey::from_bytes(&pubkey.0) else {
        return false;
    };
    let Ok(sig) = k256::schnorr::Signature::try_from(signature.as_slice()) else {
        return false;
    };
    vk.verify_prehash(message_hash, &sig).is_ok()
}

#[cfg(feature = "full-crypto")]
pub trait Sign<Cx> {
    /// Sign the message hash with a BIP-340 Schnorr signing key.
    fn sign(&self, signing_key: &k256::schnorr::SigningKey) -> [u8; 64];
}

#[cfg(feature = "full-crypto")]
impl<Cx: Encode> Sign<Cx> for SignedMessage<Cx> {
    fn sign(&self, signing_key: &k256::schnorr::SigningKey) -> [u8; 64] {
        use k256::schnorr::signature::hazmat::PrehashSigner;
        let hash = self.message_hash();
        let sig: k256::schnorr::Signature = signing_key
            .sign_prehash(&hash)
            .expect("signing should not fail");
        let bytes: [u8; 64] = sig.to_bytes().into();
        bytes
    }
}
