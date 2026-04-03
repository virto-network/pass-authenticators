use super::*;
use k256::schnorr::signature::hazmat::PrehashVerifier;

extern crate alloc;
use alloc::vec::Vec;

/// BIP-340 tag for our Nostr authenticator's tagged hash.
const BIP340_TAG: &[u8] = b"pallet-pass/nostr";

impl<Cx: Encode> SignedMessage<Cx> {
    /// The domain-separated payload bytes.
    /// Prefixed with `b"NOSTR"` to prevent cross-authenticator signature replay.
    pub fn payload(&self) -> Vec<u8> {
        [
            b"NOSTR".as_slice(),
            self.context.encode().as_ref(),
            &self.challenge[..],
            &self.authority_id[..],
        ]
        .concat()
    }

    /// Compute a BIP-340 tagged hash of the payload.
    /// Format: `SHA256(SHA256(tag) || SHA256(tag) || msg)`
    /// where tag = `b"pallet-pass/nostr"` and msg = payload bytes.
    pub fn message_hash(&self) -> [u8; 32] {
        let payload = self.payload();
        bip340_tagged_hash(BIP340_TAG, &payload)
    }
}

/// Compute a BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
fn bip340_tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash = sp_io::hashing::sha2_256(tag);
    let mut data = Vec::with_capacity(64 + msg.len());
    data.extend_from_slice(&tag_hash);
    data.extend_from_slice(&tag_hash);
    data.extend_from_slice(msg);
    sp_io::hashing::sha2_256(&data)
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
impl<Cx: Encode> SignedMessage<Cx> {
    /// Sign the BIP-340 tagged message hash with a Schnorr signing key.
    pub fn sign(&self, signing_key: &k256::schnorr::SigningKey) -> [u8; 64] {
        use k256::schnorr::signature::hazmat::PrehashSigner;
        let hash = self.message_hash();
        let sig: k256::schnorr::Signature = signing_key
            .sign_prehash(&hash)
            .expect("signing should not fail");
        sig.to_bytes().into()
    }
}
