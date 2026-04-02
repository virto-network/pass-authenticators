use super::*;

extern crate alloc;
use alloc::vec::Vec;

impl<Cx: Encode> SignedMessage<Cx> {
    /// The raw payload bytes (SCALE-encoded context || challenge || authority_id).
    /// Solana wallets sign raw bytes directly, no special prefix.
    pub fn payload(&self) -> Vec<u8> {
        [
            self.context.encode().as_ref(),
            &self.challenge[..],
            &self.authority_id[..],
        ]
        .concat()
    }
}

/// Verify an Ed25519 signature against a Solana public key.
pub fn verify_ed25519(pubkey: &SolPubkey, message: &[u8], signature: &[u8; 64]) -> bool {
    // Use sp_io's ed25519 verification
    let ed_pub = sp_core::ed25519::Public::from_raw(pubkey.0);
    let ed_sig = sp_core::ed25519::Signature::from_raw(*signature);
    sp_io::crypto::ed25519_verify(&ed_sig, message, &ed_pub)
}

#[cfg(feature = "full-crypto")]
pub trait Sign<Cx> {
    /// Sign the message payload with an Ed25519 key pair.
    fn sign(&self, pair: &sp_core::ed25519::Pair) -> [u8; 64];
}

#[cfg(feature = "full-crypto")]
impl<Cx: Encode> Sign<Cx> for SignedMessage<Cx> {
    fn sign(&self, pair: &sp_core::ed25519::Pair) -> [u8; 64] {
        use sp_core::Pair;
        let payload = self.payload();
        pair.sign(&payload).0
    }
}
