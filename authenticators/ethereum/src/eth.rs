use super::*;
use sp_io::hashing::keccak_256;

extern crate alloc;

impl<Cx: Encode> SignedMessage<Cx> {
    /// The domain-separated payload bytes.
    /// Prefixed with `b"ETH"` to prevent cross-authenticator signature replay.
    pub fn payload(&self) -> alloc::vec::Vec<u8> {
        [
            b"ETH".as_slice(),
            self.context.encode().as_ref(),
            &self.challenge[..],
            &self.authority_id[..],
        ]
        .concat()
    }

    /// Compute the Ethereum personal_sign message hash.
    /// Format: keccak256("\x19Ethereum Signed Message:\n" || len || payload)
    pub fn eth_message_hash(&self) -> [u8; 32] {
        let payload = self.payload();
        personal_sign_hash(&payload)
    }
}

/// Hash a message using Ethereum's personal_sign format.
/// `keccak256("\x19Ethereum Signed Message:\n{len}{message}")`
pub fn personal_sign_hash(message: &[u8]) -> [u8; 32] {
    let prefix = alloc::format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = prefix.into_bytes();
    data.extend_from_slice(message);
    keccak_256(&data)
}

/// Recover an Ethereum address from a personal_sign signature.
pub fn recover_eth_address(message_hash: &[u8; 32], signature: &[u8; 65]) -> Option<EthAddress> {
    // The signature format is r[32] || s[32] || v[1]
    let mut sig = [0u8; 65];
    sig[..64].copy_from_slice(&signature[..64]);
    // Normalize v: Ethereum uses 27/28, secp256k1 recovery uses 0/1
    sig[64] = match signature[64] {
        v @ 0..=1 => v,
        v @ 27..=28 => v - 27,
        _ => return None,
    };

    // Recover uncompressed public key (64 bytes, without 0x04 prefix)
    let pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig, message_hash).ok()?;
    // Ethereum address = last 20 bytes of keccak256(uncompressed_pubkey)
    let hash = keccak_256(&pubkey);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Some(EthAddress::from_raw(addr))
}

#[cfg(feature = "full-crypto")]
impl<Cx: Encode> SignedMessage<Cx> {
    /// Sign the message with a secp256k1 key, producing a 65-byte Ethereum-style signature.
    pub fn sign(&self, pair: &sp_core::ecdsa::Pair) -> [u8; 65] {
        let hash = self.eth_message_hash();
        pair.sign_prehashed(&hash).0
    }
}
