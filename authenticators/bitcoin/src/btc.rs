use super::*;
use sp_io::hashing::sha2_256;

extern crate alloc;
use alloc::vec::Vec;

impl<Cx: Encode> SignedMessage<Cx> {
    /// The domain-separated payload bytes.
    /// Prefixed with `b"BTC"` to prevent cross-authenticator signature replay.
    pub fn payload(&self) -> Vec<u8> {
        [
            b"BTC".as_slice(),
            self.context.encode().as_ref(),
            &self.challenge[..],
            &self.authority_id[..],
        ]
        .concat()
    }

    /// Compute the Bitcoin message hash (double SHA256).
    /// Format: SHA256(SHA256("\x18Bitcoin Signed Message:\n" || varint(len) || payload))
    pub fn btc_message_hash(&self) -> [u8; 32] {
        let payload = self.payload();
        bitcoin_message_hash(&payload)
    }
}

/// Encode a length as a Bitcoin-style varint.
fn varint(len: usize) -> Vec<u8> {
    if len < 0xFD {
        alloc::vec![len as u8]
    } else if len <= 0xFFFF {
        let mut v = alloc::vec![0xFD];
        v.extend_from_slice(&(len as u16).to_le_bytes());
        v
    } else {
        let mut v = alloc::vec![0xFE];
        v.extend_from_slice(&(len as u32).to_le_bytes());
        v
    }
}

/// Hash using Bitcoin Signed Message format (double SHA256).
/// `SHA256(SHA256("\x18Bitcoin Signed Message:\n" || varint(len) || message))`
pub fn bitcoin_message_hash(message: &[u8]) -> [u8; 32] {
    let prefix = b"\x18Bitcoin Signed Message:\n";
    let mut data = Vec::with_capacity(prefix.len() + 5 + message.len());
    data.extend_from_slice(prefix);
    data.extend_from_slice(&varint(message.len()));
    data.extend_from_slice(message);
    sha2_256(&sha2_256(&data))
}

/// Recover a Bitcoin public key hash (HASH160) from a signed message.
///
/// The signature format follows BIP-137: recovery_flag[1] || r[32] || s[32]
/// where recovery_flag encodes the recovery id and key compression.
pub fn recover_btc_pubkey_hash(
    message_hash: &[u8; 32],
    signature: &[u8; 65],
) -> Option<BtcPubkeyHash> {
    // BIP-137: first byte is recovery flag
    // 27-30: uncompressed key, 31-34: compressed key
    let flag = signature[0];
    let (recovery_id, compressed) = match flag {
        27..=30 => (flag - 27, false),
        31..=34 => (flag - 31, true),
        _ => return None,
    };

    // Rearrange to sp_io format: r[32] || s[32] || recovery_id[1]
    let mut sig = [0u8; 65];
    sig[..64].copy_from_slice(&signature[1..65]);
    sig[64] = recovery_id;

    if compressed {
        let pubkey = sp_io::crypto::secp256k1_ecdsa_recover_compressed(&sig, message_hash).ok()?;
        Some(BtcPubkeyHash::from_hash160(hash160(&pubkey)))
    } else {
        let pubkey = sp_io::crypto::secp256k1_ecdsa_recover(&sig, message_hash).ok()?;
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 0x04;
        uncompressed[1..].copy_from_slice(&pubkey);
        Some(BtcPubkeyHash::from_hash160(hash160(&uncompressed)))
    }
}

/// Bitcoin HASH160: RIPEMD160(SHA256(data)).
fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::{Digest, Ripemd160};
    let sha = sha2_256(data);
    let mut hasher = Ripemd160::new();
    hasher.update(sha);
    hasher.finalize().into()
}

#[cfg(feature = "full-crypto")]
impl<Cx: Encode> SignedMessage<Cx> {
    /// Sign the message with a secp256k1 key, producing a 65-byte BIP-137 signature.
    pub fn sign(&self, pair: &sp_core::ecdsa::Pair) -> [u8; 65] {
        let hash = self.btc_message_hash();
        let raw_sig = pair.sign_prehashed(&hash);
        let mut btc_sig = [0u8; 65];
        btc_sig[0] = 31 + raw_sig.0[64];
        btc_sig[1..].copy_from_slice(&raw_sig.0[..64]);
        btc_sig
    }
}
