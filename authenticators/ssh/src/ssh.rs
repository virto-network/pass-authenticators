use super::*;

extern crate alloc;
use alloc::vec::Vec;

/// SSH signature magic preamble (RFC 8709 / SSHSIG format).
const MAGIC_PREAMBLE: &[u8] = b"SSHSIG";
/// Namespace for pallet-pass authentication.
const NAMESPACE: &[u8] = b"pallet-pass";
/// Hash algorithm identifier.
const HASH_ALGO: &[u8] = b"sha256";

impl<Cx: Encode> SignedMessage<Cx> {
    /// The domain-separated payload bytes.
    /// Prefixed with `b"SSH"` to prevent cross-authenticator signature replay.
    pub fn payload(&self) -> Vec<u8> {
        [
            b"SSH".as_slice(),
            self.context.encode().as_ref(),
            &self.challenge[..],
            &self.authority_id[..],
        ]
        .concat()
    }

    /// Build the SSHSIG-style signed data.
    ///
    /// Format:
    /// ```text
    /// MAGIC_PREAMBLE (6 bytes)
    /// namespace_len (4 bytes BE) || namespace
    /// reserved_len (4 bytes BE, = 0)
    /// hash_algo_len (4 bytes BE) || hash_algo
    /// hash_len (4 bytes BE) || SHA256(payload)
    /// ```
    pub fn ssh_signed_data(&self) -> Vec<u8> {
        let payload = self.payload();
        let hash = sp_io::hashing::sha2_256(&payload);

        let mut data = Vec::new();
        data.extend_from_slice(MAGIC_PREAMBLE);
        // namespace (string)
        data.extend_from_slice(&(NAMESPACE.len() as u32).to_be_bytes());
        data.extend_from_slice(NAMESPACE);
        // reserved (empty string)
        data.extend_from_slice(&0u32.to_be_bytes());
        // hash algorithm (string)
        data.extend_from_slice(&(HASH_ALGO.len() as u32).to_be_bytes());
        data.extend_from_slice(HASH_ALGO);
        // hash (string)
        data.extend_from_slice(&(hash.len() as u32).to_be_bytes());
        data.extend_from_slice(&hash);

        data
    }
}

/// Verify an Ed25519 signature against an SSH public key using the SSHSIG format.
pub fn verify_ssh_ed25519(pubkey: &SshPubkey, signed_data: &[u8], signature: &[u8; 64]) -> bool {
    let ed_pub = sp_core::ed25519::Public::from_raw(pubkey.0);
    let ed_sig = sp_core::ed25519::Signature::from_raw(*signature);
    sp_io::crypto::ed25519_verify(&ed_sig, signed_data, &ed_pub)
}

#[cfg(feature = "full-crypto")]
impl<Cx: Encode> SignedMessage<Cx> {
    /// Sign the SSHSIG-formatted data with an Ed25519 key pair.
    pub fn sign(&self, pair: &sp_core::ed25519::Pair) -> [u8; 64] {
        use sp_core::Pair;
        let data = self.ssh_signed_data();
        pair.sign(&data).0
    }
}
