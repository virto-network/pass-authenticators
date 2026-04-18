#![cfg_attr(not(feature = "std"), no_std)]

//! # Bitcoin Authenticator for Pallet Pass
//!
//! Verifies Bitcoin message signatures (BIP-137 compatible), enabling
//! Bitcoin wallets to authenticate with pallet-pass.
//!
//! Uses the standard Bitcoin Signed Message format:
//! `SHA256d("\x18Bitcoin Signed Message:\n" || varint(len) || message)`

use codec::{Decode, Encode};
use traits_authn::{AuthorityId, Challenge, DeviceId, HashedUserId};

#[cfg(feature = "runtime")]
use {
    codec::{DecodeWithMemTracking, MaxEncodedLen},
    scale_info::TypeInfo,
};

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(feature = "runtime")]
mod runtime {
    use super::*;
    use traits_authn::{prelude::*, util::*};
    const LOG_TARGET: &str = "pass_authenticators_bitcoin";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    pub type Authenticator<Ch, AuthId> = Auth<Device<Ch, AuthId>, BtcRegistration<CxOf<Ch>>>;
    pub type Device<Ch, A> = Dev<BtcPubkeyHash, A, Ch, BtcSignature<CxOf<Ch>>>;
}

#[cfg(feature = "runtime")]
pub use runtime::{Authenticator, Device};

#[cfg(feature = "runtime")]
mod btc;

/// A Bitcoin public key hash (HASH160 = RIPEMD160(SHA256(pubkey))), stored
/// in a 32-byte DeviceId-compatible container (left-padded with zeros).
#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct BtcPubkeyHash([u8; 32]);

impl BtcPubkeyHash {
    /// Create from a raw 20-byte HASH160.
    pub fn from_hash160(hash: [u8; 20]) -> Self {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&hash);
        Self(padded)
    }

    /// Get the raw 20-byte HASH160.
    pub fn as_hash160(&self) -> &[u8; 20] {
        self.0[12..].try_into().expect("slice is exactly 20 bytes")
    }
}

impl AsRef<DeviceId> for BtcPubkeyHash {
    fn as_ref(&self) -> &DeviceId {
        &self.0
    }
}

/// A signed message containing the challenge context and authority.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct SignedMessage<Cx> {
    pub context: Cx,
    pub challenge: Challenge,
    pub authority_id: AuthorityId,
}

/// Registration of a Bitcoin public key as a device.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct BtcRegistration<Cx> {
    pub pubkey_hash: BtcPubkeyHash,
    pub message: SignedMessage<Cx>,
    /// 65-byte recoverable signature (recovery_flag[1] || r[32] || s[32])
    pub signature: [u8; 65],
}

/// A credential proving the user controls a Bitcoin key.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct BtcSignature<Cx> {
    pub user_id: HashedUserId,
    pub message: SignedMessage<Cx>,
    /// 65-byte recoverable signature (recovery_flag[1] || r[32] || s[32])
    pub signature: [u8; 65],
}
