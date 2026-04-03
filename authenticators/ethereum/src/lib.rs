#![cfg_attr(not(feature = "std"), no_std)]

//! # Ethereum Authenticator for Pallet Pass
//!
//! Verifies Ethereum `personal_sign` signatures, enabling MetaMask,
//! WalletConnect and other EVM wallets to authenticate with pallet-pass.

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use traits_authn::{AuthorityId, Challenge, DeviceId, HashedUserId};

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "runtime"))]
mod runtime {
    use super::*;
    use traits_authn::{prelude::*, util::*};
    const LOG_TARGET: &str = "pass_authenticators_ethereum";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    pub type Authenticator<Ch, AuthId> = Auth<Device<Ch, AuthId>, EthRegistration<CxOf<Ch>>>;
    pub type Device<Ch, A> = Dev<EthAddress, A, Ch, EthSignature<CxOf<Ch>>>;
}

#[cfg(any(feature = "runtime", test))]
pub use runtime::{Authenticator, Device};

mod eth;

/// A 20-byte Ethereum address stored in a 32-byte DeviceId-compatible container
/// (left-padded with 12 zero bytes).
#[derive(
    Clone,
    Copy,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    MaxEncodedLen,
    PartialEq,
    Eq,
    Debug,
)]
pub struct EthAddress([u8; 32]);

impl EthAddress {
    /// Create from a raw 20-byte Ethereum address.
    pub fn from_raw(addr: [u8; 20]) -> Self {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&addr);
        Self(padded)
    }

    /// Get the raw 20-byte Ethereum address.
    pub fn as_eth_bytes(&self) -> &[u8; 20] {
        self.0[12..].try_into().expect("slice is exactly 20 bytes")
    }

    /// Check that the upper 12 padding bytes are zero.
    pub fn is_well_formed(&self) -> bool {
        self.0[..12] == [0u8; 12]
    }
}

impl AsRef<DeviceId> for EthAddress {
    fn as_ref(&self) -> &DeviceId {
        &self.0
    }
}

/// A signed message containing the challenge context and authority.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct SignedMessage<Cx> {
    pub context: Cx,
    pub challenge: Challenge,
    pub authority_id: AuthorityId,
}

/// Registration of an Ethereum address as a device.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct EthRegistration<Cx> {
    pub address: EthAddress,
    pub message: SignedMessage<Cx>,
    /// 65-byte secp256k1 signature (r[32] || s[32] || v[1])
    pub signature: [u8; 65],
}

/// A credential proving the user controls an Ethereum address.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct EthSignature<Cx> {
    pub user_id: HashedUserId,
    pub message: SignedMessage<Cx>,
    /// 65-byte secp256k1 signature (r[32] || s[32] || v[1])
    pub signature: [u8; 65],
}
