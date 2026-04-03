#![cfg_attr(not(feature = "std"), no_std)]

//! # Solana Authenticator for Pallet Pass
//!
//! Verifies Ed25519 signatures from Solana wallets (Phantom, Solflare, etc.).
//! Solana wallets sign raw message bytes directly using Ed25519.

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
    const LOG_TARGET: &str = "pass_authenticators_solana";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    pub type Authenticator<Ch, AuthId> = Auth<Device<Ch, AuthId>, SolRegistration<CxOf<Ch>>>;
    pub type Device<Ch, A> = Dev<SolPubkey, A, Ch, SolSignature<CxOf<Ch>>>;
}

#[cfg(any(feature = "runtime", test))]
pub use runtime::{Authenticator, Device};

mod sol;

/// A 32-byte Ed25519 public key (Solana address).
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
pub struct SolPubkey(pub [u8; 32]);

impl AsRef<DeviceId> for SolPubkey {
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

/// Registration of a Solana public key as a device.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct SolRegistration<Cx> {
    pub pubkey: SolPubkey,
    pub message: SignedMessage<Cx>,
    /// 64-byte Ed25519 signature
    pub signature: [u8; 64],
}

/// A credential proving the user controls a Solana key.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct SolSignature<Cx> {
    pub user_id: HashedUserId,
    pub message: SignedMessage<Cx>,
    /// 64-byte Ed25519 signature
    pub signature: [u8; 64],
}
