#![cfg_attr(not(feature = "std"), no_std)]

//! # Nostr Authenticator for Pallet Pass
//!
//! Verifies BIP-340 Schnorr signatures over secp256k1, enabling
//! Nostr clients (NIP-07 compatible) to authenticate with pallet-pass.

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
    const LOG_TARGET: &str = "pass_authenticators_nostr";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    pub type Authenticator<Ch, AuthId> = Auth<Device<Ch, AuthId>, NostrRegistration<CxOf<Ch>>>;
    pub type Device<Ch, A> = Dev<NostrPubkey, A, Ch, NostrSignature<CxOf<Ch>>>;
}

#[cfg(any(feature = "runtime", test))]
pub use runtime::{Authenticator, Device};

mod schnorr;

/// A 32-byte x-only secp256k1 public key (Nostr npub).
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
pub struct NostrPubkey(pub [u8; 32]);

impl AsRef<DeviceId> for NostrPubkey {
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

/// Registration of a Nostr public key as a device.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct NostrRegistration<Cx> {
    pub pubkey: NostrPubkey,
    pub message: SignedMessage<Cx>,
    /// 64-byte BIP-340 Schnorr signature
    pub signature: [u8; 64],
}

/// A credential proving the user controls a Nostr key.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct NostrSignature<Cx> {
    pub user_id: HashedUserId,
    pub message: SignedMessage<Cx>,
    /// 64-byte BIP-340 Schnorr signature
    pub signature: [u8; 64],
}
