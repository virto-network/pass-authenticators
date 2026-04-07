#![cfg_attr(not(feature = "std"), no_std)]

//! # SSH Ed25519 Authenticator for Pallet Pass
//!
//! Verifies Ed25519 signatures following the SSH signing format (RFC 8709),
//! useful for developer workflows where SSH keys are already available.
//!
//! The signed data follows the SSH `SSHSIG` wire format:
//! `MAGIC_PREAMBLE || namespace || reserved || hash_algorithm || H(message)`

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
    const LOG_TARGET: &str = "pass_authenticators_ssh";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    pub type Authenticator<Ch, AuthId> = Auth<Device<Ch, AuthId>, SshRegistration<CxOf<Ch>>>;
    pub type Device<Ch, A> = Dev<SshPubkey, A, Ch, SshSignature<CxOf<Ch>>>;
}

#[cfg(feature = "runtime")]
pub use runtime::{Authenticator, Device};

#[cfg(feature = "runtime")]
mod ssh;

/// A 32-byte Ed25519 public key (SSH key fingerprint maps to this).
#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "runtime", derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen))]
pub struct SshPubkey(pub [u8; 32]);

impl AsRef<DeviceId> for SshPubkey {
    fn as_ref(&self) -> &DeviceId {
        &self.0
    }
}

/// A signed message containing the challenge context and authority.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "runtime", derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen))]
pub struct SignedMessage<Cx> {
    pub context: Cx,
    pub challenge: Challenge,
    pub authority_id: AuthorityId,
}

/// Registration of an SSH Ed25519 public key as a device.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "runtime", derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen))]
pub struct SshRegistration<Cx> {
    pub pubkey: SshPubkey,
    pub message: SignedMessage<Cx>,
    /// 64-byte Ed25519 signature
    pub signature: [u8; 64],
}

/// A credential proving the user controls an SSH key.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "runtime", derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen))]
pub struct SshSignature<Cx> {
    pub user_id: HashedUserId,
    pub message: SignedMessage<Cx>,
    /// 64-byte Ed25519 signature
    pub signature: [u8; 64],
}
