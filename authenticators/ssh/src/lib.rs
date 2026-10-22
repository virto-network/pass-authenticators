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

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
#[cfg(feature = "runtime")]
pub mod weights;

#[cfg(feature = "runtime")]
pub use weights::{SubstrateWeight, WeightInfo};

/// This crate's [`WeightInfo`] as the authenticator's [`AuthenticatorWeightInfo`], which the
/// `Authenticator` and `Device` aliases take: bind [`DefaultWeights<Runtime>`] for the weights
/// in this crate, or `Weights<W>` for any other [`WeightInfo`] `W`, such as the output of a
/// runtime's own run of this crate's benchmarks.
///
/// Verification doesn't depend on the lengths `c` and `a`: a registration or a signature is a
/// fixed-size message and a signature.
///
/// [`AuthenticatorWeightInfo`]: traits_authn::AuthenticatorWeightInfo
#[cfg(feature = "runtime")]
pub struct Weights<W>(core::marker::PhantomData<W>);

/// The weights of this crate's benchmarks (see [`Weights`]).
#[cfg(feature = "runtime")]
pub type DefaultWeights<T> = Weights<SubstrateWeight<T>>;

#[cfg(feature = "runtime")]
impl<W: WeightInfo> traits_authn::AuthenticatorWeightInfo for Weights<W> {
    fn verify_device(_c: u32, _a: u32) -> frame_support::weights::Weight {
        W::verify_attestation()
    }

    fn verify_user(_c: u32, _a: u32) -> frame_support::weights::Weight {
        W::verify_credential()
    }
}

#[cfg(feature = "runtime")]
mod runtime {
    use super::*;
    use traits_authn::{prelude::*, util::*};
    const LOG_TARGET: &str = "pass_authenticators_ssh";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    /// The SSH authenticator, for the challenger `Ch` and the authority `AuthId`.
    ///
    /// `W` is what verifying registrations and signatures costs, which `fc-pallet-pass` charges
    /// on top of its own weights. Bind [`DefaultWeights<Runtime>`](crate::DefaultWeights) (this
    /// crate's weights), or [`Weights<W>`](crate::Weights) for a runtime's own run of this
    /// crate's benchmarks.
    pub type Authenticator<Ch, AuthId, W> =
        Auth<Device<Ch, AuthId, W>, SshRegistration<CxOf<Ch>>, W>;
    /// An SSH key, registered as a device. `W` is as in [`Authenticator`].
    pub type Device<Ch, A, W> = Dev<SshPubkey, A, Ch, SshSignature<CxOf<Ch>>, W>;
}

#[cfg(feature = "runtime")]
pub use runtime::{Authenticator, Device};

#[cfg(feature = "runtime")]
mod ssh;

/// A 32-byte Ed25519 public key (SSH key fingerprint maps to this).
#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct SshPubkey(pub [u8; 32]);

impl AsRef<DeviceId> for SshPubkey {
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

/// Registration of an SSH Ed25519 public key as a device.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct SshRegistration<Cx> {
    pub pubkey: SshPubkey,
    pub message: SignedMessage<Cx>,
    /// 64-byte Ed25519 signature
    pub signature: [u8; 64],
}

/// A credential proving the user controls an SSH key.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct SshSignature<Cx> {
    pub user_id: HashedUserId,
    pub message: SignedMessage<Cx>,
    /// 64-byte Ed25519 signature
    pub signature: [u8; 64],
}
