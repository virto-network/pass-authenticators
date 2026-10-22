#![cfg_attr(not(feature = "std"), no_std)]

//! # Ethereum Authenticator for Pallet Pass
//!
//! Verifies Ethereum `personal_sign` signatures, enabling MetaMask,
//! WalletConnect and other EVM wallets to authenticate with pallet-pass.

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
    const LOG_TARGET: &str = "pass_authenticators_ethereum";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    /// The Ethereum authenticator, for the challenger `Ch` and the authority `AuthId`.
    ///
    /// `W` is what verifying registrations and signatures costs, which `fc-pallet-pass` charges
    /// on top of its own weights. Bind [`DefaultWeights<Runtime>`](crate::DefaultWeights) (this
    /// crate's weights), or [`Weights<W>`](crate::Weights) for a runtime's own run of this
    /// crate's benchmarks.
    pub type Authenticator<Ch, AuthId, W> =
        Auth<Device<Ch, AuthId, W>, EthRegistration<CxOf<Ch>>, W>;
    /// A Ethereum key, registered as a device. `W` is as in [`Authenticator`].
    pub type Device<Ch, A, W> = Dev<EthAddress, A, Ch, EthSignature<CxOf<Ch>>, W>;
}

#[cfg(feature = "runtime")]
pub use runtime::{Authenticator, Device};

#[cfg(feature = "runtime")]
mod eth;

/// A 20-byte Ethereum address stored in a 32-byte DeviceId-compatible container
/// (left-padded with 12 zero bytes).
#[derive(Clone, Copy, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
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

/// Registration of an Ethereum address as a device.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct EthRegistration<Cx> {
    pub address: EthAddress,
    pub message: SignedMessage<Cx>,
    /// 65-byte secp256k1 signature (r[32] || s[32] || v[1])
    pub signature: [u8; 65],
}

/// A credential proving the user controls an Ethereum address.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct EthSignature<Cx> {
    pub user_id: HashedUserId,
    pub message: SignedMessage<Cx>,
    /// 65-byte secp256k1 signature (r[32] || s[32] || v[1])
    pub signature: [u8; 65],
}
