#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::{AccountId32, MultiSignature};
use traits_authn::{AuthorityId, Challenge, HashedUserId};

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
pub mod weights;

pub use weights::{SubstrateWeight, WeightInfo};

/// This crate's [`WeightInfo`] as the authenticator's [`AuthenticatorWeightInfo`], which the
/// `Authenticator` and `Device` aliases take: bind [`DefaultWeights<Runtime>`] for the weights
/// measured by this crate, or `Weights<W>` for any other [`WeightInfo`] `W`, such as the output
/// of a runtime's own run of this crate's benchmarks.
///
/// Verification doesn't depend on the lengths `c` and `a` (a registration or a signature is a
/// fixed-size message and a signature), but on the key type, which isn't known from them. So
/// both report the costliest key type: an upper bound for any registration or signature.
///
/// [`AuthenticatorWeightInfo`]: traits_authn::AuthenticatorWeightInfo
pub struct Weights<W>(core::marker::PhantomData<W>);

/// The weights measured by this crate's benchmarks (see [`Weights`]).
pub type DefaultWeights<T> = Weights<SubstrateWeight<T>>;

impl<W: WeightInfo> traits_authn::AuthenticatorWeightInfo for Weights<W> {
    fn verify_device(_c: u32, _a: u32) -> frame_support::weights::Weight {
        W::verify_attestation_sr25519()
            .max(W::verify_attestation_ed25519())
            .max(W::verify_attestation_ecdsa())
            .max(W::verify_attestation_eth())
    }

    fn verify_user(_c: u32, _a: u32) -> frame_support::weights::Weight {
        W::verify_credential_sr25519()
            .max(W::verify_credential_ed25519())
            .max(W::verify_credential_ecdsa())
            .max(W::verify_credential_eth())
    }
}

#[cfg(any(test, feature = "runtime"))]
mod runtime {
    use super::*;
    use traits_authn::{prelude::*, util::*};
    const LOG_TARGET: &str = "pass_authenticators_substrate_keys";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    /// The Substrate keys authenticator, for the challenger `Ch` and the authority `AuthId`.
    ///
    /// `W` is what verifying registrations and signatures costs, which `fc-pallet-pass` charges
    /// on top of its own weights. Bind [`DefaultWeights<Runtime>`](crate::DefaultWeights) (this
    /// crate's benchmarked weights), or [`Weights<W>`](crate::Weights) for a runtime's own run of
    /// this crate's benchmarks.
    pub type Authenticator<Ch, AuthId, W> =
        Auth<Device<Ch, AuthId, W>, KeyRegistration<CxOf<Ch>>, W>;
    /// A Substrate public key, registered as a device. `W` is as in [`Authenticator`].
    pub type Device<Ch, A, W> = Dev<AccountId32, A, Ch, KeySignature<CxOf<Ch>>, W>;
}

#[cfg(any(feature = "runtime", test))]
pub use runtime::{Authenticator, Device};

mod signed_message;

/// A message to be signed.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct SignedMessage<Cx> {
    pub context: Cx,
    pub challenge: Challenge,
    pub authority_id: AuthorityId,
}

/// A structure which represents the registration of a key into the authenticator.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct KeyRegistration<Cx> {
    pub public: AccountId32,
    pub message: SignedMessage<Cx>,
    pub signature: MultiSignature,
}

/// A structure which represents the signature of a message with a given key.
#[derive(
    Clone, Encode, Decode, DecodeWithMemTracking, TypeInfo, MaxEncodedLen, PartialEq, Eq, Debug,
)]
pub struct KeySignature<Cx> {
    pub user_id: HashedUserId,
    pub message: SignedMessage<Cx>,
    pub signature: MultiSignature,
}

#[cfg(feature = "full-crypto")]
/// Allows an arbitrary message to be signed from a signer which returns a [`MultiSignature`].
pub trait Sign<S, Cx> {
    /// Signs a message, returning a [`MultiSignature`].
    fn sign(&self, signer: S) -> MultiSignature;
}
