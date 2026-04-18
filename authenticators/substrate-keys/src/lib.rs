#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode};
use traits_authn::{AuthorityId, Challenge, HashedUserId};

#[cfg(feature = "runtime")]
use {
    codec::{DecodeWithMemTracking, MaxEncodedLen},
    scale_info::TypeInfo,
    sp_runtime::{AccountId32, MultiSignature},
};

// Lightweight SCALE-compatible types for client-side use (no sp-runtime dependency).
// The SCALE encoding is identical to sp_runtime::AccountId32 and sp_runtime::MultiSignature.
#[cfg(not(feature = "runtime"))]
pub type AccountId32 = [u8; 32];

#[cfg(not(feature = "runtime"))]
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
pub enum MultiSignature {
    Ed25519([u8; 64]),
    Sr25519([u8; 64]),
    Ecdsa([u8; 65]),
}

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(feature = "runtime")]
mod runtime {
    use super::*;
    use traits_authn::{prelude::*, util::*};
    const LOG_TARGET: &str = "pass_authenticators_substrate_keys";

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    pub type Authenticator<Ch, AuthId> = Auth<Device<Ch, AuthId>, KeyRegistration<CxOf<Ch>>>;
    pub type Device<Ch, A> = Dev<AccountId32, A, Ch, KeySignature<CxOf<Ch>>>;
}

#[cfg(feature = "runtime")]
pub use runtime::{Authenticator, Device};

mod signed_message;

/// A message to be signed.
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

/// A structure which represents the registration of a key into the authenticator.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct KeyRegistration<Cx> {
    pub public: AccountId32,
    pub message: SignedMessage<Cx>,
    pub signature: MultiSignature,
}

/// A structure which represents the signature of a message with a given key.
#[derive(Clone, Encode, Decode, PartialEq, Eq, Debug)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
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
