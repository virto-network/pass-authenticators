#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, DecodeWithMemTracking, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::{AccountId32, MultiSignature};
use traits_authn::{AuthorityId, Challenge, HashedUserId};

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "runtime"))]
mod runtime {
    use super::*;
    use traits_authn::{prelude::*, util::*, *};

    mod key_registration;
    mod key_signature;

    type CxOf<Ch> = <Ch as Challenger>::Context;
    pub type Authenticator<Ch, AuthId> = Auth<Device<Ch, AuthId>, KeyRegistration<CxOf<Ch>>>;
    pub type Device<Ch, A> = Dev<AccountId32, A, Ch, KeySignature<CxOf<Ch>>>;
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
    pub message: SignedMessage<Cx>,
    pub public: AccountId32,
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

/// Allows an arbitrary message to be signed from a signer which returns a [`MultiSignature`].
pub trait Sign<S, Cx> {
    /// Signs a message, returning a [`MultiSignature`].
    fn sign(&self, signer: S) -> MultiSignature;
}
