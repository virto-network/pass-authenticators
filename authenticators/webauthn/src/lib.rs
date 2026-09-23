#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, DecodeWithMemTracking, Encode};
use frame::prelude::BoundedVec;
use frame::traits::ConstU32;
use traits_authn::{
    util::{Auth, Dev},
    AuthorityId, Challenger, DeviceId, HashedUserId,
};
#[cfg(any(feature = "runtime", test))]
use {codec::MaxEncodedLen, scale_info::TypeInfo};

#[cfg(feature = "runtime-benchmarks")]
pub mod benchmarking;
#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;
#[cfg(any(feature = "runtime", test))]
pub mod weights;

#[cfg(any(feature = "runtime", test))]
pub use weights::{SubstrateWeight, WeightInfo};

/// This crate's [`WeightInfo`] as the authenticator's [`AuthenticatorWeightInfo`], which the
/// [`Authenticator`] and [`Device`] aliases take: bind [`DefaultWeights<Runtime>`] for the
/// weights measured by this crate, or `Weights<W>` for any other [`WeightInfo`] `W`, such as
/// the output of a runtime's own run of this crate's benchmarks.
///
/// Verifying an attestation is what the `verify_attestation` benchmark measures, and verifying an
/// assertion (including its P-256 signature) what `verify_credential` measures, both for client
/// data `c` bytes long and authenticator data `a` bytes long.
///
/// `c` is capped at [`MAX_CLIENT_DATA_LEN`], the longest client data can be, and neither
/// component goes below the shortest input the benchmarks cover (the fit extrapolates, rather
/// than measures, below it).
///
/// [`AuthenticatorWeightInfo`]: traits_authn::AuthenticatorWeightInfo
#[cfg(any(feature = "runtime", test))]
pub struct Weights<W>(core::marker::PhantomData<W>);

/// The weights measured by this crate's benchmarks (see [`Weights`]).
#[cfg(any(feature = "runtime", test))]
pub type DefaultWeights<T> = Weights<SubstrateWeight<T>>;

#[cfg(any(feature = "runtime", test))]
impl<W: WeightInfo> traits_authn::AuthenticatorWeightInfo for Weights<W> {
    fn verify_device(c: u32, a: u32) -> frame_support::weights::Weight {
        W::verify_attestation(
            c.clamp(MIN_CLIENT_DATA_LEN, MAX_CLIENT_DATA_LEN),
            a.max(MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN),
        )
    }

    fn verify_user(c: u32, a: u32) -> frame_support::weights::Weight {
        W::verify_credential(
            c.clamp(MIN_CLIENT_DATA_LEN, MAX_CLIENT_DATA_LEN),
            a.max(MIN_ASSERTION_AUTHENTICATOR_DATA_LEN),
        )
    }
}

#[cfg(any(feature = "runtime", test))]
pub use runtime::{
    Authenticator, Device, MAX_AUTHENTICATOR_DATA_LEN, MAX_CLIENT_DATA_LEN,
    MIN_ASSERTION_AUTHENTICATOR_DATA_LEN, MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN,
    MIN_CLIENT_DATA_LEN,
};
#[cfg(any(feature = "runtime", test))]
mod runtime;

pub type DEREncodedPublicKey = [u8; 91];

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(feature = "runtime", test),
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct CredentialRecord {
    device_id: DeviceId,
    //. A DER-encoded public key
    public_key: DEREncodedPublicKey,
    sign_count: u32,
    backup_eligible: bool,
    backup_state: bool,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(feature = "runtime", test),
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct AttestationMeta<Cx> {
    pub(crate) authority_id: AuthorityId,
    pub(crate) device_id: DeviceId,
    pub(crate) context: Cx,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "runtime", test),
    derive(DecodeWithMemTracking, TypeInfo)
)]
pub struct Attestation<Cx> {
    pub(crate) meta: AttestationMeta<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    #[cfg(not(any(feature = "runtime", test)))]
    pub(crate) client_data: Vec<u8>,
    #[cfg(any(feature = "runtime", test))]
    pub(crate) client_data: BoundedVec<u8, ConstU32<1024>>,
    pub(crate) public_key: DEREncodedPublicKey,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(feature = "runtime", test),
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct AssertionMeta<Cx> {
    pub(crate) authority_id: AuthorityId,
    pub(crate) user_id: HashedUserId,
    pub(crate) context: Cx,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
#[cfg_attr(
    any(feature = "runtime", test),
    derive(DecodeWithMemTracking, TypeInfo)
)]
pub struct Assertion<Cx> {
    pub(crate) meta: AssertionMeta<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    #[cfg(not(any(feature = "runtime", test)))]
    pub(crate) client_data: Vec<u8>,
    #[cfg(any(feature = "runtime", test))]
    pub(crate) client_data: BoundedVec<u8, ConstU32<1024>>,
    pub(crate) signature: Vec<u8>,
}
