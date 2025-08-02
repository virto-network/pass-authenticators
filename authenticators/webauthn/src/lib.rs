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

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(any(feature = "runtime", test))]
pub use runtime::{Authenticator, Device};
#[cfg(any(feature = "runtime", test))]
mod runtime;

pub type DEREncodedPublicKey = [u8; 91];

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(
    any(feature = "runtime", test),
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct Credential {
    device_id: DeviceId,
    //. A DER-encoded public key
    public_key: DEREncodedPublicKey,
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
