#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use codec::{Decode, Encode};
use traits_authn::{AuthorityId, DeviceId, HashedUserId};
#[cfg(feature = "runtime")]
use {
    codec::{DecodeWithMemTracking, MaxEncodedLen},
    frame::prelude::BoundedVec,
    frame::traits::ConstU32,
    scale_info::TypeInfo,
};

#[cfg(test)]
mod mock;
#[cfg(test)]
mod tests;

#[cfg(feature = "runtime")]
pub use runtime::{Authenticator, Device};
#[cfg(feature = "runtime")]
mod runtime;

pub type DEREncodedPublicKey = [u8; 91];

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(
    feature = "runtime",
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
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct AttestationMeta<Cx> {
    pub(crate) authority_id: AuthorityId,
    pub(crate) device_id: DeviceId,
    pub(crate) context: Cx,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "runtime", derive(DecodeWithMemTracking, TypeInfo))]
pub struct Attestation<Cx> {
    pub(crate) meta: AttestationMeta<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    #[cfg(not(feature = "runtime"))]
    pub(crate) client_data: Vec<u8>,
    #[cfg(feature = "runtime")]
    pub(crate) client_data: BoundedVec<u8, ConstU32<1024>>,
    pub(crate) public_key: DEREncodedPublicKey,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq, Copy)]
#[cfg_attr(
    feature = "runtime",
    derive(DecodeWithMemTracking, TypeInfo, MaxEncodedLen)
)]
pub struct AssertionMeta<Cx> {
    pub(crate) authority_id: AuthorityId,
    pub(crate) user_id: HashedUserId,
    pub(crate) context: Cx,
}

#[derive(Clone, Encode, Decode, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "runtime", derive(DecodeWithMemTracking, TypeInfo))]
pub struct Assertion<Cx> {
    pub(crate) meta: AssertionMeta<Cx>,
    pub(crate) authenticator_data: Vec<u8>,
    #[cfg(not(feature = "runtime"))]
    pub(crate) client_data: Vec<u8>,
    #[cfg(feature = "runtime")]
    pub(crate) client_data: BoundedVec<u8, ConstU32<1024>>,
    pub(crate) signature: Vec<u8>,
}
