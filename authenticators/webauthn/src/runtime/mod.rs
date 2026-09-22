use super::*;

use alloc::string::String;
use frame::prelude::Parameter;
use frame_support::weights::Weight;
use traits_authn::{
    util::{Auth, Dev},
    AuthorityId, Challenge, Challenger, DeviceChallengeResponse, DeviceId,
};

type CxOf<Ch> = <Ch as Challenger>::Context;

pub type Authenticator<Ch, A> = Auth<Device<Ch, A>, Attestation<CxOf<Ch>>>;
pub type Device<Ch, A> = Dev<CredentialRecord, A, Ch, Assertion<CxOf<Ch>>>;

/// The shortest client data the benchmarks cover: `{"type":"webauthn.create",…}` with a bare
/// origin (assertions' `webauthn.get` is 3 bytes shorter). Verification weights never go
/// below what the benchmarks measured for it.
pub const MIN_CLIENT_DATA_LEN: u32 = 138;
/// The longest client data an attestation or an assertion can carry.
pub const MAX_CLIENT_DATA_LEN: u32 = 1024;
/// The shortest attestation authenticator data the benchmarks cover: the required fields, the
/// attested credential data (with a 32-byte credential id), and a P-256 credential public key.
/// Verification weights never go below what the benchmarks measured for it.
pub const MIN_ATTESTATION_AUTHENTICATOR_DATA_LEN: u32 = 168;
/// The shortest authenticator data of an assertion: just the required fields.
pub const MIN_ASSERTION_AUTHENTICATOR_DATA_LEN: u32 = 37;
/// The longest authenticator data the benchmarks cover. Nothing caps it (it is only bounded by
/// the length of the extrinsic), so weights extrapolate linearly beyond it.
pub const MAX_AUTHENTICATOR_DATA_LEN: u32 = 2048;

/// The length of `bytes`, as a benchmark component no lower than `min`.
pub(crate) fn component(bytes: &[u8], min: u32) -> u32 {
    u32::try_from(bytes.len()).unwrap_or(u32::MAX).max(min)
}

pub mod assertion;
pub mod attestation;
pub mod credential_record;

mod authenticator_data;
mod client_data;
