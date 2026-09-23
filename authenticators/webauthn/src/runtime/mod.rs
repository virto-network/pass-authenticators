use super::*;

use alloc::string::String;
use frame::prelude::Parameter;
use traits_authn::{AuthorityId, Challenge, DeviceChallengeResponse, DeviceId};

type CxOf<Ch> = <Ch as Challenger>::Context;

/// The WebAuthn authenticator, for the challenger `Ch` and the authority `A`.
///
/// `W` is what verifying attestations and assertions costs, which `fc-pallet-pass` charges on
/// top of its own weights. Bind [`WeightInfo<Runtime>`](crate::WeightInfo) (this crate's
/// benchmarked weights), or a runtime's own run of this crate's benchmarks.
pub type Authenticator<Ch, A, W> = Auth<Device<Ch, A, W>, Attestation<CxOf<Ch>>, W>;
/// A WebAuthn credential, registered as a device. `W` is as in [`Authenticator`].
pub type Device<Ch, A, W> = Dev<CredentialRecord, A, Ch, Assertion<CxOf<Ch>>, W>;

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

/// The length of `bytes`, as a weight component (saturating, so it never under-counts).
pub(crate) fn len_component(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).unwrap_or(u32::MAX)
}

pub mod assertion;
pub mod attestation;
pub mod credential_record;

mod authenticator_data;
mod client_data;
