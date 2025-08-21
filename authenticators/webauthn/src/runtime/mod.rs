use super::*;

use alloc::string::String;
use frame::prelude::Parameter;
use traits_authn::{AuthorityId, Challenge, DeviceChallengeResponse, DeviceId};

type CxOf<Ch> = <Ch as Challenger>::Context;

pub type Authenticator<Ch, A> = Auth<Device<Ch, A>, Attestation<CxOf<Ch>>>;
pub type Device<Ch, A> = Dev<CredentialRecord, A, Ch, Assertion<CxOf<Ch>>>;

pub mod assertion;
pub mod attestation;
pub mod credential_record;

mod authenticator_data;
mod client_data;
