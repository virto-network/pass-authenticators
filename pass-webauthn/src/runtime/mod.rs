use super::*;

use frame::prelude::Parameter;
use traits_authn::{AuthorityId, Challenge, DeviceChallengeResponse, DeviceId};

type CxOf<Ch> = <Ch as Challenger>::Context;

#[cfg(any(feature = "runtime", test))]
pub type Authenticator<Ch, A> = Auth<Device<Ch, A>, Attestation<CxOf<Ch>>>;
#[cfg(any(feature = "runtime", test))]
pub type Device<Ch, A> = Dev<Credential, A, Ch, Assertion<CxOf<Ch>>>;

pub mod assertion;
pub mod attestation;
pub mod credential;
mod helpers;
