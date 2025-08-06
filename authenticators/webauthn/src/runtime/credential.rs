use super::*;

use traits_authn::{util::VerifyCredential, Challenger};
use webauthn_verifier::webauthn_verify;

use super::{CxOf, Device};

const LOG_TARGET: &str = "pass::webauthn";

#[cfg(any(feature = "runtime", test))]
impl<Ch, A> From<Attestation<CxOf<Ch>>> for Device<Ch, A>
where
    Ch: Challenger,
    CxOf<Ch>: Parameter + Copy + 'static,
{
    fn from(value: Attestation<CxOf<Ch>>) -> Self {
        Device::new(Credential {
            device_id: *value.device_id(),
            public_key: value.public_key,
        })
    }
}

impl<Cx> VerifyCredential<Assertion<Cx>> for Credential {
    fn verify(&mut self, credential: &Assertion<Cx>) -> Option<()> {
        log::trace!(
            target: LOG_TARGET,
            "Verifying credentials with public key {:?} and signature {:?}",
            &self.public_key,
            &credential.signature
        );
        webauthn_verify(
            &credential.authenticator_data,
            &credential.client_data,
            &credential.signature,
            &self.public_key,
        )
        .ok()
    }
}

#[cfg(any(feature = "runtime", test))]
impl AsRef<DeviceId> for Credential {
    fn as_ref(&self) -> &DeviceId {
        &self.device_id
    }
}
