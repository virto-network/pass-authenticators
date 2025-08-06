use super::*;
use frame::deps::sp_core::hexdisplay::AsBytesRef;

use crate::runtime::authenticator_data::AuthenticatorFlags;
use authenticator_data::AuthenticatorData;
use traits_authn::{util::VerifyCredential, Challenger};
use webauthn_verifier::webauthn_verify as verify_signature;

const LOG_TARGET: &str = "pass::webauthn";

impl<Ch, A> From<Attestation<CxOf<Ch>>> for Device<Ch, A>
where
    Ch: Challenger,
    CxOf<Ch>: Parameter + Copy + 'static,
{
    fn from(value: Attestation<CxOf<Ch>>) -> Self {
        if let Ok(authenticator_data) =
            TryInto::<AuthenticatorData>::try_into(value.authenticator_data.as_bytes_ref())
        {
            Device::new(CredentialRecord {
                device_id: *value.device_id(),
                public_key: value.public_key,
                sign_count: 0,
                backup_eligible: authenticator_data
                    .flags
                    .contains(AuthenticatorFlags::BACKUP_ELEGIBILITY),
                backup_state: authenticator_data
                    .flags
                    .contains(AuthenticatorFlags::BACKUP_STATE),
            })
        } else {
            // Creation of the `CredentialRecord` must be infallible to comply
            // with `Device`.
            Device::new(CredentialRecord {
                device_id: *value.device_id(),
                public_key: value.public_key,
                sign_count: 0,
                backup_eligible: false,
                backup_state: false,
            })
        }
    }
}

impl<Cx> VerifyCredential<Assertion<Cx>> for CredentialRecord {
    fn verify(&mut self, credential: &Assertion<Cx>) -> Option<()> {
        let Ok(authenticator_data): Result<AuthenticatorData, _> =
            credential.authenticator_data.as_bytes_ref().try_into()
        else {
            log::trace!(
                target: LOG_TARGET,
                "Failed to parse credential's authenticator_data"
            );
            return None;
        };

        log::trace!(
            target: LOG_TARGET,
            "Verifying credentials with public key {:?}, signature {:?}, and authenticator_data {authenticator_data:?}",
            &self.public_key,
            &credential.signature
        );

        // Verify sign count
        ((authenticator_data.sign_count == 0 || authenticator_data.sign_count > self.sign_count)
            // Check BE
            && (self.backup_eligible
                == authenticator_data
                    .flags
                    .contains(AuthenticatorFlags::BACKUP_ELEGIBILITY)))
        .then_some(())
        .and_then(|_| {
            verify_signature(
                &credential.authenticator_data,
                &credential.client_data,
                &credential.signature,
                &self.public_key,
            )
            .ok()?;

            // Update `signCount` and BS.
            self.sign_count = authenticator_data.sign_count;
            self.backup_state = authenticator_data
                .flags
                .contains(AuthenticatorFlags::BACKUP_STATE);

            Some(())
        })
    }
}

impl AsRef<DeviceId> for CredentialRecord {
    fn as_ref(&self) -> &DeviceId {
        &self.device_id
    }
}
