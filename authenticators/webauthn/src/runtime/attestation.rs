use super::*;

impl<Cx> Attestation<Cx>
where
    Cx: Parameter,
{
    fn challenge(&self) -> Challenge {
        helpers::find_challenge_from_client_data(self.client_data.clone()).unwrap_or_default()
    }
}

#[cfg(any(feature = "runtime", test))]
impl<Cx> DeviceChallengeResponse<Cx> for Attestation<Cx>
where
    Cx: Parameter + Copy + 'static,
{
    // TODO: @pandres95, considering that DeviceChallengeResponse is used for creating a new
    // authentication device, webauth_verify wouldn't work here. We need to implement a new
    // verification method exclusively for credential creation.
    fn is_valid(&self) -> bool {
        true
    }

    fn used_challenge(&self) -> (Cx, Challenge) {
        (self.meta.context, self.challenge())
    }

    /// WebAuthn RpID should be a subdomain of the origin that is calling the create credentials request.
    /// Therefore, `authority` should be a URL-safe name, so it can be allocated in a valid URL domain.
    fn authority(&self) -> AuthorityId {
        self.meta.authority_id
    }

    fn device_id(&self) -> &DeviceId {
        &self.meta.device_id
    }
}
