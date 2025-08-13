extern crate alloc;

use byteorder::{BigEndian, ByteOrder};
use core::convert::TryFrom;
use coset::{CborSerializable, CoseKey};

// Base Structures under Authenticator Data
#[derive(Debug)]
pub struct AuthenticatorData<'a> {
    pub rp_id_hash: [u8; 32],
    #[allow(dead_code)]
    pub flags: AuthenticatorFlags,
    #[allow(dead_code)]
    pub sign_count: u32,
    #[allow(dead_code)]
    pub attested_credential_data: Option<AttestedCredentialData<'a>>,
    #[allow(dead_code)]
    pub extensions: Option<coset::cbor::Value>,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct AuthenticatorFlags: u8 {
        const USER_PRESENT       = 0b0000_0001;
        const USER_VERIFIED      = 0b0000_0100;
        const BACKUP_ELEGIBILITY = 0b0000_1000;
        const BACKUP_STATE       = 0b0001_0000;
        const AT                 = 0b0100_0000;
        const ED                 = 0b1000_0000;
    }
}

#[derive(Debug)]
pub struct AttestedCredentialData<'a> {
    #[allow(dead_code)]
    pub aaguid: [u8; 16],
    #[allow(dead_code)]
    pub credential_id: &'a [u8],
    #[allow(dead_code)]
    pub credential_public_key: CoseKey,
}

// Error Handling

#[derive(Debug)]
pub enum ParseError {
    Truncated,
    Cose(coset::CoseError),
}

#[cfg(feature = "std")]
impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ParseError::Truncated => f.write_str("byte slice too short"),
            ParseError::Cose(e) => write!(f, "CBOR error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

impl<'a> TryFrom<&'a [u8]> for AuthenticatorData<'a> {
    type Error = ParseError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        // Required fields (37 bytes).
        if bytes.len() < 37 {
            return Err(ParseError::Truncated);
        }

        let mut offset = 0;
        let mut take = |n: usize| -> Result<&[u8], ParseError> {
            bytes
                .get(offset..offset + n)
                .ok_or(ParseError::Truncated)
                .inspect(|_| offset += n)
        };

        // Get `rpIdHash`
        let rp_id_hash = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(take(32)?);
            arr
        };

        // Get authenticator flags
        let flags = AuthenticatorFlags::from_bits_truncate(take(1)?[0]);

        // Get sign count
        let sign_count = BigEndian::read_u32(take(4)?);

        // Parse optional attestedCredentialData, if present.
        let attested_credential_data = if flags.contains(AuthenticatorFlags::AT) {
            let aaguid = {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(take(16)?);
                arr
            };

            let cred_id_len = BigEndian::read_u16(take(2)?) as usize;
            let credential_id = take(cred_id_len)?;

            // credentialPublicKey is CBOR – we don't know its length a-priori.
            // Feed the *remaining* slice to serde_cbor...
            let credential_public_key: CoseKey =
                CoseKey::from_slice(&bytes[offset..]).map_err(ParseError::Cose)?;

            // ...then ask how many bytes were read.
            let len = credential_public_key
                .clone()
                .to_vec()
                .map_err(ParseError::Cose)?
                .len();
            offset += len;

            Some(AttestedCredentialData {
                aaguid,
                credential_id,
                credential_public_key,
            })
        } else {
            None
        };

        let extensions = if flags.contains(AuthenticatorFlags::ED) {
            Some(coset::cbor::Value::from_slice(&bytes[offset..]).map_err(ParseError::Cose)?)
        } else {
            None
        };

        Ok(AuthenticatorData {
            rp_id_hash,
            flags,
            sign_count,
            attested_credential_data,
            extensions,
        })
    }
}
