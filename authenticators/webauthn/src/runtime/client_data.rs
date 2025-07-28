use super::*;

use alloc::string::String;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use frame::prelude::*;

// A struct representing the raw JSON structure.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawClientData {
    r#type: String,
    challenge: String,
    #[allow(dead_code)]
    pub origin: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub cross_origin: bool,
}

impl TryFrom<Vec<u8>> for RawClientData {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let json_str = String::from_utf8(value).map_err(|_| ())?;
        serde_json::from_str(&json_str).map_err(|_| ())
    }
}

impl RawClientData {
    pub fn challenge(&self) -> Option<Challenge> {
        let encoded_challenge =
            base64::decode_engine(self.challenge.as_bytes(), &BASE64_URL_SAFE_NO_PAD).ok()?;
        Decode::decode(&mut encoded_challenge.as_ref()).ok()
    }

    pub fn request_type(&self) -> String {
        self.r#type.clone()
    }
}
