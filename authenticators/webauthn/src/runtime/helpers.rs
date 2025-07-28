use super::*;

use alloc::string::String;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use frame::prelude::*;

// A struct representing the raw JSON structure.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawClientData {
    #[allow(dead_code)]
    pub r#type: String,
    pub challenge: String,
    #[allow(dead_code)]
    pub origin: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub cross_origin: bool,
}

pub fn find_challenge_from_client_data(client_data: Vec<u8>) -> Option<Challenge> {
    let json_str = String::from_utf8(client_data).ok()?;
    let client_data_json: RawClientData = serde_json::from_str(&json_str).ok()?;

    let encoded_challenge = base64::decode_engine(
        client_data_json.challenge.as_bytes(),
        &BASE64_URL_SAFE_NO_PAD,
    )
    .ok()?;
    Decode::decode(&mut encoded_challenge.as_ref()).ok()
}
