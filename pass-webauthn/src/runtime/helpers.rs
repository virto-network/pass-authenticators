use super::*;

use alloc::string::String;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;

pub fn find_challenge_from_client_data(client_data: Vec<u8>) -> Option<Challenge> {
    get_from_json_then_map(client_data, "challenge", |challenge| {
        base64::decode_engine(challenge.as_bytes(), &BASE64_URL_SAFE_NO_PAD).ok()
    })
}

pub fn get_from_json_then_map<T>(
    json: Vec<u8>,
    key: &str,
    map: impl FnOnce(&str) -> Option<Vec<u8>>,
) -> Option<T>
where
    T: Decode,
{
    let json = String::from_utf8(json).ok()?;

    let value = json
        .split(",")
        .find_map(|kv| kv.contains(key).then_some(kv.split_once(":")?.1))
        .map(|v| v.trim_matches(|c: char| c.eq(&' ') || c.eq(&'"')))
        .and_then(map)?;

    Decode::decode(&mut value.as_ref()).ok()
}
