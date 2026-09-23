//! Genesis configuration presets.
//!
//! The benchmarks need no genesis state, so the `development` preset (the one
//! `frame-omni-bencher` builds the genesis state from by default) is empty.

use alloc::{vec, vec::Vec};
use serde_json::Value;
use sp_genesis_builder::PresetId;

/// The `development` preset: the default genesis state, unchanged.
pub fn development_config_genesis() -> Value {
    Value::Object(Default::default())
}

/// Returns the preset with the given `id`, if any.
pub fn get_preset(id: &PresetId) -> Option<Vec<u8>> {
    let patch = match id.as_ref() {
        sp_genesis_builder::DEV_RUNTIME_PRESET => development_config_genesis(),
        _ => return None,
    };
    Some(
        serde_json::to_string(&patch)
            .expect("serialization to json is expected to work; qed")
            .into_bytes(),
    )
}

/// The available presets.
pub fn preset_names() -> Vec<PresetId> {
    vec![PresetId::from(sp_genesis_builder::DEV_RUNTIME_PRESET)]
}
