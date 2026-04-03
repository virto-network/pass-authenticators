#![cfg(test)]

//! Integration tests for pass-authenticators with a composite multi-authenticator runtime.
//!
//! Tests cross-authenticator security boundaries, DeviceId isolation, session key
//! permission escalation, and challenge replay scenarios.

mod mock;
mod tests;
