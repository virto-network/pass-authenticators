//! PLACEHOLDER weights for `pass_authenticators_substrate_keys`.
//!
//! These numbers DO NOT come from a benchmark run on reference hardware. They are conservative
//! estimates (rough native timings of the same code on a development machine, scaled up
//! several times over for Wasm execution and slower hardware), pending a run of this crate's
//! benchmarks (see `src/benchmarking.rs`) on reference hardware, which regenerates this file with
//! `.maintain/frame-weight-template.hbs`. See the repository's README for the command.
//!
//! Verification touches no storage, so the proof size of every function is zero.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use core::marker::PhantomData;

/// Weight functions needed for `pass_authenticators_substrate_keys`.
pub trait WeightInfo {
	fn verify_attestation_sr25519() -> Weight;
	fn verify_attestation_ed25519() -> Weight;
	fn verify_attestation_ecdsa() -> Weight;
	fn verify_attestation_eth() -> Weight;
	fn verify_credential_sr25519() -> Weight;
	fn verify_credential_ed25519() -> Weight;
	fn verify_credential_ecdsa() -> Weight;
	fn verify_credential_eth() -> Weight;
}

// PLACEHOLDER: not produced by a benchmark run.
impl WeightInfo for () {
	/// PLACEHOLDER: conservative estimate, not measured.
	fn verify_attestation_sr25519() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	fn verify_attestation_ed25519() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	fn verify_attestation_ecdsa() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	fn verify_attestation_eth() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	fn verify_credential_sr25519() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	fn verify_credential_ed25519() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	fn verify_credential_ecdsa() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	fn verify_credential_eth() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
}
