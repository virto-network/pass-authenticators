//! PLACEHOLDER weights for `pass_authenticators_webauthn`.
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

/// Weight functions needed for `pass_authenticators_webauthn`.
pub trait WeightInfo {
	fn verify_attestation(c: u32, a: u32, ) -> Weight;
	fn verify_credential(c: u32, a: u32, ) -> Weight;
}

// PLACEHOLDER: not produced by a benchmark run.
impl WeightInfo for () {
	/// PLACEHOLDER: conservative estimate, not measured.
	/// The range of component `c` is `[138, 1024]`.
	/// The range of component `a` is `[168, 2048]`.
	fn verify_attestation(c: u32, a: u32, ) -> Weight {
		Weight::from_parts(100_000_000, 0)
			.saturating_add(Weight::from_parts(50_000, 0).saturating_mul(c.into()))
			.saturating_add(Weight::from_parts(750_000, 0).saturating_mul(a.into()))
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	/// The range of component `c` is `[138, 1024]`.
	/// The range of component `a` is `[37, 2048]`.
	fn verify_credential(c: u32, a: u32, ) -> Weight {
		Weight::from_parts(1_500_000_000, 0)
			.saturating_add(Weight::from_parts(100_000, 0).saturating_mul(c.into()))
			.saturating_add(Weight::from_parts(600_000, 0).saturating_mul(a.into()))
	}
}
