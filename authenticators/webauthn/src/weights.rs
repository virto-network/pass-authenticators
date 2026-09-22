//! PLACEHOLDER weights for `pass_webauthn`.
//!
//! THESE NUMBERS DO NOT COME FROM A BENCHMARK RUN. They are conservative estimates (rough native
//! timings of the same code on a development machine, scaled up several times over for Wasm
//! execution and slower hardware), pending a run of this crate's benchmarks (see
//! `src/benchmarking.rs`) on the benchmark runner, which overwrites this file with
//! `.maintain/frame-weight-template.hbs`. See the repository's README for the command.
//!
//! Verification touches no storage, so the proof size of every function is zero.

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(missing_docs)]

use frame_support::{traits::Get, weights::Weight};
use core::marker::PhantomData;

/// Weights for `pass_webauthn`, measured by its benchmarks.
///
/// Bind them as the authenticator's `fc_traits_authn::AuthenticatorWeightInfo` (the crate maps
/// `verify_device` and `verify_user` onto these benchmarks), e.g.
/// `Authenticator<Challenger, Authority, WeightInfo<Runtime>>`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo<T> {
	/// PLACEHOLDER: conservative estimate, not measured.
	/// The range of component `c` is `[138, 1024]`.
	/// The range of component `a` is `[168, 2048]`.
	pub fn verify_attestation(c: u32, a: u32, ) -> Weight {
		Weight::from_parts(100_000_000, 0)
			.saturating_add(Weight::from_parts(50_000, 0).saturating_mul(c.into()))
			.saturating_add(Weight::from_parts(750_000, 0).saturating_mul(a.into()))
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	/// The range of component `c` is `[138, 1024]`.
	/// The range of component `a` is `[37, 2048]`.
	pub fn verify_credential(c: u32, a: u32, ) -> Weight {
		Weight::from_parts(1_500_000_000, 0)
			.saturating_add(Weight::from_parts(100_000, 0).saturating_mul(c.into()))
			.saturating_add(Weight::from_parts(600_000, 0).saturating_mul(a.into()))
	}
}
