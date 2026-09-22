//! PLACEHOLDER weights for `pass_substrate_keys`.
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

/// Weights for `pass_substrate_keys`, measured by its benchmarks.
///
/// Bind them as the authenticator's `fc_traits_authn::AuthenticatorWeightInfo` (the crate maps
/// `verify_device` and `verify_user` onto these benchmarks), e.g.
/// `Authenticator<Challenger, Authority, WeightInfo<Runtime>>`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo<T> {
	/// PLACEHOLDER: conservative estimate, not measured.
	pub fn verify_attestation_sr25519() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	pub fn verify_attestation_ed25519() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	pub fn verify_attestation_ecdsa() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	pub fn verify_attestation_eth() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	pub fn verify_credential_sr25519() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	pub fn verify_credential_ed25519() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	pub fn verify_credential_ecdsa() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
	/// PLACEHOLDER: conservative estimate, not measured.
	pub fn verify_credential_eth() -> Weight {
		Weight::from_parts(150_000_000, 0)
	}
}
