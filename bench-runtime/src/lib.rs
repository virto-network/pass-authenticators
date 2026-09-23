//! # Pass Authenticators bench runtime
//!
//! A minimal runtime whose only purpose is to run the authenticators' benchmarks with
//! `frame-omni-bencher`, and so generate each authenticator's `src/weights.rs` on reference
//! hardware:
//!
//! ```sh
//! cargo build --release -p pass-authenticators-bench-runtime --features runtime-benchmarks
//! frame-omni-bencher v1 benchmark pallet \
//!   --runtime target/release/wbuild/pass-authenticators-bench-runtime/pass_authenticators_bench_runtime.compact.compressed.wasm \
//!   --pallet pass_webauthn --extrinsic "*" \
//!   --steps 50 --repeat 20 \
//!   --template .maintain/frame-weight-template.hbs \
//!   --output authenticators/webauthn/src/weights.rs
//! ```
//!
//! The authenticators aren't pallets: their benchmarks hang off benchmarking-only pallets that
//! only need `frame_system`, so that's the only pallet this runtime has. Recent `rustc`s need
//! `WASM_BUILD_RUSTFLAGS="-C link-arg=--allow-undefined"` to link the runtime's WASM blob, which
//! imports its host functions.
//!
//! It is not meant to run a chain: there's no consensus, no balances and no transaction payment.

#![cfg_attr(not(feature = "std"), no_std)]
// `construct_runtime!` does a lot of recursion and requires us to increase the limit.
#![recursion_limit = "256"]

// Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));

extern crate alloc;

// `#[frame_support::runtime]` expands to code that expects `Vec` in scope.
#[allow(unused_imports)]
use alloc::vec::Vec;

mod apis;
pub mod genesis_config_presets;

use frame_support::{derive_impl, parameter_types};
use sp_runtime::{
    generic,
    traits::{BlakeTwo256, IdentifyAccount, Verify},
    MultiAddress, MultiSignature,
};
use sp_version::RuntimeVersion;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = MultiSignature;
/// Some way of identifying an account on the chain.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;
/// Index of a transaction in the chain.
pub type Nonce = u32;
/// An index to a block.
pub type BlockNumber = u32;
/// The address format for describing accounts.
pub type Address = MultiAddress<AccountId, ()>;
/// Block header type as expected by this runtime.
pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
/// Block type as expected by this runtime.
pub type Block = generic::Block<Header, UncheckedExtrinsic>;

/// The transaction extensions that are added to the runtime.
pub type TxExtension = (
    frame_system::CheckNonZeroSender<Runtime>,
    frame_system::CheckSpecVersion<Runtime>,
    frame_system::CheckTxVersion<Runtime>,
    frame_system::CheckGenesis<Runtime>,
    frame_system::CheckEra<Runtime>,
    frame_system::CheckNonce<Runtime>,
    frame_system::CheckWeight<Runtime>,
);

/// Unchecked extrinsic type as expected by this runtime.
pub type UncheckedExtrinsic =
    generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, TxExtension>;

/// Executive: handles dispatch to the various modules.
pub type Executive = frame_executive::Executive<
    Runtime,
    Block,
    frame_system::ChainContext<Runtime>,
    Runtime,
    AllPalletsWithSystem,
>;

#[sp_version::runtime_version]
pub const VERSION: RuntimeVersion = RuntimeVersion {
    spec_name: alloc::borrow::Cow::Borrowed("pass-authenticators-bench"),
    impl_name: alloc::borrow::Cow::Borrowed("pass-authenticators-bench"),
    authoring_version: 1,
    spec_version: 1,
    impl_version: 1,
    apis: apis::RUNTIME_API_VERSIONS,
    transaction_version: 1,
    system_version: 1,
};

#[frame_support::runtime]
mod runtime {
    #[runtime::runtime]
    #[runtime::derive(
        RuntimeCall,
        RuntimeEvent,
        RuntimeError,
        RuntimeOrigin,
        RuntimeFreezeReason,
        RuntimeHoldReason,
        RuntimeSlashReason,
        RuntimeLockId,
        RuntimeTask,
        RuntimeViewFunction
    )]
    pub struct Runtime;

    #[runtime::pallet_index(0)]
    pub type System = frame_system;
}

parameter_types! {
    pub const Version: RuntimeVersion = VERSION;
}

#[derive_impl(frame_system::config_preludes::SolochainDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
    type Version = Version;
    type AccountId = AccountId;
    type Nonce = Nonce;
}

#[cfg(feature = "runtime-benchmarks")]
mod benches {
    frame_benchmarking::define_benchmarks!(
        [pass_webauthn, pass_webauthn::benchmarking::Pallet::<Runtime>]
        [pass_substrate_keys, pass_substrate_keys::benchmarking::Pallet::<Runtime>]
    );
}
