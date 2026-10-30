//! Semillas y escalas preregistradas (v0.2).
//!
//! Ver `docs/PREREGISTRO_v0.2.md`. Los literales son hex legales en Rust.

/// Semilla PIN.
pub const PIN_SEED: u64 = 0x0C09_F02E;
/// Semilla RPMB.
pub const RPMB_SEED: u64 = 0x0C09_F0B1;
/// Semilla Gatekeeper.
pub const GK_SEED: u64 = 0x0C09_6A7E;
/// Semilla Weaver.
pub const WEAVER_SEED: u64 = 0x0C09_0EA7;
/// Semilla FBE.
pub const FBE_SEED: u64 = 0x0C09_FBE1;
/// Semilla Apple DP.
pub const ADP_SEED: u64 = 0x0C09_AD01;
/// Semilla inactivity.
pub const IDLE_SEED: u64 = 0x0C09_1D1E;
/// Semilla AVB.
pub const AVB_SEED: u64 = 0x0C09_0AB1;
/// Semilla powercut.
pub const PWR_SEED: u64 = 0x0C09_0911;
/// Semilla PATE.
pub const PATE_SEED: u64 = 0x0C09_0A7E;
/// Semilla mutantes.
pub const MUT_SEED: u64 = 0x0C09_0071;
/// Semilla benches.
pub const BENCH_SEED: u64 = 0x0C09_BE0C;

/// Trials modo CI.
pub const CI_TRIALS: u64 = 10_000;
/// Trials modo full.
pub const FULL_TRIALS: u64 = 10_000_000;
