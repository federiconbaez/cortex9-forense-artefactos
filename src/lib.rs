//! cortex9-forense-artefactos
//!
//! Modelos formales verificables de artefactos de forense móvil.
//! Nivel modelo / amenaza / propiedad. Sin recetas operativas.

pub mod apple_dp;
pub mod avb_rollback;
pub mod crypto;
pub mod fbe_keys;
pub mod gatekeeper;
pub mod inactivity;
pub mod lock_capabilities;
pub mod model_check;
pub mod mutants;
pub mod pate;
pub mod pin_counter;
pub mod powercut;
pub mod rng;
pub mod rpmb;
pub mod weaver;

/// Semillas y escalas preregistradas (`docs/PREREGISTRO.md` v2).
/// Los mnemónicos del preregistro se mapean a literales hex válidos.
pub mod prereg {
    pub const PIN_SEED: u64 = 0x0C09_F02E;
    pub const RPMB_SEED: u64 = 0x0C09_F0B1;
    pub const GK_SEED: u64 = 0x0C09_6A7E;
    /// mnemónico WEA7 → 0x0C090EA7
    pub const WEAVER_SEED: u64 = 0x0C09_0EA7;
    pub const FBE_SEED: u64 = 0x0C09_FBE1;
    /// mnemónico ADP1 → 0x0C09AD01
    pub const ADP_SEED: u64 = 0x0C09_AD01;
    /// mnemónico IDLE → 0x0C091D1E
    pub const IDLE_SEED: u64 = 0x0C09_1D1E;
    /// mnemónico AVB1 → 0x0C090AB1
    pub const AVB_SEED: u64 = 0x0C09_0AB1;
    /// mnemónico PWR1 → 0x0C090911
    pub const PWR_SEED: u64 = 0x0C09_0911;
    /// mnemónico PATE → 0x0C090A7E
    pub const PATE_SEED: u64 = 0x0C09_0A7E;
    /// mnemónico MUT1 → 0x0C090071
    pub const MUT_SEED: u64 = 0x0C09_0071;

    pub const CI_TRIALS: u64 = 10_000;
    pub const FULL_TRIALS: u64 = 10_000_000;
}
