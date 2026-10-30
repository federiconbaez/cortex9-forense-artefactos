//! Modelos formales de artefactos de forense móvil.
//!
//! Cada módulo implementa un mecanismo (PIN, RPMB, Gatekeeper, …) a nivel
//! de protocolo / máquina de estados. Sin recetas operativas.
#![forbid(unsafe_code)]

pub mod apple_dp;
pub mod avb_rollback;
pub mod fbe_keys;
pub mod gatekeeper;
pub mod gatekeeper_model;
pub mod inactivity;
pub mod legacy_bfs;
pub mod lock_capabilities;
pub mod mutants;
pub mod pin_counter;
pub mod pin_model;
pub mod powercut;
pub mod rpmb;
pub mod rpmb_model;
pub mod weaver;

pub use mutants::{run_all_mutants, MutantReport, MutantResult};

pub use legacy_bfs::{bfs_gatekeeper, bfs_pin_counter, bfs_rpmb, BfsReport};
