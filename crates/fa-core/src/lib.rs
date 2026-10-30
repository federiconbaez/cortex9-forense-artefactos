//! Núcleo del workspace forense-artefactos.
//!
//! Define traits genéricos (`Model`, `State`, `Action`, `Property`, `Mutant`)
//! y utilidades criptográficas/RNG deterministas usadas por los modelos.
//!
//! **Alcance:** solo modelos formales. Sin recetas operativas ni exploits.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod prereg;
pub mod rng;
pub mod traits;

pub use error::{Error, Result};
pub use traits::{
    Action, CheckOutcome, Counterexample, Model, Mutant, Property, State, Transition,
};
