//! cortex9-forense-artefactos
//!
//! Modelos formales verificables de artefactos de forense móvil:
//! contador de intentos de PIN (BFU/AFU), protocolo RPMB anti-rollback,
//! Gatekeeper/Weaver HMAC-throttle y tabla de capacidades por estado de
//! bloqueo.
//!
//! Nivel modelo / amenaza / propiedad. **Sin** recetas operativas ni
//! exploits funcionales contra dispositivos concretos.

pub mod crypto;
pub mod gatekeeper;
pub mod lock_capabilities;
pub mod pin_counter;
pub mod rng;
pub mod rpmb;

/// Semillas y umbrales preregistrados (docs/PREREGISTRO.md).
pub mod prereg {
    pub const PIN_SEED: u64 = 0xC09_F02E;
    pub const PIN_TRIALS: u64 = 100;
    pub const RPMB_SEED: u64 = 0xC09_F0B1;
    pub const RPMB_TRIALS: u64 = 100;
    pub const GK_SEED: u64 = 0xC09_6A7E;
    pub const GK_TRIALS: u64 = 100;
}
