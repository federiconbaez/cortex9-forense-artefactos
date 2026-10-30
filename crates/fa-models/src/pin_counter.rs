//! Máquina de estados del contador de intentos de PIN (modelo BFU/AFU).
//!
//! Este módulo modela las propiedades del contador de intentos de código de
//! acceso que se observa en la literatura pública sobre Android Gatekeeper /
//! Weaver y sobre el Secure Enclave de iOS:
//!
//! - Contador monotónico no decreciente en cada intento fallido.
//! - Throttling exponencial (retardo ≥ 2^fails * base_ms, acotado).
//! - Wipe / lock permanente tras `max_fails` intentos fallidos.
//! - Un intento correcto reinicia el contador y el throttle.
//! - En BFU el CE permanece envuelto; en AFU las claves CE están en RAM.
//!
//! **Fuera de alcance (explícito):** eludir, congelar o reescribir el contador
//! real de un dispositivo concreto; interceptar RPMB; inyectar código en TEE/
//! Secure Enclave. Nada de esto se implementa ni se describe como procedimiento.

use fa_core::rng::Rng;

/// Estado de bloqueo del dispositivo (modelo).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockState {
    /// Before First Unlock: claves CE envueltas; DE disponible.
    Bfu,
    /// After First Unlock: claves CE en anillos de claves del kernel.
    Afu,
    /// Wipe / lock permanente tras superar max_fails.
    Wiped,
}

/// Resultado de un intento de verificación de PIN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    Accepted,
    Rejected { remaining: u32, throttle_ms: u64 },
    LockedOut,
    AlreadyWiped,
}

/// Configuración del contador (valores típicos de la literatura pública).
#[derive(Clone, Debug)]
pub struct PinPolicy {
    /// Intentos fallidos máximos antes de wipe. Típico: 10 (Android) / 10 (iOS).
    pub max_fails: u32,
    /// Retardo base en ms; el throttle efectivo es `min(cap, base * 2^fails)`.
    pub base_throttle_ms: u64,
    /// Tope de throttle en ms.
    pub throttle_cap_ms: u64,
}

impl Default for PinPolicy {
    fn default() -> Self {
        PinPolicy {
            max_fails: 10,
            base_throttle_ms: 30_000, // 30 s (orden de magnitud Gatekeeper)
            throttle_cap_ms: 86_400_000, // 24 h
        }
    }
}

/// Estado vivo del contador de PIN.
#[derive(Clone, Debug)]
pub struct PinCounter {
    pub policy: PinPolicy,
    pub fails: u32,
    pub state: LockState,
    /// Reloj monotónico simulado (ms). Avanza solo vía `advance`.
    pub now_ms: u64,
    /// Instantánea a partir de la cual se acepta un nuevo intento.
    pub unlock_at_ms: u64,
    /// PIN de referencia (solo en el simulador; nunca un secreto real).
    pin: Vec<u8>,
}

impl PinCounter {
    pub fn new(policy: PinPolicy, pin: Vec<u8>, initial: LockState) -> Self {
        assert!(
            matches!(initial, LockState::Bfu | LockState::Afu),
            "estado inicial debe ser BFU o AFU"
        );
        PinCounter {
            policy,
            fails: 0,
            state: initial,
            now_ms: 0,
            unlock_at_ms: 0,
            pin,
        }
    }

    /// Avanza el reloj simulado. No se puede retroceder.
    pub fn advance(&mut self, delta_ms: u64) {
        self.now_ms = self.now_ms.saturating_add(delta_ms);
    }

    fn throttle_for(&self, fails: u32) -> u64 {
        if fails == 0 {
            return 0;
        }
        // 2^(fails-1) * base, saturado.
        let shift = (fails - 1).min(31);
        let factor = 1u64 << shift;
        let raw = self.policy.base_throttle_ms.saturating_mul(factor);
        raw.min(self.policy.throttle_cap_ms)
    }

    /// Intento de verificación. El contador **siempre** se incrementa en fallo
    /// (propiedad monotónica) y **nunca** decrece salvo éxito o wipe.
    pub fn attempt(&mut self, candidate: &[u8]) -> AttemptOutcome {
        if self.state == LockState::Wiped {
            return AttemptOutcome::AlreadyWiped;
        }
        if self.now_ms < self.unlock_at_ms {
            // Todavía en ventana de throttle: el intento se rechaza sin
            // consumir un "nuevo" fail (el hardware real suele ignorar o
            // diferir; aquí lo modelamos como LockedOut temporal).
            return AttemptOutcome::LockedOut;
        }
        if candidate == self.pin.as_slice() {
            self.fails = 0;
            self.unlock_at_ms = self.now_ms;
            // Un unlock exitoso desde BFU pasa a AFU (modelo).
            if self.state == LockState::Bfu {
                self.state = LockState::Afu;
            }
            return AttemptOutcome::Accepted;
        }
        // Fallo: incrementar contador (propiedad monotónica).
        let prev = self.fails;
        self.fails = self.fails.saturating_add(1);
        assert!(self.fails > prev || prev == u32::MAX, "monotonía rota");
        if self.fails >= self.policy.max_fails {
            self.state = LockState::Wiped;
            return AttemptOutcome::LockedOut;
        }
        let th = self.throttle_for(self.fails);
        self.unlock_at_ms = self.now_ms.saturating_add(th);
        AttemptOutcome::Rejected {
            remaining: self.policy.max_fails - self.fails,
            throttle_ms: th,
        }
    }

    /// ¿Las claves CE están disponibles? Solo AFU (modelo).
    pub fn ce_keys_available(&self) -> bool {
        self.state == LockState::Afu
    }
}

/// Propiedades verificadas sobre un corpus generado con semilla fija.
#[derive(Clone, Debug, Default)]
pub struct PinPropertyReport {
    pub trials: u64,
    pub mono_ok: u64,
    pub throttle_ok: u64,
    pub wipe_ok: u64,
    pub success_resets_ok: u64,
    pub bfu_to_afu_ok: u64,
    pub ce_only_afu_ok: u64,
}

impl PinPropertyReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.mono_ok == self.trials
            && self.throttle_ok == self.trials
            && self.wipe_ok == self.trials
            && self.success_resets_ok == self.trials
            && self.bfu_to_afu_ok == self.trials
            && self.ce_only_afu_ok == self.trials
    }
}

/// Corre `trials` trayectorias con semilla fija y verifica propiedades.
pub fn measure_pin_properties(seed: u64, trials: u64) -> PinPropertyReport {
    let mut rng = Rng::new(seed);
    let mut rep = PinPropertyReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        let pin = rng.bytes(4); // PIN de 4 bytes (simulador)
        let initial = if rng.bool() {
            LockState::Bfu
        } else {
            LockState::Afu
        };
        let mut c = PinCounter::new(PinPolicy::default(), pin.clone(), initial);
        let mut mono = true;
        let mut throttle = true;
        let mut wipe = true;
        let mut reset = true;
        let mut bfu_afu = true;
        let mut ce_only = true;

        // Trayectoria: hasta max_fails+2 intentos con mezcla de fallos/éxito.
        let steps = (c.policy.max_fails + 2) as usize;
        let mut saw_success = false;
        for step in 0..steps {
            let before_fails = c.fails;
            let before_state = c.state;
            // Con probabilidad 1/8 intento correcto; resto fallos.
            let candidate = if rng.below(8) == 0 && !saw_success {
                pin.clone()
            } else {
                let mut bad = rng.bytes(4);
                // Garantizar distinto del PIN.
                if bad == pin {
                    bad[0] ^= 0xFF;
                }
                bad
            };
            // Avanzar el reloj lo suficiente para salir de throttle previo.
            if c.now_ms < c.unlock_at_ms {
                c.advance(c.unlock_at_ms - c.now_ms);
            }
            let out = c.attempt(&candidate);
            // Monotonía: fails nunca decrece salvo Accepted o AlreadyWiped.
            match out {
                AttemptOutcome::Accepted => {
                    if c.fails != 0 {
                        reset = false;
                    }
                    saw_success = true;
                    if before_state == LockState::Bfu && c.state != LockState::Afu {
                        bfu_afu = false;
                    }
                }
                AttemptOutcome::Rejected { throttle_ms, .. } => {
                    if c.fails <= before_fails {
                        mono = false;
                    }
                    let expected = {
                        let shift = (c.fails - 1).min(31);
                        let factor = 1u64 << shift;
                        c.policy
                            .base_throttle_ms
                            .saturating_mul(factor)
                            .min(c.policy.throttle_cap_ms)
                    };
                    if throttle_ms != expected {
                        throttle = false;
                    }
                }
                AttemptOutcome::LockedOut => {
                    if before_fails + 1 >= c.policy.max_fails
                        || before_state == LockState::Wiped
                        || c.now_ms < c.unlock_at_ms
                    {
                        // OK: wipe o todavía en throttle (este último no
                        // debería ocurrir porque avanzamos el reloj arriba).
                    } else if c.fails <= before_fails && before_state != LockState::Wiped {
                        mono = false;
                    }
                    if c.fails >= c.policy.max_fails && c.state != LockState::Wiped {
                        wipe = false;
                    }
                }
                AttemptOutcome::AlreadyWiped => {
                    if before_state != LockState::Wiped {
                        wipe = false;
                    }
                }
            }
            // CE solo en AFU.
            if c.ce_keys_available() != (c.state == LockState::Afu) {
                ce_only = false;
            }
            // Tras wipe, cualquier intento adicional queda AlreadyWiped.
            if c.state == LockState::Wiped && step + 1 < steps {
                let out2 = c.attempt(&pin);
                if out2 != AttemptOutcome::AlreadyWiped {
                    wipe = false;
                }
                break;
            }
        }
        // Forzar wipe si no se alcanzó: saturamos con fallos.
        if c.state != LockState::Wiped {
            while c.state != LockState::Wiped {
                if c.now_ms < c.unlock_at_ms {
                    c.advance(c.unlock_at_ms - c.now_ms);
                }
                let mut bad = rng.bytes(4);
                if bad == pin {
                    bad[0] ^= 0xAA;
                }
                let before = c.fails;
                let _ = c.attempt(&bad);
                if c.fails < before && c.state != LockState::Wiped {
                    mono = false;
                    break;
                }
            }
            if c.state != LockState::Wiped {
                wipe = false;
            }
        }
        if mono {
            rep.mono_ok += 1;
        }
        if throttle {
            rep.throttle_ok += 1;
        }
        if wipe {
            rep.wipe_ok += 1;
        }
        if reset {
            rep.success_resets_ok += 1;
        }
        if bfu_afu {
            rep.bfu_to_afu_ok += 1;
        }
        if ce_only {
            rep.ce_only_afu_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exito_desde_bfu_pasa_a_afu_y_habilita_ce() {
        let mut c = PinCounter::new(PinPolicy::default(), b"1234".to_vec(), LockState::Bfu);
        assert!(!c.ce_keys_available());
        assert_eq!(c.attempt(b"1234"), AttemptOutcome::Accepted);
        assert_eq!(c.state, LockState::Afu);
        assert!(c.ce_keys_available());
        assert_eq!(c.fails, 0);
    }

    #[test]
    fn fallo_incrementa_y_aplica_throttle_exponencial() {
        let mut c = PinCounter::new(PinPolicy::default(), b"1234".to_vec(), LockState::Afu);
        match c.attempt(b"0000") {
            AttemptOutcome::Rejected {
                remaining,
                throttle_ms,
            } => {
                assert_eq!(remaining, 9);
                assert_eq!(throttle_ms, 30_000); // 2^0 * 30s
            }
            o => panic!("esperado Rejected, got {:?}", o),
        }
        // Sin avanzar el reloj: LockedOut.
        assert_eq!(c.attempt(b"0000"), AttemptOutcome::LockedOut);
        c.advance(30_000);
        match c.attempt(b"0000") {
            AttemptOutcome::Rejected { throttle_ms, .. } => {
                assert_eq!(throttle_ms, 60_000); // 2^1 * 30s
            }
            o => panic!("esperado Rejected, got {:?}", o),
        }
    }

    #[test]
    fn wipe_tras_max_fails() {
        let pol = PinPolicy {
            max_fails: 3,
            base_throttle_ms: 1,
            throttle_cap_ms: 1,
        };
        let mut c = PinCounter::new(pol, b"x".to_vec(), LockState::Bfu);
        assert!(matches!(c.attempt(b"a"), AttemptOutcome::Rejected { .. }));
        c.advance(1);
        assert!(matches!(c.attempt(b"a"), AttemptOutcome::Rejected { .. }));
        c.advance(1);
        assert_eq!(c.attempt(b"a"), AttemptOutcome::LockedOut);
        assert_eq!(c.state, LockState::Wiped);
        assert_eq!(c.attempt(b"x"), AttemptOutcome::AlreadyWiped);
    }

    #[test]
    fn propiedades_semilla_fija_100_por_construccion() {
        // Umbral preregistrado: 100/100 en las 6 propiedades, seed=0x0C09_F02E.
        // Etiqueta: "por construcción" (el corpus es el propio modelo).
        let rep = measure_pin_properties(0x0C09_F02E, 100);
        assert_eq!(rep.trials, 100);
        assert_eq!(rep.mono_ok, 100);
        assert_eq!(rep.throttle_ok, 100);
        assert_eq!(rep.wipe_ok, 100);
        assert_eq!(rep.success_resets_ok, 100);
        assert_eq!(rep.bfu_to_afu_ok, 100);
        assert_eq!(rep.ce_only_afu_ok, 100);
        assert!(rep.all_pass());
    }
}
