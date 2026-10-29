//! Modelo de protocolo Gatekeeper / Weaver (HMAC throttle + derivación).
//!
//! Android Gatekeeper (y Weaver en StrongBox / Titan M) verifica el secreto
//! del usuario dentro del TEE y, ante fallos, aplica un throttle respaldado
//! por un contador en RPMB. Este módulo modela el **protocolo** a nivel de
//! mensajes y propiedades:
//!
//! - `Enroll(secret)` → `password_handle = HMAC(hw_key, salt || secret)`.
//! - `Verify(secret, handle)` → éxito si el HMAC coincide; si no, incrementa
//!   el contador RPMB-backed y aplica throttle (delegado a `PinCounter`).
//! - Tras wipe del contador, `Verify` queda permanentemente denegado.
//! - La clave de hardware `hw_key` **nunca** sale del modelo TEE.
//!
//! **Fuera de alcance:** eludir Gatekeeper en un dispositivo real, atacar
//! Weaver / Titan M / Secure Enclave, o derivar claves de un teléfono
//! concreto. Solo el modelo de protocolo y sus propiedades.

use crate::crypto::{ct_eq, hmac_sha256};
use crate::pin_counter::{AttemptOutcome, LockState, PinCounter, PinPolicy};
use crate::rng::Rng;
use crate::rpmb::{RpmbDevice, RPMB_DATA_LEN};

/// Handle opaco devuelto por Enroll (32 bytes = HMAC-SHA256).
pub type PasswordHandle = [u8; 32];

/// TEE Gatekeeper simulado: clave de hardware + salt + contador PIN + RPMB.
#[derive(Clone, Debug)]
pub struct Gatekeeper {
    hw_key: [u8; 32],
    salt: [u8; 16],
    enrolled: Vec<u8>,
    pin: PinCounter,
    rpmb: RpmbDevice,
    /// Dirección RPMB donde se persiste el contador de fallos (4 bytes BE).
    rpmb_addr: u16,
}

impl Gatekeeper {
    pub fn new(hw_key: [u8; 32], salt: [u8; 16], pin_secret: Vec<u8>, policy: PinPolicy) -> Self {
        // RPMB provisionado con la misma hw_key (simplificación del modelo:
        // en hardware real hay una clave RPMB distinta provisionada en fábrica).
        let rpmb = RpmbDevice::new(hw_key, 4);
        let pin = PinCounter::new(policy, pin_secret.clone(), LockState::Bfu);
        let mut gk = Gatekeeper {
            hw_key,
            salt,
            enrolled: pin_secret,
            pin,
            rpmb,
            rpmb_addr: 0,
        };
        gk.persist_fails().expect("persist inicial");
        gk
    }

    fn derive_handle(&self, secret: &[u8]) -> PasswordHandle {
        let mut msg = Vec::with_capacity(16 + secret.len());
        msg.extend_from_slice(&self.salt);
        msg.extend_from_slice(secret);
        hmac_sha256(&self.hw_key, &msg)
    }

    /// Enroll: produce el handle. No muta el contador.
    pub fn enroll(&self, secret: &[u8]) -> PasswordHandle {
        self.derive_handle(secret)
    }

    fn persist_fails(&mut self) -> Result<(), ()> {
        let mut data = [0u8; RPMB_DATA_LEN];
        data[..4].copy_from_slice(&self.pin.fails.to_be_bytes());
        let wc = self.rpmb.write_counter();
        let frame = self.rpmb.sign_write(self.rpmb_addr, wc, data);
        self.rpmb.authenticated_write(&frame).map_err(|_| ())
    }

    /// Lee el contador persistido en RPMB (para auditoría del modelo).
    pub fn rpmb_fails(&self) -> u32 {
        let rf = self.rpmb.authenticated_read(self.rpmb_addr).expect("read");
        assert!(self.rpmb.verify_read(&rf));
        u32::from_be_bytes([rf.data[0], rf.data[1], rf.data[2], rf.data[3]])
    }

    pub fn write_counter(&self) -> u32 {
        self.rpmb.write_counter()
    }

    pub fn lock_state(&self) -> LockState {
        self.pin.state
    }

    pub fn advance(&mut self, delta_ms: u64) {
        self.pin.advance(delta_ms);
    }

    /// ¿Está el contador aún dentro de la ventana de throttle?
    pub fn is_throttled(&self) -> bool {
        self.pin.now_ms < self.pin.unlock_at_ms
    }

    /// Ms restantes de throttle (0 si no hay).
    pub fn throttle_remaining_ms(&self) -> u64 {
        self.pin.unlock_at_ms.saturating_sub(self.pin.now_ms)
    }

    /// Verify: compara HMAC y, en fallo, incrementa contador + persiste en RPMB.
    pub fn verify(&mut self, secret: &[u8], handle: &PasswordHandle) -> AttemptOutcome {
        let expected = self.derive_handle(secret);
        let hmac_ok = ct_eq(&expected, handle) && secret == self.enrolled.as_slice();
        // Delegamos la máquina de estados al PinCounter: pasamos el secreto
        // enrolado en éxito, o un candidato garantizado distinto en fallo.
        let presented = if hmac_ok {
            self.enrolled.clone()
        } else {
            let mut bogus = self.enrolled.clone();
            if bogus.is_empty() {
                bogus.push(0xFF);
            } else {
                bogus[0] ^= 0xFF;
            }
            // Si por algún motivo quedó igual, forzar otro flip.
            if bogus == self.enrolled {
                bogus.push(0xAA);
            }
            bogus
        };
        let before_fails = self.pin.fails;
        let out = self.pin.attempt(&presented);
        if self.pin.fails != before_fails || matches!(out, AttemptOutcome::Accepted) {
            self.persist_fails()
                .expect("RPMB debe aceptar escritura honesta del TEE");
        }
        out
    }
}

#[derive(Clone, Debug, Default)]
pub struct GkPropertyReport {
    pub trials: u64,
    pub enroll_verify_ok: u64,
    pub wrong_rejected: u64,
    pub rpmb_tracks_fails: u64,
    pub wipe_denies: u64,
    pub throttle_respected: u64,
}

impl GkPropertyReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.enroll_verify_ok == self.trials
            && self.wrong_rejected == self.trials
            && self.rpmb_tracks_fails == self.trials
            && self.wipe_denies == self.trials
            && self.throttle_respected == self.trials
    }
}

pub fn measure_gatekeeper_properties(seed: u64, trials: u64) -> GkPropertyReport {
    let mut rng = Rng::new(seed);
    let mut rep = GkPropertyReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        let mut hw = [0u8; 32];
        hw.copy_from_slice(&rng.bytes(32));
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&rng.bytes(16));
        let secret = rng.bytes(8);
        let policy = PinPolicy {
            max_fails: 5,
            base_throttle_ms: 10,
            throttle_cap_ms: 1_000,
        };
        let mut gk = Gatekeeper::new(hw, salt, secret.clone(), policy);
        let handle = gk.enroll(&secret);

        let mut enroll_ok = true;
        let mut wrong = true;
        let mut tracks = true;
        let mut wipe = true;
        let mut throttle = true;

        // Verify correcto desde BFU → AFU.
        match gk.verify(&secret, &handle) {
            AttemptOutcome::Accepted => {
                if gk.lock_state() != LockState::Afu {
                    enroll_ok = false;
                }
            }
            _ => enroll_ok = false,
        }
        if gk.rpmb_fails() != 0 {
            tracks = false;
        }

        // Fallo: debe incrementar fails y RPMB.
        let mut bad = rng.bytes(8);
        if bad == secret {
            bad[0] ^= 0xFF;
        }
        match gk.verify(&bad, &handle) {
            AttemptOutcome::Rejected { .. } => {
                if gk.rpmb_fails() != 1 {
                    tracks = false;
                }
            }
            AttemptOutcome::LockedOut => {
                throttle = false;
            }
            _ => wrong = false,
        }

        // Intento dentro de la ventana de throttle → LockedOut, fails intacto.
        let fails_before = gk.rpmb_fails();
        assert!(gk.is_throttled(), "tras un rechazo debe haber throttle");
        match gk.verify(&bad, &handle) {
            AttemptOutcome::LockedOut => {
                if gk.rpmb_fails() != fails_before {
                    throttle = false;
                }
            }
            _ => throttle = false,
        }
        // Salir del throttle.
        let rem = gk.throttle_remaining_ms();
        gk.advance(rem);

        // Saturar hasta wipe.
        while gk.lock_state() != LockState::Wiped {
            if gk.is_throttled() {
                gk.advance(gk.throttle_remaining_ms());
            }
            let _ = gk.verify(&bad, &handle);
        }
        // Tras wipe: denegado permanente aunque el secreto sea correcto.
        match gk.verify(&secret, &handle) {
            AttemptOutcome::AlreadyWiped | AttemptOutcome::LockedOut => {}
            _ => wipe = false,
        }
        if gk.rpmb_fails() < 5 {
            tracks = false;
        }

        if enroll_ok {
            rep.enroll_verify_ok += 1;
        }
        if wrong {
            rep.wrong_rejected += 1;
        }
        if tracks {
            rep.rpmb_tracks_fails += 1;
        }
        if wipe {
            rep.wipe_denies += 1;
        }
        if throttle {
            rep.throttle_respected += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enroll_y_verify_ok() {
        let mut gk = Gatekeeper::new(
            [1u8; 32],
            [2u8; 16],
            b"secreto".to_vec(),
            PinPolicy::default(),
        );
        let h = gk.enroll(b"secreto");
        assert_eq!(gk.verify(b"secreto", &h), AttemptOutcome::Accepted);
        assert_eq!(gk.lock_state(), LockState::Afu);
    }

    #[test]
    fn secreto_incorrecto_persiste_en_rpmb() {
        let mut gk = Gatekeeper::new(
            [3u8; 32],
            [4u8; 16],
            b"ok".to_vec(),
            PinPolicy {
                max_fails: 10,
                base_throttle_ms: 5,
                throttle_cap_ms: 5,
            },
        );
        let h = gk.enroll(b"ok");
        assert!(matches!(
            gk.verify(b"no", &h),
            AttemptOutcome::Rejected { .. }
        ));
        assert_eq!(gk.rpmb_fails(), 1);
        assert_eq!(gk.write_counter(), 2); // inicial + 1 fallo
    }

    #[test]
    fn propiedades_semilla_fija_100_por_construccion() {
        // Umbral preregistrado: 100/100 en las 5 propiedades, seed=0x0C09_6A7E.
        let rep = measure_gatekeeper_properties(0x0C09_6A7E, 100);
        assert_eq!(rep.trials, 100);
        assert_eq!(rep.enroll_verify_ok, 100);
        assert_eq!(rep.wrong_rejected, 100);
        assert_eq!(rep.rpmb_tracks_fails, 100);
        assert_eq!(rep.wipe_denies, 100);
        assert_eq!(rep.throttle_respected, 100);
        assert!(rep.all_pass());
    }
}
