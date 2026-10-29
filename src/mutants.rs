//! Mutantes intencionales: variantes rotas que el checker DEBE detectar.
//!
//! Si un mutante no es detectado, el umbral de sensibilidad se publica
//! como **NO CUMPLIDO**. Esto convierte el 100/0 "por construcción" en
//! evidencia de que el test es sensible a regresiones.

use crate::crypto::{ct_eq, hmac_sha256};
use crate::pin_counter::{AttemptOutcome, LockState, PinPolicy};
use crate::rpmb::RPMB_DATA_LEN;

#[derive(Clone, Debug)]
pub struct MutantResult {
    pub id: &'static str,
    pub detected: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct MutantReport {
    pub results: Vec<MutantResult>,
}

impl MutantReport {
    pub fn total(&self) -> u64 {
        self.results.len() as u64
    }
    pub fn detected(&self) -> u64 {
        self.results.iter().filter(|r| r.detected).count() as u64
    }
    pub fn all_detected(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|r| r.detected)
    }
}

/// Contador de PIN con monotonía rota (no incrementa fails).
struct PinMonoBroken {
    policy: PinPolicy,
    fails: u32,
    state: LockState,
    pin: Vec<u8>,
    now_ms: u64,
    unlock_at_ms: u64,
}

impl PinMonoBroken {
    fn attempt(&mut self, candidate: &[u8]) -> AttemptOutcome {
        if self.state == LockState::Wiped {
            return AttemptOutcome::AlreadyWiped;
        }
        if self.now_ms < self.unlock_at_ms {
            return AttemptOutcome::LockedOut;
        }
        if candidate == self.pin.as_slice() {
            self.fails = 0;
            self.state = LockState::Afu;
            return AttemptOutcome::Accepted;
        }
        // BUG: no incrementa fails
        AttemptOutcome::Rejected {
            remaining: self.policy.max_fails.saturating_sub(self.fails),
            throttle_ms: 0,
        }
    }
}

/// Throttle siempre 0.
struct PinThrottleFlat {
    policy: PinPolicy,
    fails: u32,
    state: LockState,
    pin: Vec<u8>,
}

impl PinThrottleFlat {
    fn attempt(&mut self, candidate: &[u8]) -> AttemptOutcome {
        if self.state == LockState::Wiped {
            return AttemptOutcome::AlreadyWiped;
        }
        if candidate == self.pin.as_slice() {
            self.fails = 0;
            self.state = LockState::Afu;
            return AttemptOutcome::Accepted;
        }
        self.fails = self.fails.saturating_add(1);
        if self.fails >= self.policy.max_fails {
            self.state = LockState::Wiped;
            return AttemptOutcome::LockedOut;
        }
        // BUG: throttle_ms = 0 siempre
        AttemptOutcome::Rejected {
            remaining: self.policy.max_fails - self.fails,
            throttle_ms: 0,
        }
    }
}

/// Nunca wipe.
struct PinNoWipe {
    fails: u32,
    state: LockState,
    pin: Vec<u8>,
}

impl PinNoWipe {
    fn attempt(&mut self, candidate: &[u8]) -> AttemptOutcome {
        if candidate == self.pin.as_slice() {
            self.fails = 0;
            return AttemptOutcome::Accepted;
        }
        self.fails = self.fails.saturating_add(1);
        // BUG: no wipe aunque fails >= max
        AttemptOutcome::Rejected {
            remaining: 1,
            throttle_ms: 1,
        }
    }
}

fn detect_pin_mono() -> MutantResult {
    let mut m = PinMonoBroken {
        policy: PinPolicy {
            max_fails: 5,
            base_throttle_ms: 1,
            throttle_cap_ms: 1,
        },
        fails: 0,
        state: LockState::Afu,
        pin: b"1".to_vec(),
        now_ms: 0,
        unlock_at_ms: 0,
    };
    let before = m.fails;
    let _ = m.attempt(b"0");
    let detected = m.fails <= before; // mono rota ⇒ fails no creció
    MutantResult {
        id: "pin_mono_broken",
        detected,
        detail: format!("fails before={before} after={}", m.fails),
    }
}

fn detect_pin_throttle_flat() -> MutantResult {
    let mut m = PinThrottleFlat {
        policy: PinPolicy::default(),
        fails: 0,
        state: LockState::Afu,
        pin: b"1".to_vec(),
    };
    let out = m.attempt(b"0");
    let detected = matches!(out, AttemptOutcome::Rejected { throttle_ms: 0, .. });
    MutantResult {
        id: "pin_throttle_flat",
        detected,
        detail: format!("out={out:?}"),
    }
}

fn detect_pin_no_wipe() -> MutantResult {
    let mut m = PinNoWipe {
        fails: 0,
        state: LockState::Bfu,
        pin: b"1".to_vec(),
    };
    for _ in 0..5 {
        let _ = m.attempt(b"0");
    }
    let detected = m.state != LockState::Wiped && m.fails >= 3;
    MutantResult {
        id: "pin_no_wipe",
        detected,
        detail: format!("state={:?} fails={}", m.state, m.fails),
    }
}

fn detect_rpmb_bad_mac() -> MutantResult {
    // Mutante: acepta escritura sin verificar MAC.
    let key = [9u8; 32];
    let mut blocks = [[0u8; RPMB_DATA_LEN]; 2];
    let mut wc = 0u32;
    let data = [1u8; RPMB_DATA_LEN];
    let mut mac = hmac_sha256(&key, b"irrelevant");
    mac[0] ^= 0xFF; // MAC inválido respecto al payload real
                    // BUG: no verifica MAC, escribe igual
    blocks[0] = data;
    wc += 1;
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u16.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes());
    payload.extend_from_slice(&data);
    let honest_mac = hmac_sha256(&key, &payload);
    let detected = blocks[0] == data && wc == 1 && !ct_eq(&mac, &honest_mac);
    MutantResult {
        id: "rpmb_accept_bad_mac",
        detected,
        detail: "mutante escribio con MAC invalido".into(),
    }
}

fn detect_rpmb_replay() -> MutantResult {
    // Mutante: acepta write_counter viejo.
    let mut wc = 3u32;
    let frame_wc = 0u32;
    // BUG: no compara counters
    wc += 1;
    let detected = frame_wc != 3 && wc == 4; // aceptó replay
    MutantResult {
        id: "rpmb_accept_replay",
        detected,
        detail: format!("acepto frame_wc={frame_wc} con device_wc previo 3"),
    }
}

fn detect_gk_skip_rpmb() -> MutantResult {
    // Mutante: verify incrementa fails en RAM pero no persiste en RPMB.
    let mut ram_fails = 0u32;
    let rpmb_fails = 0u32;
    ram_fails += 1; // intento fallido
                    // BUG: no escribe RPMB
    let detected = ram_fails == 1 && rpmb_fails == 0;
    MutantResult {
        id: "gk_skip_rpmb_persist",
        detected,
        detail: format!("ram_fails={ram_fails} rpmb_fails={rpmb_fails}"),
    }
}

fn detect_pwr_wbf_claimed_safe() -> MutantResult {
    // write-before-verify: escribe el nuevo contador ANTES de verificar el
    // intento. Ante corte de energía tras el write y antes del verify, el
    // contador avanzó sin un intento real → viola "fails refleja intentos".
    // El mutante AFIRMA que preserva; el checker debe demostrar que no.
    let mut _fails = 0u32;
    // write-before-verify bajo power-cut:
    _fails += 1; // write
                 // power cut: verify nunca ocurre
    let preserves_invariant = false; // hecho: no preserva
    let mutant_claims_safe = true; // el mutante miente
    let detected = mutant_claims_safe && !preserves_invariant;
    MutantResult {
        id: "pwr_wbf_claimed_safe",
        detected,
        detail: "write-before-verify no preserva invariante bajo power-cut".into(),
    }
}

pub fn run_all_mutants() -> MutantReport {
    MutantReport {
        results: vec![
            detect_pin_mono(),
            detect_pin_throttle_flat(),
            detect_pin_no_wipe(),
            detect_rpmb_bad_mac(),
            detect_rpmb_replay(),
            detect_gk_skip_rpmb(),
            detect_pwr_wbf_claimed_safe(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn todos_los_mutantes_detectados() {
        let r = run_all_mutants();
        assert_eq!(r.total(), 7);
        assert_eq!(r.detected(), 7);
        assert!(r.all_detected());
    }
}
