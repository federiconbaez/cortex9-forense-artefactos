//! Weaver / StrongBox: slots con throttle por slot (modelo de protocolo).
//!
//! Weaver (Android StrongBox / Titan M) almacena secretos en slots con
//! contador de intentos por slot. Modelo: N slots, cada uno con fails y
//! throttle independientes; wipe de slot tras max_fails. Sin ataques a
//! hardware real.

use crate::crypto::{ct_eq, hmac_sha256};
use crate::rng::Rng;

#[derive(Clone, Debug)]
pub struct Slot {
    pub handle: [u8; 32],
    pub fails: u32,
    pub unlock_at_ms: u64,
    wiped: bool,
}

#[derive(Clone, Debug)]
pub struct Weaver {
    hw_key: [u8; 32],
    pub max_fails: u32,
    pub base_throttle_ms: u64,
    pub now_ms: u64,
    slots: Vec<Option<Slot>>,
    secrets: Vec<Option<Vec<u8>>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WeaverOutcome {
    Accepted,
    Rejected { remaining: u32, throttle_ms: u64 },
    Throttled,
    Wiped,
    EmptySlot,
}

impl Weaver {
    pub fn new(hw_key: [u8; 32], n_slots: usize, max_fails: u32, base_throttle_ms: u64) -> Self {
        Weaver {
            hw_key,
            max_fails,
            base_throttle_ms,
            now_ms: 0,
            slots: vec![None; n_slots],
            secrets: vec![None; n_slots],
        }
    }

    pub fn advance(&mut self, dt: u64) {
        self.now_ms = self.now_ms.saturating_add(dt);
    }

    pub fn enroll(&mut self, slot: usize, secret: &[u8]) -> Result<[u8; 32], &'static str> {
        if slot >= self.slots.len() {
            return Err("slot oob");
        }
        let handle = hmac_sha256(&self.hw_key, secret);
        self.secrets[slot] = Some(secret.to_vec());
        self.slots[slot] = Some(Slot {
            handle,
            fails: 0,
            unlock_at_ms: 0,
            wiped: false,
        });
        Ok(handle)
    }

    pub fn verify(&mut self, slot: usize, secret: &[u8]) -> WeaverOutcome {
        let some_slot = match self.slots.get_mut(slot) {
            Some(s) => s,
            None => return WeaverOutcome::EmptySlot,
        };
        let slot_ref = match some_slot.as_mut() {
            Some(s) => s,
            None => return WeaverOutcome::EmptySlot,
        };
        if slot_ref.wiped {
            return WeaverOutcome::Wiped;
        }
        if self.now_ms < slot_ref.unlock_at_ms {
            return WeaverOutcome::Throttled;
        }
        let expected = hmac_sha256(&self.hw_key, secret);
        if ct_eq(&expected, &slot_ref.handle) {
            slot_ref.fails = 0;
            slot_ref.unlock_at_ms = self.now_ms;
            return WeaverOutcome::Accepted;
        }
        slot_ref.fails = slot_ref.fails.saturating_add(1);
        if slot_ref.fails >= self.max_fails {
            slot_ref.wiped = true;
            return WeaverOutcome::Wiped;
        }
        let th = self
            .base_throttle_ms
            .saturating_mul(1u64 << (slot_ref.fails - 1).min(16));
        slot_ref.unlock_at_ms = self.now_ms.saturating_add(th);
        WeaverOutcome::Rejected {
            remaining: self.max_fails - slot_ref.fails,
            throttle_ms: th,
        }
    }

    pub fn slot_fails(&self, slot: usize) -> Option<u32> {
        self.slots
            .get(slot)
            .and_then(|s| s.as_ref().map(|x| x.fails))
    }

    pub fn slot_unlock_at(&self, slot: usize) -> Option<u64> {
        self.slots
            .get(slot)
            .and_then(|s| s.as_ref().map(|x| x.unlock_at_ms))
    }

    pub fn slot_wiped(&self, slot: usize) -> bool {
        self.slots
            .get(slot)
            .and_then(|s| s.as_ref().map(|x| x.wiped))
            .unwrap_or(true)
    }
}

#[derive(Clone, Debug, Default)]
pub struct WeaverReport {
    pub trials: u64,
    pub independent_slots_ok: u64,
    pub throttle_per_slot_ok: u64,
    pub wipe_per_slot_ok: u64,
    pub enroll_verify_ok: u64,
}

impl WeaverReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.independent_slots_ok == self.trials
            && self.throttle_per_slot_ok == self.trials
            && self.wipe_per_slot_ok == self.trials
            && self.enroll_verify_ok == self.trials
    }
}

pub fn measure_weaver(seed: u64, trials: u64) -> WeaverReport {
    let mut rng = Rng::new(seed);
    let mut rep = WeaverReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        let mut key = [0u8; 32];
        key.copy_from_slice(&rng.bytes(32));
        let mut w = Weaver::new(key, 4, 3, 5);
        let s0 = rng.bytes(8);
        let s1 = rng.bytes(8);
        let mut indep = true;
        let mut th_ok = true;
        let mut wipe_ok = true;
        let mut ev_ok = true;

        let h0 = w.enroll(0, &s0).unwrap();
        let h1 = w.enroll(1, &s1).unwrap();
        let _ = (h0, h1);

        if !matches!(w.verify(0, &s0), WeaverOutcome::Accepted) {
            ev_ok = false;
        }
        // Fallo en slot 1 no afecta slot 0.
        let mut bad = rng.bytes(8);
        if bad == s1 {
            bad[0] ^= 1;
        }
        match w.verify(1, &bad) {
            WeaverOutcome::Rejected { throttle_ms, .. } => {
                if throttle_ms == 0 {
                    th_ok = false;
                }
            }
            _ => th_ok = false,
        }
        if w.slot_fails(0) != Some(0) || w.slot_fails(1) != Some(1) {
            indep = false;
        }
        // Saturar slot 1 → wipe; slot 0 intacto.
        let mut guard = 0;
        while !w.slot_wiped(1) && guard < 20 {
            if let Some(ua) = w.slot_unlock_at(1) {
                if w.now_ms < ua {
                    w.advance(ua - w.now_ms);
                }
            }
            let _ = w.verify(1, &bad);
            guard += 1;
        }
        if !matches!(w.verify(1, &s1), WeaverOutcome::Wiped) {
            wipe_ok = false;
        }
        if !matches!(w.verify(0, &s0), WeaverOutcome::Accepted) {
            indep = false;
        }

        if indep {
            rep.independent_slots_ok += 1;
        }
        if th_ok {
            rep.throttle_per_slot_ok += 1;
        }
        if wipe_ok {
            rep.wipe_per_slot_ok += 1;
        }
        if ev_ok {
            rep.enroll_verify_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slots_independientes() {
        let mut w = Weaver::new([1u8; 32], 2, 3, 1);
        w.enroll(0, b"a").unwrap();
        w.enroll(1, b"b").unwrap();
        assert!(matches!(w.verify(1, b"x"), WeaverOutcome::Rejected { .. }));
        assert!(matches!(w.verify(0, b"a"), WeaverOutcome::Accepted));
    }
    #[test]
    fn measure_ci_scale() {
        let r = measure_weaver(0x0C09_0EA7, 200);
        assert!(r.all_pass(), "{:?}", r);
    }
}
