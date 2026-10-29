//! Reinicio por inactividad: AFU → BFU tras timeout T (modelo).
//!
//! Tras T ms sin unlock/actividad, las claves CE se evictan y el estado
//! vuelve a BFU sin apagar la pantalla necesariamente (idle lock).

use crate::fbe_keys::KeyRing;
use crate::pin_counter::LockState;
use crate::rng::Rng;

#[derive(Clone, Debug)]
pub struct IdlePolicy {
    pub timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct IdleGuard {
    pub policy: IdlePolicy,
    pub last_activity_ms: u64,
    pub now_ms: u64,
    pub keys: KeyRing,
}

impl IdleGuard {
    pub fn new(keys: KeyRing, timeout_ms: u64) -> Self {
        IdleGuard {
            policy: IdlePolicy { timeout_ms },
            last_activity_ms: 0,
            now_ms: 0,
            keys,
        }
    }

    pub fn advance(&mut self, dt: u64) {
        self.now_ms = self.now_ms.saturating_add(dt);
        self.poll();
    }

    pub fn touch(&mut self) {
        self.last_activity_ms = self.now_ms;
    }

    pub fn unlock(&mut self, cred: &[u8]) {
        self.keys.unlock(cred);
        self.touch();
    }

    fn poll(&mut self) {
        if self.keys.state == LockState::Afu
            && self.now_ms.saturating_sub(self.last_activity_ms) >= self.policy.timeout_ms
        {
            self.keys.lock_to_bfu();
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct IdleReport {
    pub trials: u64,
    pub timeout_triggers_ok: u64,
    pub touch_resets_ok: u64,
    pub ce_evicted_ok: u64,
}

impl IdleReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.timeout_triggers_ok == self.trials
            && self.touch_resets_ok == self.trials
            && self.ce_evicted_ok == self.trials
    }
}

pub fn measure_inactivity(seed: u64, trials: u64) -> IdleReport {
    let mut rng = Rng::new(seed);
    let mut rep = IdleReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        let mut master = [0u8; 32];
        master.copy_from_slice(&rng.bytes(32));
        let mut did = [0u8; 16];
        did.copy_from_slice(&rng.bytes(16));
        let t = 100 + rng.below(900);
        let mut g = IdleGuard::new(KeyRing::boot(master, did), t);
        let cred = rng.bytes(4);
        g.unlock(&cred);
        let mut timeout_ok = true;
        let mut touch_ok = true;
        let mut evict_ok = true;

        // Touch a mitad de camino: no debe caer.
        g.advance(t / 2);
        if g.keys.state != LockState::Afu {
            touch_ok = false;
        }
        g.touch();
        g.advance(t / 2);
        if g.keys.state != LockState::Afu {
            touch_ok = false;
        }
        // Sin touch: timeout completo → BFU, CE evicted.
        g.advance(t);
        if g.keys.state != LockState::Bfu {
            timeout_ok = false;
        }
        if g.keys.ce_available() {
            evict_ok = false;
        }
        if !g.keys.de_available() {
            evict_ok = false;
        }

        if timeout_ok {
            rep.timeout_triggers_ok += 1;
        }
        if touch_ok {
            rep.touch_resets_ok += 1;
        }
        if evict_ok {
            rep.ce_evicted_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_afu_a_bfu() {
        let mut g = IdleGuard::new(KeyRing::boot([1u8; 32], [2u8; 16]), 50);
        g.unlock(b"x");
        assert_eq!(g.keys.state, LockState::Afu);
        g.advance(50);
        assert_eq!(g.keys.state, LockState::Bfu);
        assert!(!g.keys.ce_available());
    }
    #[test]
    fn measure_ci() {
        assert!(measure_inactivity(0x0C09_1D1E, 200).all_pass());
    }
}
