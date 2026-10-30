//! AVB rollback index (modelo): índices monotónicos anti-downgrade.
//!
//! Android Verified Boot almacena rollback indexes en almacenamiento
//! tamper-evident. Una imagen con index < stored se rechaza. Modelo de
//! propiedad; sin flashear dispositivos.

use fa_core::rng::Rng;

#[derive(Clone, Debug)]
pub struct AvbStore {
    /// Índices por ubicación (slot).
    indexes: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AvbDecision {
    Accept,
    RejectRollback,
    OobLocation,
}

impl AvbStore {
    pub fn new(n: usize) -> Self {
        AvbStore {
            indexes: vec![0; n],
        }
    }

    pub fn get(&self, loc: usize) -> Option<u64> {
        self.indexes.get(loc).copied()
    }

    /// Intenta arrancar imagen con `image_index` en `loc`.
    pub fn check_and_update(&mut self, loc: usize, image_index: u64) -> AvbDecision {
        let Some(cur) = self.indexes.get_mut(loc) else {
            return AvbDecision::OobLocation;
        };
        if image_index < *cur {
            return AvbDecision::RejectRollback;
        }
        *cur = image_index; // monotónico: solo sube o igual
        AvbDecision::Accept
    }
}

#[derive(Clone, Debug, Default)]
pub struct AvbReport {
    pub trials: u64,
    pub mono_ok: u64,
    pub rollback_rejected_ok: u64,
    pub equal_accept_ok: u64,
}

impl AvbReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.mono_ok == self.trials
            && self.rollback_rejected_ok == self.trials
            && self.equal_accept_ok == self.trials
    }
}

pub fn measure_avb(seed: u64, trials: u64) -> AvbReport {
    let mut rng = Rng::new(seed);
    let mut rep = AvbReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        let mut store = AvbStore::new(4);
        let loc = rng.below(4) as usize;
        let mut mono = true;
        let mut rb = true;
        let mut eq = true;

        let v1 = 1 + rng.below(1000);
        assert_eq!(store.check_and_update(loc, v1), AvbDecision::Accept);
        let after = store.get(loc).unwrap();
        if after != v1 {
            mono = false;
        }
        // igual → accept, no baja
        assert_eq!(store.check_and_update(loc, v1), AvbDecision::Accept);
        if store.get(loc).unwrap() != v1 {
            eq = false;
        }
        // rollback
        if v1 > 0 {
            let low = rng.below(v1);
            if store.check_and_update(loc, low) != AvbDecision::RejectRollback {
                rb = false;
            }
            if store.get(loc).unwrap() != v1 {
                mono = false;
                rb = false;
            }
        }
        // bump
        let v2 = v1 + 1 + rng.below(10);
        assert_eq!(store.check_and_update(loc, v2), AvbDecision::Accept);
        if store.get(loc).unwrap() < v1 {
            mono = false;
        }

        if mono {
            rep.mono_ok += 1;
        }
        if rb {
            rep.rollback_rejected_ok += 1;
        }
        if eq {
            rep.equal_accept_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rechaza_downgrade() {
        let mut s = AvbStore::new(1);
        assert_eq!(s.check_and_update(0, 5), AvbDecision::Accept);
        assert_eq!(s.check_and_update(0, 4), AvbDecision::RejectRollback);
        assert_eq!(s.get(0), Some(5));
    }
    #[test]
    fn measure_ci() {
        assert!(measure_avb(0x0C09_0AB1, 200).all_pass());
    }
}
