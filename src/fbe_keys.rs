//! Jerarquía de claves FBE (CE/DE): derivación y evicción en lock (modelo).
//!
//! Android File-Based Encryption: DE disponible tras boot; CE se deriva tras
//! unlock y se evicta al volver a BFU (reboot o idle lock). Modelo de anillos
//! de claves, sin tocar keymaster real.

use crate::crypto::hmac_sha256;
use crate::pin_counter::LockState;
use crate::rng::Rng;

#[derive(Clone, Debug)]
pub struct KeyRing {
    pub state: LockState,
    de_key: Option<[u8; 32]>,
    ce_key: Option<[u8; 32]>,
    device_id: [u8; 16],
    master: [u8; 32],
}

impl KeyRing {
    pub fn boot(master: [u8; 32], device_id: [u8; 16]) -> Self {
        let de = hmac_sha256(&master, &{
            let mut m = b"DE".to_vec();
            m.extend_from_slice(&device_id);
            m
        });
        KeyRing {
            state: LockState::Bfu,
            de_key: Some(de),
            ce_key: None,
            device_id,
            master,
        }
    }

    pub fn unlock(&mut self, credential: &[u8]) {
        if self.state == LockState::Wiped {
            return;
        }
        let ce = hmac_sha256(&self.master, &{
            let mut m = b"CE".to_vec();
            m.extend_from_slice(&self.device_id);
            m.extend_from_slice(credential);
            m
        });
        self.ce_key = Some(ce);
        self.state = LockState::Afu;
    }

    /// Evicción CE al pasar a BFU (reboot / idle). DE permanece.
    pub fn lock_to_bfu(&mut self) {
        if self.state == LockState::Afu {
            self.ce_key = None;
            self.state = LockState::Bfu;
        }
    }

    pub fn wipe(&mut self) {
        self.de_key = None;
        self.ce_key = None;
        self.state = LockState::Wiped;
    }

    pub fn de_available(&self) -> bool {
        self.de_key.is_some()
    }
    pub fn ce_available(&self) -> bool {
        self.ce_key.is_some()
    }
}

#[derive(Clone, Debug, Default)]
pub struct FbeReport {
    pub trials: u64,
    pub de_after_boot_ok: u64,
    pub ce_only_afu_ok: u64,
    pub eviction_ok: u64,
    pub wipe_clears_ok: u64,
}

impl FbeReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.de_after_boot_ok == self.trials
            && self.ce_only_afu_ok == self.trials
            && self.eviction_ok == self.trials
            && self.wipe_clears_ok == self.trials
    }
}

pub fn measure_fbe(seed: u64, trials: u64) -> FbeReport {
    let mut rng = Rng::new(seed);
    let mut rep = FbeReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        let mut master = [0u8; 32];
        master.copy_from_slice(&rng.bytes(32));
        let mut did = [0u8; 16];
        did.copy_from_slice(&rng.bytes(16));
        let cred = rng.bytes(8);
        let mut kr = KeyRing::boot(master, did);
        let mut de_ok = kr.de_available() && !kr.ce_available() && kr.state == LockState::Bfu;
        kr.unlock(&cred);
        let ce_ok = kr.ce_available() && kr.de_available() && kr.state == LockState::Afu;
        let ce_before = kr.ce_key;
        kr.lock_to_bfu();
        let ev_ok = !kr.ce_available()
            && kr.de_available()
            && kr.state == LockState::Bfu
            && ce_before.is_some();
        kr.unlock(&cred);
        kr.wipe();
        let wipe_ok = !kr.de_available() && !kr.ce_available() && kr.state == LockState::Wiped;
        if !de_ok {
            // recompute flag usage
            de_ok = false;
        }
        if de_ok {
            rep.de_after_boot_ok += 1;
        }
        if ce_ok {
            rep.ce_only_afu_ok += 1;
        }
        if ev_ok {
            rep.eviction_ok += 1;
        }
        if wipe_ok {
            rep.wipe_clears_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eviction_quita_ce_deja_de() {
        let mut kr = KeyRing::boot([1u8; 32], [2u8; 16]);
        kr.unlock(b"pin");
        assert!(kr.ce_available());
        kr.lock_to_bfu();
        assert!(!kr.ce_available());
        assert!(kr.de_available());
    }
    #[test]
    fn measure_ci() {
        assert!(measure_fbe(0x0C09_FBE1, 200).all_pass());
    }
}
