//! Clases de Data Protection de Apple (nivel documentación pública).
//!
//! Catálogo de clases NSFileProtection* / Data Protection class A–D según
//! Apple Platform Security (público). No hay ataques al Secure Enclave.

use crate::pin_counter::LockState;
use fa_core::rng::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DpClass {
    /// Complete Protection (Class A).
    Complete,
    /// Protected Unless Open (Class B).
    UnlessOpen,
    /// Complete Until First Auth (Class C).
    UntilFirstAuth,
    /// No Protection (Class D).
    NoProtection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Yes,
    No,
}

pub fn accessible(class: DpClass, state: LockState) -> Access {
    match state {
        LockState::Wiped => Access::No,
        LockState::Bfu => match class {
            DpClass::NoProtection => Access::Yes,
            _ => Access::No,
        },
        LockState::Afu => Access::Yes,
    }
}

/// Tras relock (idle): Class A inaccesible; Class B si el archivo sigue open.
pub fn accessible_after_relock(class: DpClass, file_held_open: bool) -> Access {
    match class {
        DpClass::Complete => Access::No,
        DpClass::UnlessOpen => {
            if file_held_open {
                Access::Yes
            } else {
                Access::No
            }
        }
        DpClass::UntilFirstAuth => Access::Yes,
        DpClass::NoProtection => Access::Yes,
    }
}

#[derive(Clone, Debug, Default)]
pub struct AdpReport {
    pub trials: u64,
    pub bfu_only_d_ok: u64,
    pub afu_all_ok: u64,
    pub relock_class_a_denied_ok: u64,
}

impl AdpReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.bfu_only_d_ok == self.trials
            && self.afu_all_ok == self.trials
            && self.relock_class_a_denied_ok == self.trials
    }
}

pub fn measure_apple_dp(seed: u64, trials: u64) -> AdpReport {
    let mut rng = Rng::new(seed);
    let mut rep = AdpReport::default();
    let classes = [
        DpClass::Complete,
        DpClass::UnlessOpen,
        DpClass::UntilFirstAuth,
        DpClass::NoProtection,
    ];
    for _ in 0..trials {
        rep.trials += 1;
        let _ = rng.next_u64();
        let mut bfu_ok = true;
        let mut afu_ok = true;
        let mut relock_ok = true;
        for &c in &classes {
            let a_bfu = accessible(c, LockState::Bfu);
            match c {
                DpClass::NoProtection => {
                    if a_bfu != Access::Yes {
                        bfu_ok = false;
                    }
                }
                _ => {
                    if a_bfu != Access::No {
                        bfu_ok = false;
                    }
                }
            }
            if accessible(c, LockState::Afu) != Access::Yes {
                afu_ok = false;
            }
        }
        if accessible_after_relock(DpClass::Complete, false) != Access::No {
            relock_ok = false;
        }
        if accessible_after_relock(DpClass::UnlessOpen, true) != Access::Yes {
            relock_ok = false;
        }
        if accessible_after_relock(DpClass::UntilFirstAuth, false) != Access::Yes {
            relock_ok = false;
        }
        if bfu_ok {
            rep.bfu_only_d_ok += 1;
        }
        if afu_ok {
            rep.afu_all_ok += 1;
        }
        if relock_ok {
            rep.relock_class_a_denied_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn class_d_en_bfu() {
        assert_eq!(
            accessible(DpClass::NoProtection, LockState::Bfu),
            Access::Yes
        );
        assert_eq!(accessible(DpClass::Complete, LockState::Bfu), Access::No);
    }
    #[test]
    fn measure_ci() {
        assert!(measure_apple_dp(0x0C09_AD01, 200).all_pass());
    }
}
