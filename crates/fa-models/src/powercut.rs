//! Contabilidad exacta del contador ante corte de energía (modelo acotado).
//!
//! Invariante: `fails == intentos_efectivos`.
//!
//! - **write-before-verify (WBV)**: persiste fails+1 y luego verifica.
//!   Power-cut entre write y verify ⇒ **sobreconteo** (viola contabilidad
//!   exacta por el lado seguro frente a subconteo/elusión).
//! - **verify-before-write (VBW)**: verifica en RAM y solo entonces escribe.
//!   Power-cut antes del write ⇒ disco intacto. Preserva el invariante
//!   **solo si** el resultado del intento interrumpido nunca se observa;
//!   si pudiera observarse antes del write, VBW sería el orden vulnerable
//!   (ese caso **no** está modelado aquí).
//!
//! Los trials Monte-Carlo repiten el mismo caso determinista (el seed solo
//! descarta un `u64`). No es un hallazgo de seguridad sobre hardware/RPMB.

use fa_core::rng::Rng;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Order {
    WriteBeforeVerify,
    VerifyBeforeWrite,
}

#[derive(Clone, Debug)]
pub struct CounterDisk {
    pub fails: u32,
}

#[derive(Clone, Debug)]
pub struct AttemptLog {
    pub effective_failures: u32,
}

/// Simula un intento fallido con posible power-cut tras el primer paso.
/// `cut_after_first`: si true, se corta la energía después del primer paso
/// del protocolo (write en WBV, verify en VBW).
pub fn run_failed_attempt(
    order: Order,
    disk: &mut CounterDisk,
    log: &mut AttemptLog,
    cut_after_first: bool,
) {
    match order {
        Order::WriteBeforeVerify => {
            // 1) write fails+1
            disk.fails = disk.fails.saturating_add(1);
            if cut_after_first {
                // verify nunca ocurre; effective_failures NO incrementa
                return;
            }
            // 2) verify (fallido) — effective
            log.effective_failures = log.effective_failures.saturating_add(1);
        }
        Order::VerifyBeforeWrite => {
            // 1) verify en RAM (fallido)
            let would_fail = true;
            if cut_after_first {
                // no se escribió disco; effective tampoco (intento no commit)
                return;
            }
            if would_fail {
                log.effective_failures = log.effective_failures.saturating_add(1);
                disk.fails = disk.fails.saturating_add(1);
            }
        }
    }
}

/// Invariante: disk.fails == log.effective_failures.
pub fn invariant_holds(disk: &CounterDisk, log: &AttemptLog) -> bool {
    disk.fails == log.effective_failures
}

#[derive(Clone, Debug, Default)]
pub struct PowercutReport {
    pub trials: u64,
    /// WBV bajo power-cut: fracción donde el invariante SE ROMPE (esperado: 100%).
    pub wbv_breaks_ok: u64,
    /// VBW bajo power-cut: fracción donde el invariante SE PRESERVA (esperado: 100%).
    pub vbw_preserves_ok: u64,
    pub wbv_no_cut_ok: u64,
    pub vbw_no_cut_ok: u64,
}

impl PowercutReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.wbv_breaks_ok == self.trials
            && self.vbw_preserves_ok == self.trials
            && self.wbv_no_cut_ok == self.trials
            && self.vbw_no_cut_ok == self.trials
    }
}

pub fn measure_powercut(seed: u64, trials: u64) -> PowercutReport {
    let mut rng = Rng::new(seed);
    let mut rep = PowercutReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        // Caso determinista idéntico en cada trial; el seed solo avanza RNG.
        let _ = rng.next_u64();

        // WBV + cut → debe romper
        let mut disk = CounterDisk { fails: 0 };
        let mut log = AttemptLog {
            effective_failures: 0,
        };
        run_failed_attempt(Order::WriteBeforeVerify, &mut disk, &mut log, true);
        if !invariant_holds(&disk, &log) {
            rep.wbv_breaks_ok += 1;
        }

        // VBW + cut → debe preservar
        let mut disk = CounterDisk { fails: 0 };
        let mut log = AttemptLog {
            effective_failures: 0,
        };
        run_failed_attempt(Order::VerifyBeforeWrite, &mut disk, &mut log, true);
        if invariant_holds(&disk, &log) {
            rep.vbw_preserves_ok += 1;
        }

        // Sin cut, ambos preservan y avanzan igual
        let mut disk = CounterDisk { fails: 0 };
        let mut log = AttemptLog {
            effective_failures: 0,
        };
        run_failed_attempt(Order::WriteBeforeVerify, &mut disk, &mut log, false);
        if invariant_holds(&disk, &log) && disk.fails == 1 {
            rep.wbv_no_cut_ok += 1;
        }

        let mut disk = CounterDisk { fails: 0 };
        let mut log = AttemptLog {
            effective_failures: 0,
        };
        run_failed_attempt(Order::VerifyBeforeWrite, &mut disk, &mut log, false);
        if invariant_holds(&disk, &log) && disk.fails == 1 {
            rep.vbw_no_cut_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wbv_cut_rompe_invariante() {
        let mut d = CounterDisk { fails: 0 };
        let mut l = AttemptLog {
            effective_failures: 0,
        };
        run_failed_attempt(Order::WriteBeforeVerify, &mut d, &mut l, true);
        assert!(!invariant_holds(&d, &l));
        assert_eq!(d.fails, 1);
        assert_eq!(l.effective_failures, 0);
    }
    #[test]
    fn vbw_cut_preserva() {
        let mut d = CounterDisk { fails: 0 };
        let mut l = AttemptLog {
            effective_failures: 0,
        };
        run_failed_attempt(Order::VerifyBeforeWrite, &mut d, &mut l, true);
        assert!(invariant_holds(&d, &l));
        assert_eq!(d.fails, 0);
    }
    #[test]
    fn measure_ci() {
        assert!(measure_powercut(0x0C09_0911, 200).all_pass());
    }
}
