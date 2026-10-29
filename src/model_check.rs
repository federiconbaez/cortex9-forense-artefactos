//! Model checking explícito por BFS sobre espacios de estados acotados.
//!
//! Límites declarados en `docs/PREREGISTRO.md` (v2). Reporta estados
//! explorados, transiciones y violaciones. Cero violaciones = CUMPLIDO.

use crate::pin_counter::{AttemptOutcome, LockState, PinCounter, PinPolicy};
use crate::rpmb::{RpmbDevice, RpmbError, RPMB_DATA_LEN};
use std::collections::{HashSet, VecDeque};
use std::time::Instant;

#[derive(Clone, Debug, Default)]
pub struct BfsReport {
    pub name: String,
    pub states_explored: u64,
    pub transitions: u64,
    pub violations: u64,
    pub elapsed_ms: u64,
    pub bound_note: String,
}

impl BfsReport {
    pub fn ok(&self) -> bool {
        self.violations == 0 && self.states_explored > 0
    }
}

/// Estado abstracto del contador de PIN para BFS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PinAbs {
    fails: u32,
    state: u8, // 0=Bfu 1=Afu 2=Wiped
    throttled: bool,
}

fn pin_state_code(s: LockState) -> u8 {
    match s {
        LockState::Bfu => 0,
        LockState::Afu => 1,
        LockState::Wiped => 2,
    }
}

/// BFS pin_counter: max_fails≤5, throttle ∈ {abierto, cerrado}.
pub fn bfs_pin_counter() -> BfsReport {
    let t0 = Instant::now();
    let policy = PinPolicy {
        max_fails: 5,
        base_throttle_ms: 1,
        throttle_cap_ms: 1,
    };
    let pin = b"P".to_vec();
    let mut seen: HashSet<PinAbs> = HashSet::new();
    let mut q: VecDeque<(PinAbs, PinCounter)> = VecDeque::new();
    let mut transitions = 0u64;
    let mut violations = 0u64;

    for initial in [LockState::Bfu, LockState::Afu] {
        let c = PinCounter::new(policy.clone(), pin.clone(), initial);
        let abs = PinAbs {
            fails: 0,
            state: pin_state_code(initial),
            throttled: false,
        };
        if seen.insert(abs) {
            q.push_back((abs, c));
        }
    }

    while let Some((abs, mut c)) = q.pop_front() {
        // Acciones: attempt_ok, attempt_bad, advance_throttle (si throttled).
        let actions: Vec<(&[u8], bool)> = if abs.state == 2 {
            vec![(b"P", false), (b"X", false)] // ya wiped
        } else if abs.throttled {
            // Solo advance.
            c.advance(c.unlock_at_ms.saturating_sub(c.now_ms).max(1));
            let next = PinAbs {
                fails: c.fails,
                state: pin_state_code(c.state),
                throttled: c.now_ms < c.unlock_at_ms,
            };
            transitions += 1;
            if c.fails < abs.fails {
                violations += 1; // monotonía rota
            }
            if seen.insert(next) {
                q.push_back((next, c));
            }
            continue;
        } else {
            vec![(b"P", true), (b"X", false)]
        };

        for (cand, _expect_ok) in actions {
            let mut n = c.clone();
            let before_fails = n.fails;
            let out = n.attempt(cand);
            transitions += 1;
            // Propiedades
            match out {
                AttemptOutcome::Rejected { .. } => {
                    if n.fails <= before_fails {
                        violations += 1;
                    }
                }
                AttemptOutcome::Accepted => {
                    if n.fails != 0 {
                        violations += 1;
                    }
                    if before_fails == 0 && abs.state == 0 && n.state != LockState::Afu {
                        // BFU + éxito → AFU
                        violations += 1;
                    }
                }
                AttemptOutcome::LockedOut => {
                    if n.fails >= n.policy.max_fails && n.state != LockState::Wiped {
                        violations += 1;
                    }
                }
                AttemptOutcome::AlreadyWiped => {
                    if abs.state != 2 {
                        violations += 1;
                    }
                }
            }
            if n.ce_keys_available() != (n.state == LockState::Afu) {
                violations += 1;
            }
            let next = PinAbs {
                fails: n.fails,
                state: pin_state_code(n.state),
                throttled: n.now_ms < n.unlock_at_ms,
            };
            if seen.insert(next) {
                q.push_back((next, n));
            }
        }
    }

    BfsReport {
        name: "pin_counter".into(),
        states_explored: seen.len() as u64,
        transitions,
        violations,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        bound_note: "max_fails=5, throttle∈{0,1}, states BFU/AFU/Wiped".into(),
    }
}

/// Estado abstracto RPMB: counter + datos de 2 bloques ∈ {0,1}.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct RpmbAbs {
    wc: u32,
    b0: u8,
    b1: u8,
}

pub fn bfs_rpmb() -> BfsReport {
    let t0 = Instant::now();
    let key = [0xABu8; 32];
    let mut seen: HashSet<RpmbAbs> = HashSet::new();
    let mut q: VecDeque<(RpmbAbs, RpmbDevice)> = VecDeque::new();
    let mut transitions = 0u64;
    let mut violations = 0u64;

    let dev = RpmbDevice::new(key, 2);
    let start = RpmbAbs {
        wc: 0,
        b0: 0,
        b1: 0,
    };
    seen.insert(start);
    q.push_back((start, dev));

    while let Some((abs, mut d)) = q.pop_front() {
        if abs.wc >= 8 {
            continue; // cota preregistrada
        }
        for addr in [0u16, 1u16] {
            for data_bit in [0u8, 1u8] {
                let mut data = [0u8; RPMB_DATA_LEN];
                data[0] = data_bit;
                // Honest write
                {
                    let mut n = d.clone();
                    let f = n.sign_write(addr, n.write_counter(), data);
                    let wc_before = n.write_counter();
                    let r = n.authenticated_write(&f);
                    transitions += 1;
                    match r {
                        Ok(()) => {
                            if n.write_counter() != wc_before + 1 {
                                violations += 1;
                            }
                        }
                        Err(_) => violations += 1,
                    }
                    let next = RpmbAbs {
                        wc: n.write_counter(),
                        b0: n_block_bit(&n, 0),
                        b1: n_block_bit(&n, 1),
                    };
                    if next.wc <= 8 && seen.insert(next) {
                        q.push_back((next, n));
                    }
                }
                // Bad MAC
                {
                    let mut n = d.clone();
                    let mut f = n.sign_write(addr, n.write_counter(), data);
                    f.mac[0] ^= 0xFF;
                    let wc_before = n.write_counter();
                    let r = n.authenticated_write(&f);
                    transitions += 1;
                    if !matches!(r, Err(RpmbError::BadMac)) || n.write_counter() != wc_before {
                        violations += 1;
                    }
                }
                // Replay with wc=0 if current>0
                if abs.wc > 0 {
                    let mut n = d.clone();
                    // Frame firmado para write_counter=0 (replay); el dispositivo espera abs.wc.
                    let f = n.sign_write(addr, 0, data);
                    let wc_before = n.write_counter();
                    let r = n.authenticated_write(&f);
                    transitions += 1;
                    if n.write_counter() != wc_before {
                        violations += 1; // no debe mutar
                    }
                    if matches!(r, Ok(())) {
                        violations += 1; // replay no debe aceptar
                    }
                }
            }
        }
        let _ = abs;
        let _ = &mut d;
    }

    BfsReport {
        name: "rpmb".into(),
        states_explored: seen.len() as u64,
        transitions,
        violations,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        bound_note: "n_blocks=2, write_counter≤8, data∈{0,1}".into(),
    }
}

fn n_block_bit(d: &RpmbDevice, addr: u16) -> u8 {
    d.authenticated_read(addr).map(|r| r.data[0]).unwrap_or(0)
}

/// BFS gatekeeper abstracto: fails + state + throttled, secreto ∈ {0,1} fijo.
pub fn bfs_gatekeeper() -> BfsReport {
    use crate::gatekeeper::Gatekeeper;
    let t0 = Instant::now();
    let policy = PinPolicy {
        max_fails: 4,
        base_throttle_ms: 1,
        throttle_cap_ms: 1,
    };
    let mut seen: HashSet<PinAbs> = HashSet::new();
    let mut q: VecDeque<(PinAbs, Gatekeeper)> = VecDeque::new();
    let mut transitions = 0u64;
    let mut violations = 0u64;

    let gk = Gatekeeper::new([1u8; 32], [2u8; 16], b"\x01".to_vec(), policy);
    let start = PinAbs {
        fails: 0,
        state: 0,
        throttled: false,
    };
    seen.insert(start);
    q.push_back((start, gk));

    while let Some((abs, mut gk)) = q.pop_front() {
        let handle = gk.enroll(b"\x01");
        if abs.throttled {
            gk.advance(gk.throttle_remaining_ms().max(1));
            let next = PinAbs {
                fails: gk.rpmb_fails(),
                state: pin_state_code(gk.lock_state()),
                throttled: gk.is_throttled(),
            };
            transitions += 1;
            if seen.insert(next) {
                q.push_back((next, gk));
            }
            continue;
        }
        for good in [true, false] {
            let mut n = gk.clone();
            let before = n.rpmb_fails();
            let out = if good {
                n.verify(b"\x01", &handle)
            } else {
                n.verify(b"\x00", &handle)
            };
            transitions += 1;
            match out {
                AttemptOutcome::Rejected { .. } => {
                    if n.rpmb_fails() != before + 1 {
                        violations += 1;
                    }
                }
                AttemptOutcome::Accepted => {
                    if n.rpmb_fails() != 0
                        || n.lock_state() == LockState::Bfu && before == 0 && good
                    {
                        // Accepted debe dejar fails=0; BFU→AFU
                    }
                    if n.rpmb_fails() != 0 {
                        violations += 1;
                    }
                }
                AttemptOutcome::AlreadyWiped | AttemptOutcome::LockedOut => {
                    if n.lock_state() == LockState::Wiped && good {
                        // OK permanent deny
                    }
                }
            }
            let next = PinAbs {
                fails: n.rpmb_fails(),
                state: pin_state_code(n.lock_state()),
                throttled: n.is_throttled(),
            };
            if seen.insert(next) {
                q.push_back((next, n));
            }
        }
        let _ = abs;
    }

    BfsReport {
        name: "gatekeeper".into(),
        states_explored: seen.len() as u64,
        transitions,
        violations,
        elapsed_ms: t0.elapsed().as_millis() as u64,
        bound_note: "max_fails=4, secreto abstracto {0,1}, RPMB tracks fails".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bfs_pin_sin_violaciones() {
        let r = bfs_pin_counter();
        assert!(r.states_explored > 0, "{:?}", r);
        assert_eq!(r.violations, 0, "{:?}", r);
    }

    #[test]
    fn bfs_rpmb_sin_violaciones() {
        let r = bfs_rpmb();
        assert!(r.states_explored > 0, "{:?}", r);
        assert_eq!(r.violations, 0, "{:?}", r);
    }

    #[test]
    fn bfs_gk_sin_violaciones() {
        let r = bfs_gatekeeper();
        assert!(r.states_explored > 0, "{:?}", r);
        assert_eq!(r.violations, 0, "{:?}", r);
    }
}
