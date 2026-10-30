//! Adaptador [`Model`] Gatekeeper equivalente a v0.1 `bfs_gatekeeper`.
//!
//! `materialize` localiza un `Gatekeeper` concreto alcanzable con la misma
//! huella abstracta mediante BFS concreto (misma semántica que v0.1).

use crate::gatekeeper::Gatekeeper;
use crate::pin_counter::{LockState, PinPolicy};
use fa_core::{Action, Model, Property, Result, State};
use std::collections::{HashSet, VecDeque};

/// Estado abstracto GK.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GkState {
    /// Fallos RPMB.
    pub fails: u32,
    /// 0=Bfu 1=Afu 2=Wiped.
    pub state: u8,
    /// Throttle.
    pub throttled: bool,
}

impl State for GkState {
    fn label(&self) -> String {
        format!("g{}/{}/t{}", self.fails, self.state, self.throttled as u8)
    }
}

/// Acción GK.
#[derive(Clone, Debug)]
pub enum GkAction {
    /// Verify ok.
    VerifyOk,
    /// Verify bad.
    VerifyBad,
    /// Advance throttle.
    Advance,
}

impl Action for GkAction {
    fn name(&self) -> &str {
        match self {
            GkAction::VerifyOk => "ok",
            GkAction::VerifyBad => "bad",
            GkAction::Advance => "adv",
        }
    }
}

/// Modelo Gatekeeper (max_fails=4).
#[derive(Clone, Debug)]
pub struct GatekeeperModel {
    policy: PinPolicy,
}

impl Default for GatekeeperModel {
    fn default() -> Self {
        Self {
            policy: PinPolicy {
                max_fails: 4,
                base_throttle_ms: 1,
                throttle_cap_ms: 1,
            },
        }
    }
}

fn abs_of(gk: &Gatekeeper) -> GkState {
    GkState {
        fails: gk.rpmb_fails(),
        state: match gk.lock_state() {
            LockState::Bfu => 0,
            LockState::Afu => 1,
            LockState::Wiped => 2,
        },
        throttled: gk.is_throttled(),
    }
}

impl GatekeeperModel {
    fn fresh(&self) -> Gatekeeper {
        Gatekeeper::new([1u8; 32], [2u8; 16], b"\x01".to_vec(), self.policy.clone())
    }

    /// Encuentra un concreto alcanzable con huella `target`.
    fn materialize(&self, target: &GkState) -> Gatekeeper {
        let mut seen: HashSet<GkState> = HashSet::new();
        let mut q: VecDeque<Gatekeeper> = VecDeque::new();
        let start = self.fresh();
        seen.insert(abs_of(&start));
        q.push_back(start);
        while let Some(gk) = q.pop_front() {
            if abs_of(&gk) == *target {
                return gk;
            }
            let handle = gk.enroll(b"\x01");
            let abs = abs_of(&gk);
            if abs.throttled {
                let mut n = gk.clone();
                n.advance(n.throttle_remaining_ms().max(1));
                let a = abs_of(&n);
                if seen.insert(a) {
                    q.push_back(n);
                }
                continue;
            }
            for good in [true, false] {
                let mut n = gk.clone();
                let _ = if good {
                    n.verify(b"\x01", &handle)
                } else {
                    n.verify(b"\x00", &handle)
                };
                let a = abs_of(&n);
                if seen.insert(a) {
                    q.push_back(n);
                }
            }
        }
        // Fallback: initial (no debería ocurrir si target es alcanzable).
        self.fresh()
    }
}

impl Model for GatekeeperModel {
    type S = GkState;
    type A = GkAction;

    fn name(&self) -> &str {
        "gatekeeper"
    }

    fn initials(&self) -> Vec<GkState> {
        vec![GkState {
            fails: 0,
            state: 0,
            throttled: false,
        }]
    }

    fn successors(&self, s: &GkState) -> Result<Vec<(GkAction, GkState)>> {
        let gk = self.materialize(s);
        let handle = gk.enroll(b"\x01");
        let mut out = Vec::new();
        if s.throttled {
            let mut n = gk;
            n.advance(n.throttle_remaining_ms().max(1));
            out.push((GkAction::Advance, abs_of(&n)));
            return Ok(out);
        }
        for (act, good) in [(GkAction::VerifyOk, true), (GkAction::VerifyBad, false)] {
            let mut n = gk.clone();
            let _ = if good {
                n.verify(b"\x01", &handle)
            } else {
                n.verify(b"\x00", &handle)
            };
            out.push((act, abs_of(&n)));
        }
        Ok(out)
    }
}

/// Cota de fails.
pub struct GkBound;
impl Property<GatekeeperModel> for GkBound {
    fn name(&self) -> &str {
        "fails_bound"
    }
    fn holds(&self, m: &GatekeeperModel, s: &GkState) -> Result<bool> {
        Ok(s.fails <= m.policy.max_fails)
    }
}
