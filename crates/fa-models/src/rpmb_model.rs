//! Adaptador [`Model`] RPMB — grafo abstracto equivalente a v0.1 `bfs_rpmb`.
//!
//! Transiciones (por estado con wc<8): ∀ addr∈{0,1}, ∀ bit∈{0,1}:
//! Honest, BadMac, y si wc>0 también Replay. BadMac/Replay no cambian estado;
//! Honest hace `wc+1` y actualiza el bit del addr. Misma convención de conteo
//! que v0.1 (cada acción = 1 transición).

use fa_core::{Action, Model, Property, Result, State};

/// Estado abstracto RPMB.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RpmbState {
    /// Write counter.
    pub wc: u32,
    /// Bit bloque 0.
    pub b0: u8,
    /// Bit bloque 1.
    pub b1: u8,
}

impl State for RpmbState {
    fn label(&self) -> String {
        format!("wc{}/{}/{}", self.wc, self.b0, self.b1)
    }
}

/// Acción RPMB.
#[derive(Clone, Debug)]
pub enum RpmbAction {
    /// Escritura honesta.
    Honest {
        /// Addr.
        addr: u16,
        /// Bit.
        bit: u8,
    },
    /// MAC inválido.
    BadMac {
        /// Addr.
        addr: u16,
        /// Bit.
        bit: u8,
    },
    /// Replay wc=0.
    Replay {
        /// Addr.
        addr: u16,
        /// Bit.
        bit: u8,
    },
}

impl Action for RpmbAction {
    fn name(&self) -> &str {
        match self {
            RpmbAction::Honest { .. } => "honest",
            RpmbAction::BadMac { .. } => "bad_mac",
            RpmbAction::Replay { .. } => "replay",
        }
    }
}

/// Modelo RPMB.
#[derive(Clone, Debug, Default)]
pub struct RpmbModel;

impl Model for RpmbModel {
    type S = RpmbState;
    type A = RpmbAction;

    fn name(&self) -> &str {
        "rpmb"
    }

    fn initials(&self) -> Vec<RpmbState> {
        vec![RpmbState {
            wc: 0,
            b0: 0,
            b1: 0,
        }]
    }

    fn successors(&self, s: &RpmbState) -> Result<Vec<(RpmbAction, RpmbState)>> {
        if s.wc >= 8 {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        for addr in [0u16, 1u16] {
            for bit in [0u8, 1u8] {
                let mut next = *s;
                if addr == 0 {
                    next.b0 = bit;
                } else {
                    next.b1 = bit;
                }
                next.wc = s.wc + 1;
                out.push((RpmbAction::Honest { addr, bit }, next));
                out.push((RpmbAction::BadMac { addr, bit }, *s));
                if s.wc > 0 {
                    out.push((RpmbAction::Replay { addr, bit }, *s));
                }
            }
        }
        Ok(out)
    }
}

/// Cota de wc.
pub struct RpmbBound;
impl Property<RpmbModel> for RpmbBound {
    fn name(&self) -> &str {
        "wc_bound"
    }
    fn holds(&self, _: &RpmbModel, s: &RpmbState) -> Result<bool> {
        Ok(s.wc <= 8)
    }
}

/// Propiedades CLI.
pub fn rpmb_properties() -> Vec<Box<dyn Property<RpmbModel>>> {
    vec![Box::new(RpmbBound)]
}
