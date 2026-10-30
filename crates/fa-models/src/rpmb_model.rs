//! Adaptador [`Model`] para RPMB acotado (n_blocks=2, wc≤8).

use crate::rpmb::{RpmbDevice, RPMB_DATA_LEN};
use fa_core::{Action, Model, Property, Result, State};

/// Estado abstracto RPMB.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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
        /// Dirección.
        addr: u16,
        /// Bit de datos.
        bit: u8,
    },
    /// Intento con MAC inválido (estado no cambia).
    BadMac {
        /// Dirección.
        addr: u16,
    },
}

impl Action for RpmbAction {
    fn name(&self) -> &str {
        match self {
            RpmbAction::Honest { .. } => "honest",
            RpmbAction::BadMac { .. } => "bad_mac",
        }
    }
}

/// Modelo RPMB.
#[derive(Clone, Debug, Default)]
pub struct RpmbModel;

fn rebuild(s: &RpmbState) -> RpmbDevice {
    let mut cur = RpmbDevice::new([0xABu8; 32], 2);
    // Aproxima el estado escribiendo b0/b1 con wc pasos (acotado).
    for i in 0..s.wc {
        let addr = (i % 2) as u16;
        let mut data = [0u8; RPMB_DATA_LEN];
        data[0] = if addr == 0 { s.b0 } else { s.b1 };
        let f = cur.sign_write(addr, cur.write_counter(), data);
        let _ = cur.authenticated_write(&f);
    }
    cur
}

fn abs(d: &RpmbDevice) -> RpmbState {
    RpmbState {
        wc: d.write_counter().min(8),
        b0: d.authenticated_read(0).map(|r| r.data[0]).unwrap_or(0),
        b1: d.authenticated_read(1).map(|r| r.data[0]).unwrap_or(0),
    }
}

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
        let d = rebuild(s);
        let mut out = Vec::new();
        for addr in [0u16, 1] {
            for bit in [0u8, 1] {
                let mut n = d.clone();
                let mut data = [0u8; RPMB_DATA_LEN];
                data[0] = bit;
                let f = n.sign_write(addr, n.write_counter(), data);
                let _ = n.authenticated_write(&f);
                let st = abs(&n);
                if st.wc <= 8 {
                    out.push((RpmbAction::Honest { addr, bit }, st));
                }
            }
            let mut n = d.clone();
            let mut f = n.sign_write(addr, n.write_counter(), [0u8; RPMB_DATA_LEN]);
            f.mac[0] ^= 0xFF;
            let _ = n.authenticated_write(&f);
            out.push((RpmbAction::BadMac { addr }, abs(&n)));
        }
        Ok(out)
    }
}

/// wc acotado.
pub struct RpmbBound;
impl Property<RpmbModel> for RpmbBound {
    fn name(&self) -> &str {
        "wc_bound"
    }
    fn holds(&self, _: &RpmbModel, s: &RpmbState) -> Result<bool> {
        Ok(s.wc <= 8)
    }
}

/// Propiedades para CLI.
pub fn rpmb_properties() -> Vec<Box<dyn Property<RpmbModel>>> {
    vec![Box::new(RpmbBound)]
}
