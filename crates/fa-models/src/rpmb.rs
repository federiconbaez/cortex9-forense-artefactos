//! Modelo ejecutable del protocolo RPMB (Replay Protected Memory Block).
//!
//! RPMB (eMMC / UFS) es la memoria autenticada que usan Gatekeeper / Weaver /
//! Keymaster para persistir el contador de intentos y material antirrebote.
//! Propiedades modeladas (JEDEC eMMC 5.1 §6.6.22 / UFS RPMB, literatura
//! pública):
//!
//! 1. **Write counter monotónico**: cada escritura autenticada exitosa
//!    incrementa `write_counter` en exactamente 1; nunca decrece.
//! 2. **Autenticación HMAC**: toda escritura / lectura autenticada lleva un
//!    MAC = HMAC-SHA256(key, frame). Un MAC inválido se rechaza y **no**
//!    muta el contador ni el dato.
//! 3. **Anti-rollback**: una escritura que presenta un `write_counter`
//!    distinto del valor actual del dispositivo se rechaza (el atacante no
//!    puede "rebobinar" el contador rejugando un frame viejo).
//!
//! **Fuera de alcance:** interceptar el bus eMMC/UFS, clonar el RPMB de un
//! dispositivo real, eludir el contador de PIN vía RPMB, o cualquier receta
//! operativa. Esto es un simulador de protocolo con tests de propiedades.

use fa_core::crypto::{ct_eq, hmac_sha256};
use fa_core::rng::Rng;

/// Tamaño del bloque de datos RPMB modelado (bytes). JEDEC usa 256; aquí
/// usamos 32 para mantener los tests livianos sin cambiar las propiedades.
pub const RPMB_DATA_LEN: usize = 32;

/// Frame autenticado de escritura.
#[derive(Clone, Debug)]
pub struct WriteFrame {
    pub address: u16,
    pub write_counter: u32,
    pub data: [u8; RPMB_DATA_LEN],
    pub mac: [u8; 32],
}

/// Frame autenticado de lectura (respuesta).
#[derive(Clone, Debug)]
pub struct ReadFrame {
    pub address: u16,
    pub write_counter: u32,
    pub data: [u8; RPMB_DATA_LEN],
    pub mac: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpmbError {
    BadMac,
    CounterMismatch { expected: u32, got: u32 },
    AddressOob,
}

/// Dispositivo RPMB simulado: un arreglo de bloques + write_counter global
/// + clave HMAC de autenticación (provisionada en fábrica, en el modelo).
#[derive(Clone, Debug)]
pub struct RpmbDevice {
    key: [u8; 32],
    write_counter: u32,
    blocks: Vec<[u8; RPMB_DATA_LEN]>,
}

impl RpmbDevice {
    pub fn new(key: [u8; 32], n_blocks: usize) -> Self {
        assert!(n_blocks > 0);
        RpmbDevice {
            key,
            write_counter: 0,
            blocks: vec![[0u8; RPMB_DATA_LEN]; n_blocks],
        }
    }

    pub fn write_counter(&self) -> u32 {
        self.write_counter
    }

    pub fn n_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Serializa el payload sobre el que se calcula el MAC (sin el MAC).
    fn write_payload(address: u16, write_counter: u32, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(2 + 4 + data.len());
        v.extend_from_slice(&address.to_be_bytes());
        v.extend_from_slice(&write_counter.to_be_bytes());
        v.extend_from_slice(data);
        v
    }

    /// Firma un frame de escritura con la clave del dispositivo. Solo el
    /// "host legítimo" (TEE / Gatekeeper) conoce la clave en el modelo.
    pub fn sign_write(
        &self,
        address: u16,
        write_counter: u32,
        data: [u8; RPMB_DATA_LEN],
    ) -> WriteFrame {
        let mac = hmac_sha256(
            &self.key,
            &Self::write_payload(address, write_counter, &data),
        );
        WriteFrame {
            address,
            write_counter,
            data,
            mac,
        }
    }

    /// Escritura autenticada. Propiedades:
    /// - MAC inválido → BadMac, estado intacto.
    /// - write_counter ≠ actual → CounterMismatch, estado intacto (anti-rollback).
    /// - OK → dato escrito y write_counter += 1.
    pub fn authenticated_write(&mut self, frame: &WriteFrame) -> Result<(), RpmbError> {
        if frame.address as usize >= self.blocks.len() {
            return Err(RpmbError::AddressOob);
        }
        let expected_mac = hmac_sha256(
            &self.key,
            &Self::write_payload(frame.address, frame.write_counter, &frame.data),
        );
        if !ct_eq(&expected_mac, &frame.mac) {
            return Err(RpmbError::BadMac);
        }
        if frame.write_counter != self.write_counter {
            return Err(RpmbError::CounterMismatch {
                expected: self.write_counter,
                got: frame.write_counter,
            });
        }
        self.blocks[frame.address as usize] = frame.data;
        self.write_counter = self.write_counter.saturating_add(1);
        Ok(())
    }

    /// Lectura autenticada: el dispositivo responde con (data, write_counter)
    /// firmados, para que el host pueda verificar integridad y frescura.
    pub fn authenticated_read(&self, address: u16) -> Result<ReadFrame, RpmbError> {
        if address as usize >= self.blocks.len() {
            return Err(RpmbError::AddressOob);
        }
        let data = self.blocks[address as usize];
        let mac = hmac_sha256(
            &self.key,
            &Self::write_payload(address, self.write_counter, &data),
        );
        Ok(ReadFrame {
            address,
            write_counter: self.write_counter,
            data,
            mac,
        })
    }

    /// Verifica un ReadFrame con la clave del dispositivo (lado host).
    pub fn verify_read(&self, frame: &ReadFrame) -> bool {
        if frame.address as usize >= self.blocks.len() {
            return false;
        }
        let expected = hmac_sha256(
            &self.key,
            &Self::write_payload(frame.address, frame.write_counter, &frame.data),
        );
        ct_eq(&expected, &frame.mac)
    }
}

#[derive(Clone, Debug, Default)]
pub struct RpmbPropertyReport {
    pub trials: u64,
    pub mono_ok: u64,
    pub bad_mac_rejected: u64,
    pub replay_rejected: u64,
    pub honest_write_ok: u64,
    pub read_roundtrip_ok: u64,
}

impl RpmbPropertyReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.mono_ok == self.trials
            && self.bad_mac_rejected == self.trials
            && self.replay_rejected == self.trials
            && self.honest_write_ok == self.trials
            && self.read_roundtrip_ok == self.trials
    }
}

/// Mide las propiedades anti-rollback / autenticación con semilla fija.
pub fn measure_rpmb_properties(seed: u64, trials: u64) -> RpmbPropertyReport {
    let mut rng = Rng::new(seed);
    let mut rep = RpmbPropertyReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        let mut key = [0u8; 32];
        let kb = rng.bytes(32);
        key.copy_from_slice(&kb);
        let mut dev = RpmbDevice::new(key, 8);
        let mut mono = true;
        let mut bad_mac = true;
        let mut replay = true;
        let mut honest = true;
        let mut roundtrip = true;

        // Escritura honesta.
        let addr = rng.below(8) as u16;
        let mut data = [0u8; RPMB_DATA_LEN];
        data.copy_from_slice(&rng.bytes(RPMB_DATA_LEN));
        let wc_before = dev.write_counter();
        let frame = dev.sign_write(addr, wc_before, data);
        if dev.authenticated_write(&frame).is_err() {
            honest = false;
        }
        if dev.write_counter() != wc_before + 1 {
            mono = false;
            honest = false;
        }

        // Roundtrip de lectura.
        match dev.authenticated_read(addr) {
            Ok(rf) => {
                if !dev.verify_read(&rf) || rf.data != data || rf.write_counter != wc_before + 1 {
                    roundtrip = false;
                }
            }
            Err(_) => roundtrip = false,
        }

        // MAC inválido: flip de un byte del MAC. Estado no debe mutar.
        let wc2 = dev.write_counter();
        let mut evil = frame.clone();
        evil.write_counter = wc2; // contador actual, pero MAC viejo/roto
        evil.mac[0] ^= 0xFF;
        let blocks_before = dev.blocks.clone();
        match dev.authenticated_write(&evil) {
            Err(RpmbError::BadMac) => {}
            other => {
                let _ = other;
                bad_mac = false;
            }
        }
        if dev.write_counter() != wc2 || dev.blocks != blocks_before {
            bad_mac = false;
            mono = false;
        }

        // Replay del frame original (write_counter viejo): anti-rollback.
        let blocks_before = dev.blocks.clone();
        let wc3 = dev.write_counter();
        match dev.authenticated_write(&frame) {
            Err(RpmbError::CounterMismatch { expected, got }) => {
                if expected != wc3 || got != frame.write_counter {
                    replay = false;
                }
            }
            _ => replay = false,
        }
        if dev.write_counter() != wc3 || dev.blocks != blocks_before {
            replay = false;
            mono = false;
        }

        // Segunda escritura honesta: contador avanza exactamente +1.
        let mut data2 = [0u8; RPMB_DATA_LEN];
        data2.copy_from_slice(&rng.bytes(RPMB_DATA_LEN));
        let f2 = dev.sign_write(addr, wc3, data2);
        if dev.authenticated_write(&f2).is_err() || dev.write_counter() != wc3 + 1 {
            mono = false;
            honest = false;
        }

        if mono {
            rep.mono_ok += 1;
        }
        if bad_mac {
            rep.bad_mac_rejected += 1;
        }
        if replay {
            rep.replay_rejected += 1;
        }
        if honest {
            rep.honest_write_ok += 1;
        }
        if roundtrip {
            rep.read_roundtrip_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escritura_honesta_avanza_contador() {
        let mut d = RpmbDevice::new([7u8; 32], 4);
        let data = [1u8; RPMB_DATA_LEN];
        let f = d.sign_write(0, 0, data);
        assert!(d.authenticated_write(&f).is_ok());
        assert_eq!(d.write_counter(), 1);
    }

    #[test]
    fn mac_invalido_no_muta() {
        let mut d = RpmbDevice::new([7u8; 32], 4);
        let mut f = d.sign_write(0, 0, [2u8; RPMB_DATA_LEN]);
        f.mac[3] ^= 1;
        assert_eq!(d.authenticated_write(&f), Err(RpmbError::BadMac));
        assert_eq!(d.write_counter(), 0);
    }

    #[test]
    fn replay_rechazado_anti_rollback() {
        let mut d = RpmbDevice::new([9u8; 32], 4);
        let f = d.sign_write(1, 0, [3u8; RPMB_DATA_LEN]);
        assert!(d.authenticated_write(&f).is_ok());
        // Rejugar el mismo frame: contador ya es 1, frame dice 0.
        assert!(matches!(
            d.authenticated_write(&f),
            Err(RpmbError::CounterMismatch {
                expected: 1,
                got: 0
            })
        ));
        assert_eq!(d.write_counter(), 1);
    }

    #[test]
    fn lectura_autenticada_verifica() {
        let mut d = RpmbDevice::new([1u8; 32], 2);
        let data = [0xABu8; RPMB_DATA_LEN];
        let f = d.sign_write(0, 0, data);
        d.authenticated_write(&f).unwrap();
        let rf = d.authenticated_read(0).unwrap();
        assert!(d.verify_read(&rf));
        assert_eq!(rf.data, data);
    }

    #[test]
    fn propiedades_semilla_fija_100_por_construccion() {
        // Umbral preregistrado: 100/100 en las 5 propiedades, seed=0x0C09_F0B1.
        let rep = measure_rpmb_properties(0x0C09_F0B1, 100);
        assert_eq!(rep.trials, 100);
        assert_eq!(rep.mono_ok, 100);
        assert_eq!(rep.bad_mac_rejected, 100);
        assert_eq!(rep.replay_rejected, 100);
        assert_eq!(rep.honest_write_ok, 100);
        assert_eq!(rep.read_roundtrip_ok, 100);
        assert!(rep.all_pass());
    }
}
