//! PATE-FNBR: Protocolo de Atestación de Transcripción de Extracción.
//!
//! Transcripción hash-encadenada y verificable de un acto de extracción
//! forense (modelo). Cada evento se liga al hash del anterior; la cadena
//! se cierra con un ancla. Detecta inserción, omisión y reordenamiento.
//! Nivel protocolo/propiedad — no ejecuta extracciones reales.

use crate::crypto::{ct_eq, sha256};
use crate::rng::Rng;

#[derive(Clone, Debug)]
pub struct Event {
    pub seq: u64,
    pub kind: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct TranscriptEntry {
    pub event: Event,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct Transcript {
    pub entries: Vec<TranscriptEntry>,
}

impl Transcript {
    pub fn new() -> Self {
        Self::default()
    }

    fn hash_event(prev: &[u8; 32], ev: &Event) -> [u8; 32] {
        let mut buf = Vec::with_capacity(32 + 8 + ev.kind.len() + ev.payload.len());
        buf.extend_from_slice(prev);
        buf.extend_from_slice(&ev.seq.to_be_bytes());
        buf.extend_from_slice(ev.kind.as_bytes());
        buf.push(0);
        buf.extend_from_slice(&ev.payload);
        sha256(&buf)
    }

    pub fn append(&mut self, kind: &str, payload: Vec<u8>) {
        let prev = self.entries.last().map(|e| e.hash).unwrap_or([0u8; 32]);
        let seq = self.entries.len() as u64;
        let event = Event {
            seq,
            kind: kind.to_string(),
            payload,
        };
        let hash = Self::hash_event(&prev, &event);
        self.entries.push(TranscriptEntry {
            event,
            prev_hash: prev,
            hash,
        });
    }

    pub fn tip(&self) -> [u8; 32] {
        self.entries.last().map(|e| e.hash).unwrap_or([0u8; 32])
    }

    /// Verifica la cadena completa. Cualquier tamper ⇒ Err.
    pub fn verify(&self) -> Result<(), &'static str> {
        let mut expect_prev = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.event.seq != i as u64 {
                return Err("seq gap/reorder");
            }
            if !ct_eq(&e.prev_hash, &expect_prev) {
                return Err("prev_hash mismatch");
            }
            let h = Self::hash_event(&e.prev_hash, &e.event);
            if !ct_eq(&h, &e.hash) {
                return Err("hash mismatch");
            }
            expect_prev = e.hash;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct PateReport {
    pub trials: u64,
    pub honest_ok: u64,
    pub detect_insert_ok: u64,
    pub detect_omit_ok: u64,
    pub detect_reorder_ok: u64,
}

impl PateReport {
    pub fn all_pass(&self) -> bool {
        self.trials > 0
            && self.honest_ok == self.trials
            && self.detect_insert_ok == self.trials
            && self.detect_omit_ok == self.trials
            && self.detect_reorder_ok == self.trials
    }
}

pub fn measure_pate(seed: u64, trials: u64) -> PateReport {
    let mut rng = Rng::new(seed);
    let mut rep = PateReport::default();
    for _ in 0..trials {
        rep.trials += 1;
        let mut t = Transcript::new();
        let n = 3 + (rng.below(5) as usize);
        for i in 0..n {
            t.append("step", format!("e{i}").into_bytes());
        }
        let mut honest = t.verify().is_ok();

        // Insert tamper: flip payload in middle and keep old hash → detect
        let mut evil = t.clone();
        if let Some(e) = evil.entries.get_mut(n / 2) {
            e.event.payload.push(0xFF);
            // hash no recalculado → mismatch
        }
        let ins = evil.verify().is_err();

        // Omit: drop an entry
        let mut omit = t.clone();
        if omit.entries.len() > 2 {
            omit.entries.remove(1);
            // seq/prev rotos
        }
        let om = omit.verify().is_err();

        // Reorder
        let mut re = t.clone();
        if re.entries.len() >= 2 {
            re.entries.swap(0, 1);
        }
        let rd = re.verify().is_err();

        // tip continuity
        if t.tip() == [0u8; 32] && !t.entries.is_empty() {
            honest = false;
        }

        if honest {
            rep.honest_ok += 1;
        }
        if ins {
            rep.detect_insert_ok += 1;
        }
        if om {
            rep.detect_omit_ok += 1;
        }
        if rd {
            rep.detect_reorder_ok += 1;
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cadena_honesta_verifica() {
        let mut t = Transcript::new();
        t.append("boot", b"dev".to_vec());
        t.append("extract", b"fs".to_vec());
        assert!(t.verify().is_ok());
    }
    #[test]
    fn tamper_detectado() {
        let mut t = Transcript::new();
        t.append("a", b"1".to_vec());
        t.append("b", b"2".to_vec());
        t.entries[1].event.payload = b"X".to_vec();
        assert!(t.verify().is_err());
    }
    #[test]
    fn measure_ci() {
        assert!(measure_pate(0x0C09_0A7E, 200).all_pass());
    }
}
