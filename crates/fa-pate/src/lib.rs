//! PATE-FNBR: Protocolo de Atestación de Transcripción de Extracción.
//!
//! Cadena hash (SHA-256) de eventos de adquisición forense, verificable
//! y exportable a JSON / Markdown para el expediente.
//!
//! **No ejecuta extracciones reales**; registra y atesta lo declarado.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

use fa_core::crypto::{ct_eq, sha256};
use fa_core::{Error, Result};
use serde::{Deserialize, Serialize};

/// Evento de la transcripción.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    /// Secuencia (0..n-1).
    pub seq: u64,
    /// Tipo (p.ej. `acquire`, `hash`, `tool`, `seal`).
    pub kind: String,
    /// Payload libre (UTF-8 recomendado).
    pub payload: String,
    /// Timestamp declarado (ISO-8601 o etiqueta ART).
    pub timestamp: String,
    /// Operador declarado.
    pub operator: String,
    /// Herramienta declarada.
    pub tool: String,
    /// Hash SHA-256 hex del artefacto (opcional, vacío si N/A).
    pub artifact_sha256: String,
}

/// Entrada encadenada.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    /// Evento.
    pub event: Event,
    /// Hash previo (64 hex o ceros iniciales).
    pub prev_hash: String,
    /// Hash de esta entrada.
    pub hash: String,
}

/// Transcripción PATE.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transcript {
    /// Identificador de caso / expediente.
    pub case_id: String,
    /// Entradas.
    pub entries: Vec<Entry>,
    /// ¿Sellada?
    pub sealed: bool,
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{:02x}", x);
    }
    s
}

fn unhex(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        return Err(Error::Protocol("hash hex debe tener 64 chars"));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Protocol("hash hex inválido"))?;
    }
    Ok(out)
}

impl Transcript {
    /// Crea transcripción vacía.
    pub fn init(case_id: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            entries: Vec::new(),
            sealed: false,
        }
    }

    fn hash_event(prev: &[u8; 32], ev: &Event) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(prev);
        buf.extend_from_slice(&ev.seq.to_be_bytes());
        for part in [
            ev.kind.as_bytes(),
            ev.payload.as_bytes(),
            ev.timestamp.as_bytes(),
            ev.operator.as_bytes(),
            ev.tool.as_bytes(),
            ev.artifact_sha256.as_bytes(),
        ] {
            buf.extend_from_slice(part);
            buf.push(0);
        }
        sha256(&buf)
    }

    /// Append de un paso. Falla si está sellada.
    pub fn append(
        &mut self,
        kind: impl Into<String>,
        payload: impl Into<String>,
        timestamp: impl Into<String>,
        operator: impl Into<String>,
        tool: impl Into<String>,
        artifact_sha256: impl Into<String>,
    ) -> Result<&Entry> {
        if self.sealed {
            return Err(Error::Protocol("transcripción sellada"));
        }
        let prev = self
            .entries
            .last()
            .map(|e| unhex(&e.hash))
            .transpose()?
            .unwrap_or([0u8; 32]);
        let event = Event {
            seq: self.entries.len() as u64,
            kind: kind.into(),
            payload: payload.into(),
            timestamp: timestamp.into(),
            operator: operator.into(),
            tool: tool.into(),
            artifact_sha256: artifact_sha256.into(),
        };
        let hash = Self::hash_event(&prev, &event);
        self.entries.push(Entry {
            event,
            prev_hash: hex(&prev),
            hash: hex(&hash),
        });
        self.entries
            .last()
            .ok_or(Error::Msg("append interno".into()))
    }

    /// Sella la cadena con un ancla.
    pub fn seal(
        &mut self,
        operator: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> Result<()> {
        if self.sealed {
            return Err(Error::Protocol("ya sellada"));
        }
        self.append("seal", "chain-seal", timestamp, operator, "pate-fnbr", "")?;
        self.sealed = true;
        Ok(())
    }

    /// Tip hash.
    pub fn tip(&self) -> String {
        self.entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| hex(&[0u8; 32]))
    }

    /// Verifica la cadena. Devuelve Ok(()) o el índice/razón del fallo.
    pub fn verify(&self) -> std::result::Result<(), VerifyError> {
        let mut expect_prev = [0u8; 32];
        for (i, e) in self.entries.iter().enumerate() {
            if e.event.seq != i as u64 {
                return Err(VerifyError {
                    index: i,
                    reason: "seq gap/reorder",
                });
            }
            let prev = unhex(&e.prev_hash).map_err(|_| VerifyError {
                index: i,
                reason: "prev_hash hex",
            })?;
            if !ct_eq(&prev, &expect_prev) {
                return Err(VerifyError {
                    index: i,
                    reason: "prev_hash mismatch",
                });
            }
            let h = Self::hash_event(&prev, &e.event);
            let got = unhex(&e.hash).map_err(|_| VerifyError {
                index: i,
                reason: "hash hex",
            })?;
            if !ct_eq(&h, &got) {
                return Err(VerifyError {
                    index: i,
                    reason: "hash mismatch (alteración)",
                });
            }
            expect_prev = got;
        }
        Ok(())
    }

    /// Export JSON pretty.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| Error::Msg(e.to_string()))
    }

    /// Desde JSON.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| Error::Msg(e.to_string()))
    }

    /// Informe Markdown para expediente.
    pub fn to_markdown(&self) -> String {
        let mut md = format!("# Transcripción PATE-FNBR — caso `{}`\n\n", self.case_id);
        md.push_str(&format!("- Sellada: **{}**\n", self.sealed));
        md.push_str(&format!("- Entradas: **{}**\n", self.entries.len()));
        md.push_str(&format!("- Tip: `{}`\n\n", self.tip()));
        md.push_str("| seq | kind | timestamp | operator | tool | artifact_sha256 | hash |\n");
        md.push_str("|----:|------|-----------|----------|------|-----------------|------|\n");
        for e in &self.entries {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} | `{}` | `{}` |\n",
                e.event.seq,
                e.event.kind,
                e.event.timestamp,
                e.event.operator,
                e.event.tool,
                e.event.artifact_sha256,
                &e.hash[..16]
            ));
        }
        md.push_str("\nVerificación: ejecutar `fa pate verify <archivo.json>`.\n");
        md
    }
}

/// Error de verificación con índice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyError {
    /// Índice de entrada.
    pub index: usize,
    /// Razón.
    pub reason: &'static str,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "entrada {}: {}", self.index, self.reason)
    }
}

impl std::error::Error for VerifyError {}

/// Throughput de verify (entradas/s) sobre `n` entradas sintéticas.
pub fn bench_verify_throughput(n: usize) -> (u64, f64) {
    let mut t = Transcript::init("bench");
    for i in 0..n {
        let _ = t.append("step", format!("p{i}"), "T", "op", "tool", "");
    }
    let t0 = std::time::Instant::now();
    let _ = t.verify();
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    let per_s = if ms > 0.0 {
        (n as f64) / (ms / 1000.0)
    } else {
        f64::INFINITY
    };
    (n as u64, per_s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_verify() {
        let mut t = Transcript::init("C-1");
        t.append(
            "acquire",
            "ufs",
            "2026-10-29T12:00:00-03:00",
            "FNB",
            "tool-x",
            "ab".repeat(32),
        )
        .unwrap();
        t.seal("FNB", "2026-10-29T12:05:00-03:00").unwrap();
        assert!(t.verify().is_ok());
        let j = t.to_json().unwrap();
        let t2 = Transcript::from_json(&j).unwrap();
        assert_eq!(t, t2);
    }

    #[test]
    fn detect_alteracion() {
        let mut t = Transcript::init("C");
        t.append("a", "1", "t", "o", "x", "").unwrap();
        t.append("b", "2", "t", "o", "x", "").unwrap();
        t.entries[1].event.payload = "X".into();
        let e = t.verify().unwrap_err();
        assert_eq!(e.index, 1);
    }
}
