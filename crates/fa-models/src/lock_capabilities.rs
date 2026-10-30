//! Tabla de capacidades de extracción por estado de bloqueo (modelo).
//!
//! Cataloga, a partir de literatura pública y documentación de proveedores,
//! qué **clase** de evidencia es alcanzable en BFU vs AFU vs wipe, sin
//! describir procedimientos, exploits ni herramientas concretas contra un
//! dispositivo. Cada fila es una capacidad abstracta + la condición mínima
//! de estado. Los tests verifican invariantes del catálogo (completitud,
//! consistencia BFU⊂AFU para clases CE, etc.), no un laboratorio real.
//!
//! Fuentes públicas citadas en `docs/FUENTES.md`. Nada aquí es una receta.

use crate::pin_counter::LockState;

/// Clase abstracta de evidencia / superficie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceClass {
    /// Datos cifrados por dispositivo (DE): accesibles tras boot, sin unlock.
    DeviceEncrypted,
    /// Datos cifrados por credenciales (CE): requieren AFU.
    CredentialEncrypted,
    /// Claves en anillos del kernel (volátiles): solo AFU, se pierden al reboot.
    VolatileKeyring,
    /// Contador de intentos / throttle en RPMB: observable como estado, no
    /// como valor en claro desde fuera del TEE.
    RpmbBackedCounter,
    /// Volcado físico crudo de NAND/UFS: alta entropía bajo FBE inline crypto.
    RawNandDump,
    /// Full File System vía agente en memoria: requiere primitiva de
    /// lectura/escritura en kernel + estado AFU para CE.
    FullFileSystem,
    /// Artefactos SQLite WAL/freelist: dependen de FFS o de imagen de FS.
    SqliteWalResidues,
}

/// ¿La capacidad es alcanzable en ese estado? (modelo binario).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reachability {
    Reachable,
    NotReachable,
    /// Alcanzable pero el contenido es criptográficamente inútil sin claves.
    ReachableButCiphertext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityRow {
    pub class: EvidenceClass,
    pub in_bfu: Reachability,
    pub in_afu: Reachability,
    pub in_wiped: Reachability,
    /// Nota corta (literatura pública).
    pub note: &'static str,
}

/// Catálogo fijo. Semilla conceptual: literatura Android FBE / iOS Data
/// Protection + reportes públicos de laboratorios forenses (ver FUENTES.md).
pub fn catalog() -> &'static [CapabilityRow] {
    use EvidenceClass::*;
    use Reachability::*;
    &[
        CapabilityRow {
            class: DeviceEncrypted,
            in_bfu: Reachable,
            in_afu: Reachable,
            in_wiped: NotReachable,
            note: "DE disponible tras boot; wipe destruye el keystore del usuario",
        },
        CapabilityRow {
            class: CredentialEncrypted,
            in_bfu: NotReachable,
            in_afu: Reachable,
            in_wiped: NotReachable,
            note: "CE envuelto en BFU; disponible en AFU; wipe elimina material",
        },
        CapabilityRow {
            class: VolatileKeyring,
            in_bfu: NotReachable,
            in_afu: Reachable,
            in_wiped: NotReachable,
            note: "Claves CE en RAM solo tras primer unlock; reboot → BFU",
        },
        CapabilityRow {
            class: RpmbBackedCounter,
            in_bfu: Reachable,
            in_afu: Reachable,
            in_wiped: Reachable,
            note: "El contador RPMB persiste; wipe es un estado del contador, no su borrado",
        },
        CapabilityRow {
            class: RawNandDump,
            in_bfu: ReachableButCiphertext,
            in_afu: ReachableButCiphertext,
            in_wiped: ReachableButCiphertext,
            note: "Chip-off/JTAG entregan ciphertext bajo inline crypto; sin claves de silicio",
        },
        CapabilityRow {
            class: FullFileSystem,
            in_bfu: NotReachable, // CE no; DE parcial se modela aparte
            in_afu: Reachable,
            in_wiped: NotReachable,
            note: "FFS con CE requiere AFU; en BFU solo DE parcial (no modelado como FFS)",
        },
        CapabilityRow {
            class: SqliteWalResidues,
            in_bfu: NotReachable,
            in_afu: Reachable,
            in_wiped: NotReachable,
            note: "Residuos WAL/freelist viven en el FS del usuario (CE) → AFU",
        },
    ]
}

/// Consulta: ¿`class` es alcanzable (Reachable) en `state`?
pub fn is_reachable(class: EvidenceClass, state: LockState) -> bool {
    for row in catalog() {
        if row.class == class {
            let r = match state {
                LockState::Bfu => row.in_bfu,
                LockState::Afu => row.in_afu,
                LockState::Wiped => row.in_wiped,
            };
            return r == Reachability::Reachable;
        }
    }
    false
}

#[derive(Clone, Debug, Default)]
pub struct CapPropertyReport {
    pub rows: u64,
    /// Toda clase CE-dependiente es NotReachable en BFU y Reachable en AFU.
    pub ce_bfu_afu_ok: bool,
    /// RawNandDump es ReachableButCiphertext en los tres estados.
    pub nand_ciphertext_ok: bool,
    /// Wipe ⇒ ninguna clase CE/FFS/WAL reachable.
    pub wipe_clears_user_ok: bool,
    /// RPMB counter reachable en los tres (persiste).
    pub rpmb_persists_ok: bool,
    /// Catálogo no vacío y sin clases duplicadas.
    pub catalog_wellformed_ok: bool,
}

impl CapPropertyReport {
    pub fn all_pass(&self) -> bool {
        self.rows > 0
            && self.ce_bfu_afu_ok
            && self.nand_ciphertext_ok
            && self.wipe_clears_user_ok
            && self.rpmb_persists_ok
            && self.catalog_wellformed_ok
    }
}

pub fn measure_capability_properties() -> CapPropertyReport {
    use EvidenceClass::*;
    use Reachability::*;
    let cat = catalog();
    let mut rep = CapPropertyReport {
        rows: cat.len() as u64,
        ..Default::default()
    };

    // Well-formed: sin duplicados.
    let mut seen = Vec::new();
    let mut dup = false;
    for row in cat {
        if seen.contains(&row.class) {
            dup = true;
        }
        seen.push(row.class);
    }
    rep.catalog_wellformed_ok = !cat.is_empty() && !dup;

    // CE / VolatileKeyring / FFS / WAL: NotReachable en BFU, Reachable en AFU.
    let ce_deps = [
        CredentialEncrypted,
        VolatileKeyring,
        FullFileSystem,
        SqliteWalResidues,
    ];
    rep.ce_bfu_afu_ok = ce_deps
        .iter()
        .all(|&c| !is_reachable(c, LockState::Bfu) && is_reachable(c, LockState::Afu));

    // NAND: ciphertext en los tres.
    rep.nand_ciphertext_ok = cat.iter().any(|r| {
        r.class == RawNandDump
            && r.in_bfu == ReachableButCiphertext
            && r.in_afu == ReachableButCiphertext
            && r.in_wiped == ReachableButCiphertext
    });

    // Wipe limpia clases de usuario.
    rep.wipe_clears_user_ok = ce_deps.iter().all(|&c| !is_reachable(c, LockState::Wiped))
        && !is_reachable(DeviceEncrypted, LockState::Wiped);

    // RPMB persiste.
    rep.rpmb_persists_ok = is_reachable(RpmbBackedCounter, LockState::Bfu)
        && is_reachable(RpmbBackedCounter, LockState::Afu)
        && is_reachable(RpmbBackedCounter, LockState::Wiped);

    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ce_no_en_bfu_si_en_afu() {
        assert!(!is_reachable(
            EvidenceClass::CredentialEncrypted,
            LockState::Bfu
        ));
        assert!(is_reachable(
            EvidenceClass::CredentialEncrypted,
            LockState::Afu
        ));
    }

    #[test]
    fn de_en_bfu_y_afu_no_en_wipe() {
        assert!(is_reachable(EvidenceClass::DeviceEncrypted, LockState::Bfu));
        assert!(is_reachable(EvidenceClass::DeviceEncrypted, LockState::Afu));
        assert!(!is_reachable(
            EvidenceClass::DeviceEncrypted,
            LockState::Wiped
        ));
    }

    #[test]
    fn propiedades_catalogo() {
        let rep = measure_capability_properties();
        assert_eq!(rep.rows, 7);
        assert!(rep.ce_bfu_afu_ok);
        assert!(rep.nand_ciphertext_ok);
        assert!(rep.wipe_clears_user_ok);
        assert!(rep.rpmb_persists_ok);
        assert!(rep.catalog_wellformed_ok);
        assert!(rep.all_pass());
    }
}
