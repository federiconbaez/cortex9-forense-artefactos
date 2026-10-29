# Modelo formal — cortex9-forense-artefactos

## Framing

Todo es **modelo / máquina de estados / propiedad medible**. No hay
recetas, bypass ni exploits contra dispositivos, contadores de PIN o
RPMB reales. La tesis cita este repo como evidencia de implementación
del modelo; lo operativo queda fuera de alcance.

## Artefactos y mapping a la tesis

| Módulo | Qué modela | Capítulos tesis |
|--------|------------|-----------------|
| `pin_counter` | Contador de intentos BFU/AFU, throttle 2^n, wipe | 7, 11 |
| `inactivity` | AFU→BFU por idle timeout T + evicción CE | 7, 11 |
| `rpmb` | Write counter monotónico + HMAC anti-rollback | 11, 12 |
| `powercut` | WBV vs VBW bajo corte de energía | 11, 12 |
| `gatekeeper` | Enroll/Verify HMAC + persistencia RPMB | 12, 13 |
| `weaver` | Slots StrongBox con throttle/wipe por slot | 12, 13 |
| `fbe_keys` | Jerarquía CE/DE, unlock, evicción, wipe | 7, 13 |
| `apple_dp` | Clases Data Protection A–D (docs públicas) | 7, 13 |
| `lock_capabilities` | Tabla de capacidades por estado | 7, 13 |
| `avb_rollback` | Índices AVB anti-downgrade | 19 |
| `pate` | PATE-FNBR: transcripción hash-encadenada | 19 |
| `model_check` | BFS exhaustivo acotado | transversal |
| `mutants` | Sensibilidad del checker (7 mutantes) | transversal |

## Escalas de verificación

| Modo | Trials MC | Dónde |
|------|----------:|-------|
| `ci` | 10_000 | GitHub Actions |
| `full` | **10_000_000** | evidencia versionada |

Semillas y umbrales: `docs/PREREGISTRO.md` (commit **antes** de medir).

## Model checking (BFS)

Límites preregistrados; se reportan estados, transiciones, violaciones y
tiempo. Umbral: 0 violaciones.

## Mutantes

7 variantes rotas a propósito. Umbral: 7/7 detectados. Si alguno no se
detecta ⇒ **NO CUMPLIDO** (el 100/0 "por construcción" solo vale con
test sensible).

## Power-cut (resultado estructural)

- **write-before-verify**: bajo power-cut tras el write, el invariante
  `fails == intentos_efectivos` **se rompe** (demostrado).
- **verify-before-write**: bajo el mismo fallo, el invariante
  **se preserva** (demostrado).

## Límites explícitos

- No se mide hardware real.
- No hay payloads, offsets ni procedimientos de extracción.
- "Por construcción" = corpus = propio modelo.
- Kani / verificación formal deducida: ver README (estado de toolchain).
- Fuzzing: ver README / `fuzz/` si el toolchain lo permite.
