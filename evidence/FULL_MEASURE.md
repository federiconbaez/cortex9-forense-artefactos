# Evidencia FULL measure (v2.1)

Medido / regenerado: **2026-10-29 17:36:37 ART** (America/Buenos_Aires).

## Contrato

- Umbrales/semillas: `docs/PREREGISTRO.md` v2, commit **antes** de la medición.
- Comando exacto:
  ```
  cargo build --release
  ./target/release/forense-artefactos all --mode full
  ```
- Generador de evidencia: `scripts/gen_evidence.py` (parser section-aware:
  `monte_carlo` ≠ `bfs`).
- Trials Monte-Carlo: **10_000_000** por artefacto (≥5 órdenes vs v1=100).
- Etiqueta: **por construcción** (corpus = propio modelo).
- Mutantes: sensibilidad del checker; 7/7 detectados.

## Hashes

| Artefacto | SHA-256 |
|-----------|---------|
| `target/release/forense-artefactos` | `7ef89f72f5c0618dfe9dc261e6d11f1351fc8115d7c707b24faeabdb649430c0` |
| `evidence/full_measure.json` | `2d1dd95da1a044ba5572a04ef7672ed7a04dd44edb1a805e945edf863dca1fa7` |
| `evidence/full_measure.raw.txt` | `001deba16188796bc34201e7ee8547fdeb4e852d4d7a220f731aa994ca2e5d2c` |

## Monte-Carlo (campos corregidos; no son líneas BFS)

| `apple_dp` | `apple_dp: bfu_d=10000000/10000000 afu=10000000/10000000 relock=10000000/10000000 => CUMPLIDO` |
| `avb_rollback` | `avb_rollback: mono=10000000/10000000 rb=10000000/10000000 eq=10000000/10000000 => CUMPLIDO` |
| `fbe_keys` | `fbe_keys: de=10000000/10000000 ce_afu=10000000/10000000 evict=10000000/10000000 wipe=10000000/10000000 => CUMPLIDO` |
| `gatekeeper` | `gatekeeper: enroll=10000000/10000000 wrong=10000000/10000000 tracks=10000000/10000000 wipe=10000000/10000000 th=10000000/10000000 => CUMPLIDO` |
| `inactivity` | `inactivity: timeout=10000000/10000000 touch=10000000/10000000 evict=10000000/10000000 => CUMPLIDO` |
| `lock_capabilities` | `lock_capabilities: rows=7 invariantes_ok=true => CUMPLIDO` |
| `pate` | `pate: honest=10000000/10000000 insert=10000000/10000000 omit=10000000/10000000 reorder=10000000/10000000 => CUMPLIDO` |
| `pin_counter` | `pin_counter: mono=10000000/10000000 throttle=10000000/10000000 wipe=10000000/10000000 reset=10000000/10000000 bfu_afu=10000000/10000000 ce=10000000/10000000 => CUMPLIDO` |
| `powercut` | `powercut: wbv_breaks=10000000/10000000 vbw_preserves=10000000/10000000 wbv_nocut=10000000/10000000 vbw_nocut=10000000/10000000 => CUMPLIDO` |
| `rpmb` | `rpmb: mono=10000000/10000000 bad_mac=10000000/10000000 replay=10000000/10000000 honest=10000000/10000000 rt=10000000/10000000 => CUMPLIDO` |
| `weaver` | `weaver: indep=10000000/10000000 th=10000000/10000000 wipe=10000000/10000000 enroll=10000000/10000000 => CUMPLIDO` |

## BFS

| Modelo | states | transitions | violations | elapsed_ms |
|--------|-------:|------------:|-----------:|-----------:|
| pin_counter | 19 | 30 | 0 | 0 |
| rpmb | 32 | 332 | 0 | 1 |
| gatekeeper | 15 | 24 | 0 | 0 |

## Mutantes

**7/7** detectados.

## Powercut (framing)

Invariante modelado: **contabilidad exacta** (`fails == intentos_efectivos`).

- **WBV (write-before-verify):** ante power-cut tras el write, el invariante
  falla por **sobreconteo** (el disco avanzó sin intento efectivo). Eso es el
  **lado seguro** respecto de subconteo/elusión del contador: el modelo no
  afirma que WBV sea "inseguro", sino que no preserva contabilidad exacta.
- **VBW (verify-before-write):** preserva el invariante **solo bajo el
  supuesto** de que el resultado de un intento interrumpido **nunca se
  observa**. Si el resultado pudiera observarse antes de la escritura, VBW
  sería el orden vulnerable; **ese caso no está representado** en el modelo.
- Los **1e7 trials** de `powercut` **repiten el mismo caso determinista**
  (el seed solo descarta un `u64`); no exploran diversidad de fallos.

Esto **no** se vende como hallazgo de seguridad sobre hardware real.

Elapsed measure global (transcript): **671714 ms**.

## Fuzzing (smoke)

Ver `evidence/fuzz_smoke.txt` (corrida previa: 706567 runs / 21 s, 0 crashes).

## Kani

**NO VIABLE** en esta caja (no instalado; declarado explícitamente).

## Transcript

Ver `evidence/full_measure.raw.txt` y el campo `raw_transcript` del JSON.
