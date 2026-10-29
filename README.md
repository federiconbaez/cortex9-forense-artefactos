# cortex9-forense-artefactos

**ES:** Modelos formales verificables de artefactos de forense móvil
(PIN/BFU/AFU, RPMB, Gatekeeper/Weaver, FBE, Data Protection, AVB, PATE-FNBR),
con Monte-Carlo a **10⁷** trials, BFS exhaustivo acotado y mutantes de
sensibilidad.

**EN:** Verifiable formal models of mobile-forensics artifacts with 1e7-trial
Monte-Carlo, bounded exhaustive BFS, and intentional-mutant sensitivity checks.

## Qué es / qué no es

| Es | No es |
|----|-------|
| Simuladores de protocolo + propiedades medidas | Receta para romper un teléfono |
| Contador de PIN / RPMB / Gatekeeper / Weaver | Eludir contador o RPMB reales |
| FBE CE/DE, idle AFU→BFU, AVB rollback, PATE | Exploits, N-day, agentes extractores |
| Power-cut: WBV rompe / VBW preserva (demostrado) | Ataque a hardware |

Nivel: **modelo / amenaza / propiedad**. Ver `docs/AMENAZA.md`, `docs/MODELO.md`.

## Escala (v2)

| Modo | Trials | Dónde |
|------|-------:|-------|
| `ci` | 10_000 | GitHub Actions |
| `full` | **10_000_000** | `evidence/FULL_MEASURE.md` (versionado) |

Preregistro (semillas/umbrales **antes** de medir): `docs/PREREGISTRO.md`.

## Resultados medidos (full, por construcción)

| Artefacto | Trials / estados | Resultado |
|-----------|------------------:|-----------|
| pin_counter | 1e7 × 6 props | CUMPLIDO |
| rpmb | 1e7 × 5 props | CUMPLIDO |
| gatekeeper | 1e7 × 5 props | CUMPLIDO |
| weaver | 1e7 × 4 props | CUMPLIDO |
| fbe_keys | 1e7 × 4 props | CUMPLIDO |
| apple_dp | 1e7 × 3 props | CUMPLIDO |
| inactivity | 1e7 × 3 props | CUMPLIDO |
| avb_rollback | 1e7 × 3 props | CUMPLIDO |
| powercut | 1e7 × 4 checks | CUMPLIDO |
| pate (PATE-FNBR) | 1e7 × 4 props | CUMPLIDO |
| lock_capabilities | 5 invariantes | CUMPLIDO |
| BFS pin / rpmb / gk | 19 / 32 / 15 estados | 0 violaciones |
| mutantes | 7/7 detectados | CUMPLIDO |
| fuzz smoke | 706567 runs / 21s | 0 crashes |
| Kani | — | **NO VIABLE** (no instalado) |

Hashes y transcript: `evidence/FULL_MEASURE.md`, `evidence/full_measure.json`.
Elapsed full measure: **671714 ms**.

## Reproducir

```bash
cargo test --workspace
cargo run --release --bin forense-artefactos -- all --mode ci
# full (≈11 min release):
cargo run --release --bin forense-artefactos -- all --mode full
# fuzz (nightly + g++):
cargo +nightly fuzz run hmac_pin_rpmb -- -max_total_time=20
```

Sin crates de runtime en la lib (SHA-256/HMAC propios; FIPS/RFC vectors).
Fuzz usa `libfuzzer-sys` solo bajo `fuzz/`.

## CI

`.github/workflows/ci.yml`: fmt + `clippy -D warnings` + `cargo test` +
`all --mode ci` + catalog. Sin `#[ignore]` ni `continue-on-error`.

## Mapping tesis

Capítulos **7, 11, 12, 13, 19** — detalle en `docs/MODELO.md`.

## Límites

- No se mide hardware real.
- "Por construcción" = corpus = propio modelo; mutantes demuestran sensibilidad.
- Umbral no alcanzado ⇒ **NO CUMPLIDO** (exit ≠ 0).
- Kani no viable en esta caja (declarado).

License: Apache-2.0
