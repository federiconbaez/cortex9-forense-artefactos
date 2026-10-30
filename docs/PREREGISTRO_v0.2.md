# Preregistro v0.2 — refactor workspace (ANTES de medir)

Fijado **antes** de la medición post-refactor (2026-10-29 ART).
Cualquier cambio posterior = post-hoc y no cuenta como cumplimiento.

## Semillas (heredadas de v2 + nuevas)

| Artefacto | Semilla |
|-----------|--------:|
| PIN / RPMB / GK | `0x0C09F02E` / `0x0C09F0B1` / `0x0C096A7E` |
| WEAVER / FBE / ADP / IDLE / AVB / PWR / PATE | `0x0C090EA7` / `0x0C09FBE1` / `0x0C09AD01` / `0x0C091D1E` / `0x0C090AB1` / `0x0C090911` / `0x0C090A7E` |
| mutantes | `0x0C090071` |
| pate throughput bench | `0x0C09BENC` → literal `0x0C09BE0C` |

## Monte-Carlo

| Modo | Trials |
|------|-------:|
| `ci` | 10_000 |
| `full` | 10_000_000 |

Umbral: 100% propiedades OK por artefacto, etiqueta **por construcción**.

## Mutantes

Umbral: **detectados / total == 100%**, con **≥1 mutante por modelo**:
pin, rpmb, gatekeeper, weaver, fbe, apple_dp, inactivity, avb, powercut,
lock_capabilities (≥10 mutantes).

## Benchmarks (metas preregistradas)

Hardware de la caja; publicar lo medido.

| Bench | Meta (razonable) | Notas |
|-------|------------------:|-------|
| checker BFS pin estados/s | ≥ 50_000 | release |
| pate verify 1e5 entradas/s | ≥ 20_000 | release |
| pate verify 1e6 entradas/s | ≥ 20_000 | release |
| compare v0.1 vs v0.2 pin MC 1e4 | reportar ambos ms | mismo binario harness |

Si una meta no se alcanza ⇒ **NO CUMPLIDO** (se publica el número real).

## Compatibilidad

- CLI `forense-artefactos` / `fa` conserva `measure|bfs|mutants|catalog|all`.
- Evidencia previa en `evidence/` se conserva; se agrega `evidence/v0.2_*`.

## Nota post-medición (2026-10-30, no altera umbrales)

Las metas ≥50_000 estados/s fueron **conservadoras** (cumplidas con holgura).
Para comparar refactor vs monolito usar el harness like-for-like (`fa-bench`)
y el **ratio v0.2/v0.1**, no el umbral absoluto.
