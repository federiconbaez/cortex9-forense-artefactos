# Evidencia FULL measure (v2)

Medido: **2026-10-29 17:29:07 ART** (America/Buenos_Aires).

## Contrato

- Umbrales/semillas: `docs/PREREGISTRO.md` v2, commit **antes** de esta medición.
- Comando exacto:
  ```
  cargo build --release
  ./target/release/forense-artefactos all --mode full
  ```
- Trials Monte-Carlo: **10_000_000** por artefacto (≥5 órdenes vs v1=100).
- Etiqueta: **por construcción** (corpus = propio modelo).
- Mutantes: sensibilidad del checker; 7/7 detectados.

## Hashes

| Artefacto | SHA-256 |
|-----------|---------|
| `target/release/forense-artefactos` | `7ef89f72f5c0618dfe9dc261e6d11f1351fc8115d7c707b24faeabdb649430c0` |
| `evidence/full_measure.json` | `f279b34138b472cc51dcfb812634aad0a92aff2f9bf84aa4233aee04e0078891` |
| `evidence/full_measure.raw.txt` | `001deba16188796bc34201e7ee8547fdeb4e852d4d7a220f731aa994ca2e5d2c` |

## Resultados (resumen)

| Artefacto | Resultado |
|-----------|-----------|
| pin_counter | 1e7/1e7 × 6 props CUMPLIDO |
| rpmb | 1e7/1e7 × 5 props CUMPLIDO |
| gatekeeper | 1e7/1e7 × 5 props CUMPLIDO |
| weaver | 1e7/1e7 × 4 props CUMPLIDO |
| fbe_keys | 1e7/1e7 × 4 props CUMPLIDO |
| apple_dp | 1e7/1e7 × 3 props CUMPLIDO |
| inactivity | 1e7/1e7 × 3 props CUMPLIDO |
| avb_rollback | 1e7/1e7 × 3 props CUMPLIDO |
| powercut | 1e7/1e7 × 4 checks CUMPLIDO (WBV rompe; VBW preserva) |
| pate | 1e7/1e7 × 4 props CUMPLIDO |
| lock_capabilities | 5/5 invariantes CUMPLIDO |
| BFS pin/rpmb/gk | 19/32/15 estados; 0 violaciones |
| mutantes | **7/7** detectados |

Elapsed measure global: **671714 ms** (~11.2 min).

## Transcript

Ver `evidence/full_measure.raw.txt` y el campo `raw_transcript` del JSON.

## Fuzzing (smoke)

```
cargo +nightly fuzz run hmac_pin_rpmb -- -max_total_time=20 -max_len=128
```

Resultado medido en esta caja: **706567 runs / 21 s**, cov≈191, **0 crashes**.
Transcript: `evidence/fuzz_smoke.txt`.

## Kani

**NO VIABLE** en esta expansión: Kani no está instalado en la caja y no se
instaló (peso + tiempo). Declarado explícitamente; no omitido.
