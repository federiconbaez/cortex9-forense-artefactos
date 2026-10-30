# cortex9-forense-artefactos

**v0.2.1** — Workspace modular de modelos formales de forense móvil + PATE-FNBR.

Nivel **modelo / amenaza / propiedad**. Sin recetas ni exploits contra dispositivos.

## Crates

`fa-core` · `fa-checker` · `fa-models` · `fa-pate` · `fa-cli`

## CLI útil (perito)

```bash
cargo run -p fa-cli --bin fa -- pate init EXP-001 --out case.json
cargo run -p fa-cli --bin fa -- pate append case.json \
  --kind acquire --payload ffs --timestamp 2026-10-29T18:00:00-03:00 \
  --operator "F. Baez" --tool lab-X \
  --artifact-sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
cargo run -p fa-cli --bin fa -- pate seal case.json --operator "F. Baez" --timestamp 2026-10-29T18:05:00-03:00
cargo run -p fa-cli --bin fa -- pate verify case.json
cargo run -p fa-cli --bin fa -- pate report case.json --out case.md
```

Model checking / grafos / mutantes:

```bash
cargo run -p fa-cli --bin fa -- check pin
cargo run -p fa-cli --bin fa -- graph rpmb -o rpmb.dot
cargo run -p fa-cli --bin fa -- bfs
cargo run -p fa-cli --bin fa -- mutants
cargo run -p fa-cli --bin fa -- all --mode ci
```

## Medición

Preregistro: `docs/PREREGISTRO_v0.2.md` (**antes** de medir).  
Evidencia: `evidence/` (v0.1 conservada) + `evidence/v0.2_*` + `evidence/v0.2_AUDIT.*`.

```bash
cargo run --release -p fa-cli --bin fa -- all --mode ci    # 1e4
cargo run --release -p fa-cli --bin fa-bench               # like-for-like + MC 1e6
```

### BFS (equiv. v0.1 / e593662)

| Modelo | states | transitions |
|--------|-------:|------------:|
| pin | 19 | 30 |
| rpmb | 32 | 332 |
| gatekeeper | 15 | 24 |

Transición = cada acción del modelo, incluidos no-ops. Tests: **49/49**. Mutantes: **12/12**.

## Límites

- Kani: **NO VIABLE**.
- Powercut: contabilidad exacta (WBV=sobreconteo seguro; VBW condicional); no hallazgo de seguridad.
- Metas preregistro ≥50k st/s fueron **conservadoras**; publicar ratio v0.2/v0.1.
- No se publica en crates.io.

License: Apache-2.0 · MSRV 1.85 · Author: Federico Nicolas Baez Rizzo
