# Changelog

## [0.2.1] — 2026-10-30

### Fixed (Ben audit)
- BFS pin/rpmb: transición = cada acción (incl. no-ops). Conteos restaurados a
  **19/30** y **32/332** (equiv. oráculo v0.1 e593662). Causa: faltaban wipe-bad
  (pin) y badmac×bit+replay (rpmb); no era dedupe.
- Adapter `Model` Gatekeeper: **CUMPLIDO** (15/24, match legacy).
- Tests: 43 → **49** (6 legacy/equiv BFS; explica pérdida de 3 `model_check_*`
  monolito + ganancia `explore_tiny` en el refactor = −2 neto vs 45 monolito).
- `fa-bench` like-for-like: BFS v0.1 vs v0.2 + MC 1e6 compartido; metas ≥50k
  st/s declaradas conservadoras (ratio es la cifra útil).

### Docs
- README / CHANGELOG / ARCHITECTURE / CONTRIBUTING / NOTICE: identidad sin tilde
  (`Federico Nicolas Baez Rizzo`); GK ya no pendiente.

## [0.2.0] — 2026-10-29

### Added
- Workspace modular: `fa-core`, `fa-checker`, `fa-models`, `fa-pate`, `fa-cli`.
- Checker genérico BFS/DFS con DOT export (`fa check`, `fa graph`).
- PATE-FNBR usable: `fa pate init|append|seal|verify|report`.
- ≥1 mutante por modelo (12/12).
- Bench `fa-bench` (estados/s, pate verify 1e5/1e6).
- Docs: ARCHITECTURE, CONTRIBUTING, SECURITY, PREREGISTRO_v0.2.

### Changed
- Semver 0.2.0; CLI principal `fa` (alias `forense-artefactos`).
- Framing powercut (contabilidad; no hallazgo de seguridad) conservado.

### Declared limitations (al release; corregidas en 0.2.1 donde aplica)
- Adapter `Model` gatekeeper: estaba pendiente → **cerrado en 0.2.1**.
- BFS pin/rpmb transitions divergían de v0.1 (29/168) → **cerrado en 0.2.1**.
- Kani: NO VIABLE.
- crates.io: no se publica.
