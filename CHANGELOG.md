# Changelog

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

### Declared limitations
- Adapter `Model` para gatekeeper en el checker genérico: pendiente (MC+mutantes sí).
- Kani: NO VIABLE.
- crates.io: no se publica.
