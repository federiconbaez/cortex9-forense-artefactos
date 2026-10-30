# Architecture

```mermaid
flowchart TB
  CLI[fa-cli]
  CORE[fa-core traits/crypto/rng]
  CHK[fa-checker BFS/DFS/DOT]
  MOD[fa-models PIN RPMB GK ...]
  PATE[fa-pate PATE-FNBR]
  CLI --> CORE
  CLI --> CHK
  CLI --> MOD
  CLI --> PATE
  CHK --> CORE
  MOD --> CORE
  MOD --> CHK
  PATE --> CORE
```

## Crates

| Crate | Rol |
|-------|-----|
| `fa-core` | `Model`/`State`/`Action`/`Property`/`Mutant`, crypto, RNG, prereg |
| `fa-checker` | exploración, contraejemplos, DOT |
| `fa-models` | mecanismos + mutantes + adapters pin/rpmb |
| `fa-pate` | transcripción hash-encadenada |
| `fa-cli` | `fa` / `forense-artefactos` / `fa-bench` |

MSRV: **1.85** (workspace `rust-version`).
