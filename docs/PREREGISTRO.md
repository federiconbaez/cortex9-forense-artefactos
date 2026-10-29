# Preregistro de semillas y umbrales

Fijado **antes** de la primera medición (2026-10-29). Cualquier cambio
posterior se publica como post-hoc y no cuenta como cumplimiento del
umbral original.

| Artefacto        | Semilla     | Trials | Umbral                                      | Etiqueta            |
|------------------|------------:|-------:|---------------------------------------------|---------------------|
| `pin_counter`    | `0xC09F02E` |    100 | 100/100 en 6 propiedades                    | por construcción    |
| `rpmb`           | `0xC09F0B1` |    100 | 100/100 en 5 propiedades                    | por construcción    |
| `gatekeeper`     | `0xC096A7E` |    100 | 100/100 en 5 propiedades                    | por construcción    |
| `lock_capabilities` | (catálogo estático) | 1 | 5 invariantes verdaderos | por construcción |

"Por construcción" = el corpus es el propio modelo formal; un 100/0 sobre
ese corpus demuestra que las propiedades se cumplen en el simulador, no
que un dispositivo real las cumpla. Los resultados sobre hardware real
están **fuera de alcance** de este repo.

Reproducir:

```bash
cargo test --workspace
cargo run --bin forense-artefactos -- measure
```
