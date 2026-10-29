# Preregistro de semillas y umbrales (v2 — expansión 5× órdenes)

Fijado **antes** de la medición a escala (2026-10-29 ART, commit de este
archivo). Cualquier cambio posterior se publica como post-hoc y **no**
cuenta como cumplimiento del umbral original.

## Escala

| Modo | Trials por artefacto Monte-Carlo | Dónde corre |
|------|----------------------------------:|-------------|
| `ci` | 10_000 | GitHub Actions (reproducible, <2 min) |
| `full` | **10_000_000** (≥ 5 órdenes vs v1=100) | caja / evidencia versionada |

## Semillas (fijas, no se cambian post-hoc)

| Artefacto | Semilla | Constante |
|-----------|--------:|-----------|
| `pin_counter` MC | `0xC09_F02E` | `PIN_SEED` |
| `rpmb` MC | `0xC09_F0B1` | `RPMB_SEED` |
| `gatekeeper` MC | `0xC09_6A7E` | `GK_SEED` |
| `weaver` MC | `0xC09_WEA7` | `WEAVER_SEED` |
| `fbe_keys` MC | `0xC09_FBE1` | `FBE_SEED` |
| `apple_dp` MC | `0xC09_ADP1` | `ADP_SEED` |
| `inactivity` MC | `0xC09_IDLE` | `IDLE_SEED` |
| `avb_rollback` MC | `0xC09_AVB1` | `AVB_SEED` |
| `powercut` MC | `0xC09_PWR1` | `PWR_SEED` |
| `pate` MC | `0xC09_PATE` | `PATE_SEED` |
| mutantes (orfoldo) | `0xC09_MUT1` | `MUT_SEED` |

## Umbrales Monte-Carlo (modo `full`)

Todos: **10_000_000 / 10_000_000** propiedades OK, etiqueta **por construcción**
salvo que se indique lo contrario. Un fallo ⇒ **NO CUMPLIDO**.

| Artefacto | # propiedades | Umbral full |
|-----------|--------------:|-------------|
| pin_counter | 6 | 1e7/1e7 |
| rpmb | 5 | 1e7/1e7 |
| gatekeeper | 5 | 1e7/1e7 |
| weaver | 4 | 1e7/1e7 |
| fbe_keys | 4 | 1e7/1e7 |
| apple_dp | 3 | 1e7/1e7 (catálogo+MC) |
| inactivity | 3 | 1e7/1e7 |
| avb_rollback | 3 | 1e7/1e7 |
| powercut | 2 escenarios × invariante | write-before-verify **NO** preserva; verify-before-write **SÍ** (demostrado) |
| pate | 4 | 1e7/1e7 |
| lock_capabilities | 5 invariantes | 5/5 |

## Model checking exhaustivo (BFS)

Límites de espacio de estados **declarados** (no se suben después de medir):

| Modelo | Acotación | Umbral |
|--------|-----------|--------|
| pin_counter | `max_fails≤5`, throttle discretizado a `{0,1}` (ventana abierta/cerrada), estados BFU/AFU/Wiped | explorar **todos** los alcanzables; 0 violaciones |
| rpmb | `n_blocks=2`, `write_counter≤8`, datos abstractos `{0,1}` | todos alcanzables; 0 violaciones de mono/auth/anti-rollback |
| gatekeeper | `max_fails≤4`, RPMB addr fija, secreto abstracto `{0,1}` | todos alcanzables; 0 violaciones |

Se reportan: estados explorados, transiciones, tiempo (ms), violaciones.

## Mutantes (sensibilidad del checker)

Para cada propiedad crítica, ≥1 variante intencionalmente rota. Umbral:
**detectados / total_mutantes == 100%**. Si el checker no detecta un mutante,
se publica **NO CUMPLIDO** (el 100/0 "por construcción" solo vale si el
test es sensible).

Mutantes preregistrados (IDs estables):

1. `pin_mono_broken` — fails no incrementa en rechazo
2. `pin_throttle_flat` — throttle constante 0
3. `pin_no_wipe` — nunca pasa a Wiped
4. `rpmb_accept_bad_mac` — ignora MAC inválido
5. `rpmb_accept_replay` — acepta write_counter viejo
6. `gk_skip_rpmb_persist` — verify no persiste fails en RPMB
7. `pwr_wbf_claimed_safe` — el modelo write-before-verify afirma preservar (debe fallar el check de preservación)

## Fuzzing / formal

- `cargo-fuzz` (libFuzzer): **intentar** targets sobre `hmac_sha256`,
  `PinCounter::attempt`, `RpmbDevice::authenticated_write`. Si el toolchain
  de la caja no permite nightly/libFuzzer, se declara **NO VIABLE** en
  README (no se omite en silencio).
- Kani: **no instalado** en la caja al momento del preregistro → se declara
  **NO VIABLE** salvo que se logre instalar antes de medir; si no, README
  lo dice.

## Evidencia

- `evidence/FULL_MEASURE.md` + `evidence/full_measure.json` con hashes SHA-256
  del binario y del JSON, comando exacto, tiempos, conteos.
- CI corre modo `ci` (10k). La corrida `full` (1e7) vive en evidencia
  versionada, no en el critical path de Actions.

## Mapping tesis (capítulos)

| Módulo | Capítulos tesis |
|--------|-----------------|
| pin_counter, inactivity | 7 (BFU/AFU), 11 (contador) |
| rpmb, powercut | 11, 12 (RPMB / anti-rollback) |
| gatekeeper, weaver | 12, 13 (TEE / Gatekeeper / Weaver) |
| fbe_keys, apple_dp, lock_capabilities | 7, 13 |
| avb_rollback | 19 (cadena de confianza / rollback) |
| pate | 19 (atestación de extracción / PATE-FNBR) |
