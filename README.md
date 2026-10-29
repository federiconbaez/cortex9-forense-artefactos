# cortex9-forense-artefactos

**ES:** Modelos formales verificables de artefactos de forense móvil:
contador de intentos de PIN (BFU/AFU + throttle exponencial + wipe),
protocolo RPMB anti-rollback (write counter monotónico + HMAC),
Gatekeeper/Weaver (HMAC throttle + persistencia RPMB) y tabla de
capacidades de extracción por estado de bloqueo.

**EN:** Verifiable formal models of mobile-forensics artifacts: PIN attempt
counter (BFU/AFU), RPMB anti-rollback protocol, Gatekeeper/Weaver HMAC
throttle, and a lock-state extraction-capability table.

## Qué es / qué no es

| Es | No es |
|----|-------|
| Simulador de protocolo + propiedades medidas | Receta para romper un teléfono |
| Máquina de estados del contador de PIN | Cómo eludir el contador real |
| RPMB autenticado con tests anti-rollback | Interceptar eMMC/UFS o clonar RPMB |
| Gatekeeper a nivel de mensajes HMAC | Atacar TEE / Weaver / Secure Enclave |
| Catálogo público BFU/AFU/wipe | Exploits, N-day, agentes extractores |

Nivel: **modelo / amenaza / propiedad**. La tesis académica cita este repo
como evidencia de implementación; lo operativo contra dispositivos concretos
está fuera de alcance (ver `docs/AMENAZA.md`, `docs/FUENTES.md`).

## Artefactos

| Módulo | Propiedades medidas | Semilla | Umbral |
|--------|---------------------|---------|--------|
| `pin_counter` | monotonía, throttle 2^n, wipe, reset, BFU→AFU, CE solo en AFU | `0xC09F02E` | 100/100 (por construcción) |
| `rpmb` | write counter +1, BadMac sin mutar, replay rechazado, escritura honesta, roundtrip | `0xC09F0B1` | 100/100 (por construcción) |
| `gatekeeper` | enroll/verify, rechazo, RPMB tracks fails, wipe deniega, throttle | `0xC096A7E` | 100/100 (por construcción) |
| `lock_capabilities` | CE⊂AFU, NAND=ciphertext, wipe limpia usuario, RPMB persiste, catálogo bien formado | estático | 5/5 invariantes |

"Por construcción" = el corpus es el propio modelo. No se afirma nada sobre
hardware real. Umbrales en `docs/PREREGISTRO.md` (fijados antes de medir).

## Reproducir

```bash
cargo test --workspace
cargo run --bin forense-artefactos -- measure
cargo run --bin forense-artefactos -- catalog
```

Sin crates externos (SHA-256/HMAC propios, validados contra FIPS 180-4 y
RFC 4231). `RUSTUP_TOOLCHAIN=stable`.

## CI

`.github/workflows/ci.yml`: `fmt` + `clippy -D warnings` + `cargo test` +
reproducción de `measure` + `catalog`. Tiene que quedar verde. Un skip
silencioso cuenta como falla: no hay `#[ignore]` ni `continue-on-error`.

## Límites

- No se mide ningún dispositivo físico.
- No se incluyen payloads, offsets ni procedimientos de extracción.
- El catálogo de capacidades es abstracto (literatura pública); no es un
  inventario de un laboratorio concreto.
- Un umbral no alcanzado se publica como **NO CUMPLIDO** (el binario
  `measure` sale ≠ 0).

License: Apache-2.0
