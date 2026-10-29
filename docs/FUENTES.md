# Fuentes públicas (leídas / citadas)

Ninguna fuente se usa para construir una receta operativa. Solo alimentan
el modelo de amenaza y la tabla de capacidades.

- Android Open Source Project — File-Based Encryption (FBE), Direct Boot,
  Gatekeeper HAL, Weaver. https://source.android.com/docs/security/features/encryption
- Android Open Source Project — Gatekeeper.
  https://source.android.com/docs/security/features/authentication/gatekeeper
- JEDEC eMMC 5.1 — Replay Protected Memory Block (RPMB), §6.6.22 (especificación
  de protocolo; no se reproduce el texto normativo aquí).
- NIST FIPS 180-4 — Secure Hash Standard (SHA-256). Vectores CAVP usados en
  `src/crypto.rs`.
- RFC 4231 — Identifiers and Test Vectors for HMAC-SHA-256. Casos 1–3 en
  `src/crypto.rs`.
- Apple Platform Security — Data Protection classes, Secure Enclave overview
  (documentación pública). https://support.apple.com/guide/security/
- Literatura forense pública sobre BFU/AFU (Cellebrite / Magnet / papers
  académicos de acceso abierto): usada solo para clasificar capacidades
  abstractas en `lock_capabilities.rs`, sin procedimientos.

## Fuera de alcance (explícito)

- Eludir, congelar o reescribir el contador de PIN de un dispositivo real.
- Interceptar el bus eMMC/UFS o clonar RPMB.
- Inyectar código en TEE / StrongBox / Secure Enclave / Titan M.
- Exploits, N-day o 0-day contra un SoC, bootloader o app concreta.
- Cualquier receta que permita romper un teléfono específico.
