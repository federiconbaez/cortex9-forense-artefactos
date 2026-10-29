# Modelo de amenaza (resumen)

Atacante: perito / laboratorio con acceso físico al dispositivo y a
herramientas comerciales de extracción (cajas negras). Objetivo: obtener
evidencia CE. Barreras modeladas:

1. Estado BFU: claves CE envueltas; solo DE.
2. Contador de intentos + throttle exponencial + wipe.
3. Persistencia del contador en RPMB autenticado (anti-rollback).
4. Gatekeeper/Weaver: verificación HMAC dentro del TEE.

Este repo **demuestra las propiedades defensivas del modelo**, no cómo
saltarlas. La tesis académica cita estos artefactos como evidencia de
implementación del modelo; cualquier discusión de elusión queda a nivel
de hipótesis de amenaza, sin procedimiento.
