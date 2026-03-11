# Primera entrega - Cobertura HU-ENTR-1-006 a HU-ENTR-1-013

Fecha: 2026-03-11
Proyecto: `ms-security`

## Objetivo de la entrega
Implementar y evidenciar autenticacion y seguridad base para las HU:
- `HU-ENTR-1-006` GitHub OAuth
- `HU-ENTR-1-007` Registro tradicional
- `HU-ENTR-1-008` Login tradicional
- `HU-ENTR-1-009` Control de sesion y autorizacion por URL
- `HU-ENTR-1-010` reCAPTCHA en login
- `HU-ENTR-1-011` reCAPTCHA en recuperacion
- `HU-ENTR-1-012` Verificacion 2FA por codigo
- `HU-ENTR-1-013` Solicitud de recuperacion de contrasena

## Alcance funcional por HU (backend)

### HU-ENTR-1-006 - Autenticacion con GitHub
**Backend requerido**
- Endpoint para iniciar flujo OAuth GitHub.
- Callback para intercambio `code -> access_token`.
- Lectura de `email`, `name`, `avatar_url`, `login`.
- Logica:
  - Si email existe: autentica.
  - Si no existe: crea usuario.
  - Si email privado/no disponible: marcar estado `PENDING_EMAIL` y solicitar correo alterno.
- Vinculacion/desvinculacion cuenta GitHub a usuario existente.

**DoD**
- API de callback funcional con pruebas de servicio (mock HTTP a GitHub).
- Persistencia de `githubId` y `githubUsername`.
- Caso de email privado cubierto con respuesta controlada.

### HU-ENTR-1-007 - Registro con email y contrasena
**Backend requerido**
- Endpoint `POST /auth/register`.
- Validaciones:
  - Email unico.
  - Contrasena fuerte: minimo 8, mayuscula, minuscula, numero, especial.
  - Confirmacion de contrasena.
- Hash de contrasena (nunca texto plano).
- Envio de email de confirmacion.

**DoD**
- Respuestas de error de validacion estandarizadas.
- Pruebas unitarias de politicas de contrasena.
- Prueba de persistencia con hash.

### HU-ENTR-1-008 - Inicio de sesion con email y contrasena
**Backend requerido**
- Endpoint `POST /auth/login`.
- Validacion de credenciales contra hash almacenado.
- Mensaje generico ante error: `Email o contrasena incorrectos`.
- Creacion de token de sesion unico.

**DoD**
- Login exitoso retorna token + metadata minima.
- Login fallido no filtra si fallo email o contrasena.
- Pruebas de exito/fallo.

### HU-ENTR-1-009 - Control de sesion y prevencion de inyecciones URL
**Backend requerido**
- Filtro/JWT middleware para endpoints protegidos.
- Validar token, expiracion y firma.
- Incluir en token: `userId`, `rol`, `iat`, `exp`.
- Autorizacion por rol/ruta (403 sin permiso).
- Proteccion de rutas de administracion.

**DoD**
- Endpoints protegidos rechazan token ausente/invalido.
- Endpoints admin requieren rol autorizado.
- Pruebas de autorizacion 401/403.

### HU-ENTR-1-010 - reCAPTCHA v3 en login
**Backend requerido**
- Endpoint de login debe recibir `recaptchaToken`.
- Validacion server-to-server con Google `siteverify`.
- Rechazar login si score/estado no cumple politica.

**DoD**
- Integracion configurable por propiedades (`secret`, `threshold`).
- Pruebas con cliente HTTP mockeado.

### HU-ENTR-1-011 - reCAPTCHA en recuperacion de contrasena
**Backend requerido**
- Endpoint de recuperacion exige `recaptchaToken`.
- Misma validacion backend que HU-010.

**DoD**
- Recuperacion falla con captcha invalido.
- Pruebas de validacion de captcha.

### HU-ENTR-1-012 - Validacion de codigo 2FA
**Backend requerido**
- Flujo en 2 pasos:
  1. Credenciales validas -> generar sesion parcial + OTP 6 digitos por email.
  2. `POST /auth/2fa/verify` valida OTP y emite token final.
- OTP numerico (6), expiracion, maximo 3 intentos.
- Reenvio de codigo con control de frecuencia.
- Si cierra/expira sesion parcial: invalidar.

**DoD**
- 3 intentos fallidos invalidan sesion parcial.
- OTP expirado no autentica.
- Pruebas de intentos, expiracion y exito.

### HU-ENTR-1-013 - Solicitud de recuperacion de contrasena
**Backend requerido**
- Endpoints:
  - `POST /auth/password/forgot`
  - `POST /auth/password/reset`
- Mensaje generico siempre: `Si el email existe, recibira instrucciones de recuperacion`.
- Si existe email: generar token unico valido 30 min y enviar enlace.

**DoD**
- No revelar existencia de email.
- Token de recuperacion de un solo uso y expiracion 30 min.
- Pruebas de token valido/expirado/reusado.

## Backlog tecnico recomendado para esta primera entrega
1. Refactor `SecurityService` para soportar login en dos pasos (credenciales + 2FA).
2. Mejorar `JwtService` para firmar con clave de propiedades (`jwt.secret`) y claims de rol.
3. Incorporar capa de validaciones (`PasswordPolicyService`, `CaptchaService`).
4. Incorporar entidad/token para recuperacion de contrasena.
5. Integrar proveedor de correo (SMTP o servicio transaccional) con entorno `dev` mock.
6. Crear pruebas unitarias y de integracion para 401/403/login/registro/recuperacion.

## Evidencias que debes adjuntar en la entrega
- Capturas/video respetando mockups del documento.
- Coleccion Postman/Insomnia con casos exito/fallo por HU.
- Reporte de pruebas (`mvn test`) y cobertura minima por modulo auth.
- Tabla HU -> endpoint -> evidencia (captura o request/response).
- Link al tablero de trabajo con asignaciones por integrante.

## Riesgos y mitigacion
- OAuth GitHub requiere app registrada: crear credenciales por ambiente (`dev`, `qa`).
- reCAPTCHA requiere frontend para token: agregar modo `test` controlado en backend.
- Email puede fallar por SMTP: usar proveedor sandbox al inicio.
- Sin control de intentos: riesgo de fuerza bruta; aplicar rate limit por IP/email.

## Criterio de aceptacion de la primera entrega (checklist)
- [ ] HU-006 implementada y probada con cuenta GitHub real.
- [ ] HU-007 implementada con politicas de contrasena y email unico.
- [ ] HU-008 login tradicional con mensaje de error generico.
- [ ] HU-009 proteccion JWT + autorizacion por rol en rutas sensibles.
- [ ] HU-010/011 captcha validado en backend.
- [ ] HU-012 2FA por email con 3 intentos maximos.
- [ ] HU-013 recuperacion con token 30 min y respuesta generica.
- [ ] Mockups respetados y evidenciados.
- [ ] Plan de trabajo de segunda entrega publicado y compartido.

