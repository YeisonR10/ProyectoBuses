# ms-security

Backend Spring Boot para la primera entrega de autenticacion y seguridad.

## HU cubiertas en esta base
- HU-ENTR-1-006: OAuth GitHub
- HU-ENTR-1-007: Registro con email y contrasena
- HU-ENTR-1-008: Login con email y contrasena
- HU-ENTR-1-009: Validacion JWT y proteccion de rutas
- HU-ENTR-1-010: reCAPTCHA en login
- HU-ENTR-1-011: reCAPTCHA en recuperacion
- HU-ENTR-1-012: Verificacion 2FA por codigo
- HU-ENTR-1-013: Recuperacion de contrasena

## Endpoints principales
- `POST /security/register`
- `POST /security/login`
- `POST /security/2fa/verify`
- `POST /security/2fa/resend/{sessionId}`
- `DELETE /security/2fa/session/{sessionId}`
- `POST /security/password/forgot`
- `POST /security/password/reset`
- `GET /security/oauth/github/url`
- `GET /security/oauth/github/callback`
- `DELETE /security/oauth/github/unlink/{userId}`

## Payloads basicos
### Registro
```json
{
  "name": "Ana",
  "lastName": "Lopez",
  "email": "ana@test.com",
  "password": "Abcd1234!",
  "confirmPassword": "Abcd1234!"
}
```

### Login
```json
{
  "email": "ana@test.com",
  "password": "Abcd1234!",
  "recaptchaToken": "token-opcional-en-dev"
}
```

### Verificacion 2FA
```json
{
  "sessionId": "ID_SESION_PARCIAL",
  "code": "123456"
}
```

## Configuracion relevante
Revisa `src/main/resources/application.properties`.

Variables importantes:
- `jwt.secret`
- `jwt.expiration`
- `captcha.enabled`
- `captcha.secret`
- `security.otp.expiration-ms`
- `security.reset.expiration-ms`
- `github.client-id`
- `github.client-secret`
- `github.redirect-uri`

## Notas
- En desarrollo, `captcha.enabled=false` permite probar sin Google reCAPTCHA.
- El envio de correo se deja trazado por log para facilitar demo local.
- Las rutas administrativas (`/roles`, `/user-role`, `/admin`) exigen rol `ADMIN` via JWT.
- El login devuelve `sessionId`, `maskedEmail` y tiempo restante para completar el 2FA.

## Estado de build en este entorno
No fue posible ejecutar `mvn test` aqui porque:
1. el proyecto no incluye la carpeta `.mvn/wrapper`, y
2. `mvn` no esta instalado en la terminal disponible.

Aun asi, se corrigieron errores de analisis estatico del IDE y se dejaron pruebas unitarias listas para ejecutar cuando Maven este disponible.
