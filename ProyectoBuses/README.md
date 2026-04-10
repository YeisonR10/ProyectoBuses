# ms-security

Microservicio Spring Boot para autenticacion, autorizacion y gestion basica de usuarios/roles sobre MongoDB.

## Que hace actualmente el software

El servicio expone APIs para:

- Registro de usuarios con validacion de politica de contrasena
- Login con correo/contrasena + flujo de 2FA por codigo enviado por email
- Recuperacion de contrasena con token temporal
- Login social por OAuth (GitHub, Google y Microsoft)
- Emision y validacion de JWT con sesion persistida/revocable en base de datos
- Gestion CRUD de usuarios, roles, perfiles y sesiones
- Asignacion de roles a usuarios y consulta de usuarios con sus roles
- Autorizacion por permisos granulares en endpoints protegidos

## Modulos principales

- `security`: autenticacion, 2FA, recuperacion y OAuth
- `users`: gestion de usuarios y asociaciones con perfiles/sesiones
- `roles`: gestion de roles y permisos
- `user-role`: asignacion y actualizacion de roles por usuario
- `profiles`: CRUD de perfiles
- `sessions`: CRUD de sesiones
- `users-query`: listado de usuarios con sus roles

## Endpoints principales por controlador

### `SecurityController` (`/security`)

- `POST /security/register`
- `POST /security/login`
- `POST /security/2fa/verify`
- `POST /security/2fa/resend/{sessionId}`
- `DELETE /security/2fa/session/{sessionId}`
- `POST /security/password/forgot`
- `POST /security/password/reset`
- `GET /security/oauth/github/url`
- `GET /security/oauth/google/url`
- `GET /security/oauth/microsoft/url`
- `GET /security/oauth/github/callback`
- `GET /security/oauth/google/callback`
- `GET /security/oauth/microsoft/callback`
- `DELETE /security/oauth/github/unlink/{userId}`
- `DELETE /security/oauth/google/unlink/{userId}`
- `DELETE /security/oauth/microsoft/unlink/{userId}`

### `UserController` (`/users`)

- `GET /users`
- `GET /users/{id}`
- `POST /users`
- `PUT /users/{id}`
- `DELETE /users/{id}`
- `POST /users/{userId}/profile/{profileId}`
- `DELETE /users/{userId}/profile/{profileId}`
- `POST /users/{userId}/session/{sessionId}`
- `DELETE /users/{userId}/session/{sessionId}`

### `RoleController` (`/roles`)

- `GET /roles`
- `GET /roles/{id}`
- `POST /roles`
- `PUT /roles/{id}`
- `PUT /roles/{id}/permissions`
- `DELETE /roles/{id}`

### Otros controladores

- `ProfileController` (`/profiles`): CRUD completo
- `SessionController` (`/sessions`): CRUD completo
- `UserRoleController` (`/user-role`): asignar/remover/reemplazar roles
- `UserQueryController` (`/users-query`): listado con filtro `q`

## Seguridad de acceso

- Rutas excluidas del interceptor JWT: `/security/**` y `/error`
- Rutas protegidas: el resto de endpoints exige `Authorization: Bearer <token>`
- Validaciones de sesion: token JWT valido + sesion vigente en BD
- Permisos granulares por modulo/accion en:
  - `/roles/**`
  - `/user-role/**`
  - `/users/**`
  - `/users-query/**`

## Pruebas en Postman

Se incluyeron artefactos en `docs/postman`:

- `docs/postman/ms-security.postman_collection.json` (importable directamente en Postman)
- `docs/postman/ms-security.postman_environment.json`
- `docs/postman/ms-security.postman_collection.xml` (representacion XML equivalente)

La coleccion cubre 44 requests (todos los endpoints de los controladores detectados) y contiene scripts de test basicos por request.

## Revision tecnica completa

Se documento una revision detallada en:

- `docs/REVISION_COMPLETA.md`

Incluye hallazgos, riesgos y recomendaciones priorizadas.

## Ejecucion local

Requisitos:

- Java 17
- MongoDB accesible

Comandos:

```bash
./mvnw spring-boot:run
./mvnw test
```

En Windows PowerShell:

```powershell
.\mvnw.cmd spring-boot:run
.\mvnw.cmd test
```

## Configuracion relevante

Archivo: `src/main/resources/application.properties`

- `spring.data.mongodb.uri`
- `spring.data.mongodb.database`
- `server.port`
- `jwt.secret`
- `jwt.expiration`
- `captcha.enabled`
- `captcha.secret`
- `security.otp.expiration-ms`
- `security.reset.expiration-ms`
- `security.reset.base-url`
- `github.client-*`, `google.client-*`, `microsoft.client-*`

## Estado de pruebas en este entorno

Se ejecutaron pruebas con Maven Wrapper y se generaron reportes en `target/surefire-reports`.
