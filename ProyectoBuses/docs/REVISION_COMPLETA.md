# Revision completa del proyecto `ms-security`

## 1) Alcance revisado

Se revisaron componentes de API, autenticacion/autorizacion y configuracion del proyecto Spring Boot:

- Controladores en `src/main/java/com/ysrm/ms_security/Controllers`
- Interceptor y configuracion en `src/main/java/com/ysrm/ms_security/Config`
- Servicios principales en `src/main/java/com/ysrm/ms_security/Services`
- Configuracion en `src/main/resources/application.properties`
- Dependencias en `pom.xml`

## 2) Estado funcional actual

El software implementa un microservicio de seguridad con:

- Registro, login con 2FA por codigo y recuperacion de contrasena
- OAuth social (GitHub, Google, Microsoft)
- Emision y validacion de JWT + sesion persistida en MongoDB
- Gestion CRUD de usuarios, roles, perfiles y sesiones
- Asignacion de roles a usuarios y consulta de usuarios con roles
- Autorizacion por permisos granulares para rutas protegidas

## 3) Endpoints principales detectados

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

### `ProfileController` (`/profiles`)

- `GET /profiles`
- `GET /profiles/{id}`
- `POST /profiles`
- `PUT /profiles/{id}`
- `DELETE /profiles/{id}`

### `SessionController` (`/sessions`)

- `GET /sessions`
- `GET /sessions/{id}`
- `POST /sessions`
- `PUT /sessions/{id}`
- `DELETE /sessions/{id}`

### `UserRoleController` (`/user-role`)

- `POST /user-role/user/{userId}/role/{roleId}`
- `DELETE /user-role/{userRoleId}`
- `PUT /user-role/user/{userId}`

### `UserQueryController` (`/users-query`)

- `GET /users-query?q={texto}`

## 4) Seguridad y autorizacion observadas

- Todas las rutas excepto `/security/**` exigen header `Authorization: Bearer <token>` por `JwtAuthInterceptor`.
- Se valida:
  - JWT vigente
  - sesion en BD
  - que la sesion no sea parcial (2FA pendiente)
  - expiracion de sesion
- Permisos granulares por modulo/accion en `EndpointPermissionResolver` + `AuthorizationService` para:
  - `/roles/**`
  - `/user-role/**`
  - `/users/**`
  - `/users-query/**`
- Actualmente `/profiles/**` y `/sessions/**` requieren JWT, pero no permiso granular por modulo.

## 5) Hallazgos relevantes (priorizados)

### Criticos

1. Exposicion de credenciales en configuracion:
   - `application.properties` contiene URI de MongoDB con usuario/contrasena en texto plano.
   - Riesgo alto de compromiso de entorno y datos.

### Altos

1. Secreto JWT debil en `application.properties` (`jwt.secret=fbc`):
   - Demasiado corto y facil de comprometer.
2. Endpoints de OAuth unlink (`/security/oauth/*/unlink/{userId}`) son publicos:
   - Estan bajo `/security/**`, por lo tanto no pasan por el interceptor.
   - Permite desvincular cuentas sociales sin JWT si se conoce `userId`.

### Medios

1. Controladores CRUD (`users`, `profiles`, `sessions`) devuelven `null` o `void` sin codigos HTTP explicitos para no encontrado.
2. `UserController.removeProfile/removeSession` valida que existan usuario y recurso, pero no que pertenezcan entre si.
3. `SecurityController.login` recibe `Map<String,String>` en vez de DTO tipado con validaciones formales.

## 6) Artefactos de prueba creados

Se generaron archivos en `docs/postman/`:

- `ms-security.postman_collection.json` (coleccion importable en Postman, con tests por endpoint)
- `ms-security.postman_environment.json` (entorno local con variables)
- `ms-security.postman_collection.xml` (version XML de referencia de la misma cobertura)

Cobertura incluida: 44 requests (todos los endpoints detectados en controladores).

## 7) Recomendaciones inmediatas

1. Mover secretos a variables de entorno y rotar credenciales expuestas.
2. Proteger `unlink` de OAuth con JWT y validacion de ownership.
3. Estandarizar respuestas HTTP para errores (`404`, `400`, `409`) en todos los CRUD.
4. Agregar permisos granulares para `/profiles/**` y `/sessions/**`.
5. Agregar pruebas automatizadas de integracion para flujos de seguridad (login + 2FA + autorizacion por permisos).

