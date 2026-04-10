# Plan Frontend - Integracion completa con `ms-security`

## Objetivo

Implementar en frontend los flujos de `autenticacion`, `2FA`, `recuperacion`, `OAuth` y administracion (`users`, `roles`, `profiles`, `sessions`, `user-role`, `users-query`) usando los contratos actuales del backend.

## Checklist de implementacion

- [ ] Configurar cliente HTTP base (`baseURL`, interceptores, manejo de `401/403`)
- [ ] Implementar modulo de autenticacion (registro + login + 2FA)
- [ ] Implementar modulo de recuperacion de contrasena
- [ ] Implementar login social OAuth (GitHub, Google, Microsoft)
- [ ] Implementar almacenamiento y refresco de estado de sesion frontend
- [ ] Implementar CRUD y pantallas de administracion (`users`, `roles`, `profiles`, `sessions`)
- [ ] Implementar asignacion de roles (`user-role`) y consulta avanzada (`users-query`)
- [ ] Centralizar tipados de request/response con modelos equivalentes al backend
- [ ] Cubrir pruebas E2E de flujos criticos (login+2FA, reset, oauth, permisos)

---

## 1) Configuracion base frontend

- `BASE_URL` sugerida local: `http://localhost:8081`
- Header para rutas protegidas:
  - `Authorization: Bearer <token>`
- `Content-Type`: `application/json`

Regla backend actual:

- Publico (sin JWT): `/security/**`
- Protegido (con JWT): todo lo demas

---

## 2) Flujos funcionales para UI

## 2.1 Registro

1. Formulario registro
2. `POST /security/register`
3. Si `201`, mostrar exito e ir a login
4. Si `400`, mostrar `error`

## 2.2 Login + 2FA

1. Formulario login
2. `POST /security/login`
3. Si exito, backend devuelve `sessionId` y `requires2FA=true`
4. Mostrar pantalla OTP (codigo 6 digitos)
5. `POST /security/2fa/verify`
6. Si exito, guardar `token` y entrar a app
7. Soportar:
   - reenviar codigo: `POST /security/2fa/resend/{sessionId}`
   - cancelar sesion parcial: `DELETE /security/2fa/session/{sessionId}`

## 2.3 Recuperacion de contrasena

1. Pantalla "olvide mi contrasena"
2. `POST /security/password/forgot`
3. Mostrar mensaje generico siempre
4. Pantalla reset (con `token` desde enlace)
5. `POST /security/password/reset`

## 2.4 OAuth (GitHub, Google, Microsoft)

1. Boton social en login
2. Obtener URL desde backend:
   - `GET /security/oauth/github/url`
   - `GET /security/oauth/google/url`
   - `GET /security/oauth/microsoft/url`
3. Redirigir navegador a proveedor
4. Proveedor redirige al callback backend (`/security/oauth/*/callback?code=...`)
5. Backend responde JSON con `token`
6. Frontend debe capturar token (segun estrategia de navegacion actual)

Nota: hoy el callback es backend-first. Si el frontend es SPA pura, se recomienda planear un ajuste posterior para redirigir a una ruta frontend dedicada.

---

## 3) Endpoints completos (contrato operativo)

## 3.1 `security` (publico)

- `POST /security/register`
  - body: `RegisterRequest`
  - resp ok: `{ "message": string }`
  - resp error: `{ "error": string }`

- `POST /security/login`
  - body real: `{ email, password, recaptchaToken }`
  - resp ok: `{ requires2FA, sessionId, maskedEmail, expiresInSeconds, message }`
  - resp error: `{ "error": string }`

- `POST /security/2fa/verify`
  - body: `TwoFactorVerifyRequest`
  - resp ok: `{ token, message }`
  - resp error: `{ "error": string }`

- `POST /security/2fa/resend/{sessionId}`
  - resp ok: `{ message, maskedEmail, expiresInSeconds }`
  - resp error: `{ "error": string }`

- `DELETE /security/2fa/session/{sessionId}`
  - resp ok: `{ message }`
  - resp error: `{ "error": string }`

- `POST /security/password/forgot`
  - body: `ForgotPasswordRequest`
  - resp: `{ message }` o `{ error }`

- `POST /security/password/reset`
  - body: `ResetPasswordRequest`
  - resp ok: `{ message }`
  - resp error: `{ error }`

- `GET /security/oauth/github/url`
- `GET /security/oauth/google/url`
- `GET /security/oauth/microsoft/url`
  - resp: `{ url }`

- `GET /security/oauth/github/callback?code=...&alternativeEmail=...`
  - resp ok: `{ token, githubUsername? }`
  - resp error: `{ error }`

- `GET /security/oauth/google/callback?code=...`
  - resp ok: `{ token }`
  - resp error: `{ error }`

- `GET /security/oauth/microsoft/callback?code=...`
  - resp ok: `{ token }`
  - resp error: `{ error }`

- `DELETE /security/oauth/github/unlink/{userId}`
- `DELETE /security/oauth/google/unlink/{userId}`
- `DELETE /security/oauth/microsoft/unlink/{userId}`
  - resp ok: `{ message }`
  - resp error: `{ error }`

## 3.2 `users` (protegido)

- `GET /users`
- `GET /users/{id}`
- `POST /users`
- `PUT /users/{id}`
- `DELETE /users/{id}`
- `POST /users/{userId}/profile/{profileId}`
- `DELETE /users/{userId}/profile/{profileId}`
- `POST /users/{userId}/session/{sessionId}`
- `DELETE /users/{userId}/session/{sessionId}`

## 3.3 `roles` (protegido)

- `GET /roles`
- `GET /roles/{id}`
- `POST /roles`
- `PUT /roles/{id}`
- `PUT /roles/{id}/permissions` (body: `RolePermissionsRequest`)
- `DELETE /roles/{id}`

## 3.4 `profiles` (protegido)

- `GET /profiles`
- `GET /profiles/{id}`
- `POST /profiles`
- `PUT /profiles/{id}`
- `DELETE /profiles/{id}`

## 3.5 `sessions` (protegido)

- `GET /sessions`
- `GET /sessions/{id}`
- `POST /sessions`
- `PUT /sessions/{id}`
- `DELETE /sessions/{id}`

## 3.6 `user-role` (protegido)

- `POST /user-role/user/{userId}/role/{roleId}`
- `DELETE /user-role/{userRoleId}`
- `PUT /user-role/user/{userId}` body: `{ "roleIds": string[] }`

## 3.7 `users-query` (protegido)

- `GET /users-query?q={texto}`
  - resp: `UserWithRolesResponse[]`

---

## 4) Modelos frontend (tal cual backend)

Copiar estos tipados en frontend para no romper contratos.

```ts
export interface RegisterRequest {
  name: string;
  lastName: string;
  email: string;
  password: string;
  confirmPassword: string;
}

export interface LoginRequest {
  email: string;
  password: string;
  recaptchaToken: string;
}

export interface TwoFactorVerifyRequest {
  sessionId: string;
  code: string;
}

export interface ForgotPasswordRequest {
  email: string;
  recaptchaToken: string;
}

export interface ResetPasswordRequest {
  token: string;
  password: string;
  confirmPassword: string;
}

export type SystemAction = "READ" | "CREATE" | "UPDATE" | "DELETE";

export type SystemModule =
  | "USERS"
  | "ROLES"
  | "PERMISSIONS"
  | "BUSES"
  | "ROUTES"
  | "SCHEDULES"
  | "REPORTS"
  | "INCIDENTS"
  | "MASS_MESSAGING";

export interface PermissionGrant {
  module: SystemModule;
  actions: SystemAction[];
}

export interface Role {
  id?: string;
  name: string;
  description: string;
  permissions: PermissionGrant[];
}

export interface User {
  _id?: string;
  name: string;
  lastName: string;
  email: string;
  password?: string;
  githubId?: string;
  githubUsername?: string;
  githubAvatarUrl?: string;
  googleId?: string;
  googleAvatarUrl?: string;
  microsoftId?: string;
  microsoftAvatarUrl?: string;
}

export interface Profile {
  id?: string;
  phone: string;
  photo: string;
  user?: User | null;
}

export interface Session {
  id?: string;
  token?: string;
  expiration?: string;
  code2FA?: string;
  otpAttempts?: number;
  otpVerified?: boolean;
  partialAuth?: boolean;
  createdAt?: string;
  user?: User;
}

export interface UserRole {
  id?: string;
  user: User;
  role: Role;
}

export interface PasswordResetToken {
  id?: string;
  token: string;
  expiration: string;
  used: boolean;
  user: User;
}

export interface RolePermissionsRequest {
  permissions: PermissionGrant[];
}

export interface UserWithRolesResponse {
  id: string;
  name: string;
  lastName: string;
  email: string;
  roles: Role[];
}
```

---

## 5) Estructura sugerida en frontend

- `src/modules/auth/`
  - `api.ts`
  - `types.ts`
  - `store.ts`
  - `pages/Login.tsx`, `pages/Register.tsx`, `pages/TwoFactor.tsx`, `pages/Forgot.tsx`, `pages/Reset.tsx`
- `src/modules/oauth/`
  - `api.ts`
  - `handlers.ts`
- `src/modules/admin/`
  - `users/`, `roles/`, `profiles/`, `sessions/`, `user-role/`, `users-query/`
- `src/shared/http/client.ts`
  - interceptor bearer token
  - normalizacion de errores (`error`, `message`)

---

## 6) Orden recomendado de desarrollo

1. Tipos y cliente HTTP base
2. Registro + login + 2FA
3. Recuperacion de contrasena
4. OAuth social
5. CRUD de usuarios/roles
6. Resto de CRUD (`profiles`, `sessions`, `user-role`, `users-query`)
7. Pruebas E2E y hardening UX

---

## 7) Criterios de aceptacion frontend

- [ ] Usuario puede registrarse y autenticarse por `login + 2FA`
- [ ] JWT se adjunta automaticamente a endpoints protegidos
- [ ] `401/403` redirigen correctamente (login/sin permisos)
- [ ] Recuperacion de contrasena funciona de extremo a extremo
- [ ] OAuth para 3 proveedores llega a sesion valida en frontend
- [ ] CRUD administrativos consumen contratos actuales sin transformaciones manuales inseguras
- [ ] Manejo de errores consistente con `error` y `message`

