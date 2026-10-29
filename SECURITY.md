# Authentication and security notes

This document describes the authentication implementation in this repository. It is a starter, not a claim that a deployment is production-ready without environment-specific review.

## Components

- `public/app.js` submits credentials as JSON and uses the returned user profile only for display. It cannot access the session cookie because it is `HttpOnly`.
- `src/server.ts` restricts state-changing auth calls to the configured exact origin, requires JSON, applies Helmet headers, caps request bodies, disables the Express fingerprint header, and limits auth attempts.
- `src/auth.ts` normalizes emails, enforces password length, hashes/verifies passwords with Argon2id, issues opaque sessions, and revokes sessions.
- `src/db.ts` stores user password hashes and session-token digests in SQLite using prepared statements. Foreign keys remove a user's sessions if their account is later deleted.

## Request sequence

### Register

`POST /api/auth/register` → origin/content-type checks → rate limit → email/password validation → Argon2id hash → insert user → generate random session token → store SHA-256(token) and expiry → set cookie → return public user fields.

### Sign in

`POST /api/auth/login` → origin/content-type checks → rate limit → normalize email → retrieve password hash → Argon2id verification → on success create a new server-side session and set cookie → return public user fields. Unknown emails are verified against a dummy Argon2 hash, and the response text is the same for unknown users and bad passwords.

### Restore session

Browser sends the cookie automatically → server hashes the token → SQLite finds a non-expired matching session → return user profile. Missing, malformed, revoked, and expired tokens return `{"user":null}`.

### Sign out

`POST /api/auth/logout` → origin/content-type checks → hash cookie token → delete matching session → clear cookie → return `204 No Content`.

## Credential and token handling

- Passwords are accepted only in the request body over HTTPS in production. The app does not log request bodies, echo passwords, or store plaintext credentials. Password hashes use Argon2id defaults from the `argon2` package.
- The browser receives only an opaque random token in the `sid` cookie during local development and `__Host-sid` in production. The cookie is `HttpOnly`, `SameSite=Lax`, path `/`, and `Secure` in production. The production `__Host-` prefix also requires a secure, host-only, root-path cookie.
- The database stores SHA-256(token), never the raw token. This is suitable here because tokens are uniformly random 256-bit values; a stolen digest cannot be used as a bearer token.
- A session is server-side, revocable, and expires after 14 days. There is no JWT, refresh token, or client-side token storage.
- Auth JSON responses include only `id`, `email`, and account creation time. Password hashes and session digests are not serialized.
- State-changing routes require both same-origin `Origin` and JSON content type. `SameSite=Lax` is an additional browser safeguard, not a substitute for HTTPS or origin validation.

## Deployment requirements and limits

1. Serve the app only through HTTPS. Set `NODE_ENV=production` and `APP_ORIGIN` to the exact external origin, without a trailing slash. The server fails to start in production if this is missing or not HTTPS.
2. Keep `DATABASE_PATH` on persistent storage with restrictive filesystem permissions. SQLite is appropriate for a single-node starter; move users and sessions to a managed database before running multiple app instances.
3. `express-rate-limit` uses its default in-memory store. Limits reset on restart and are not shared between instances. Use a shared store and consider account-plus-IP throttling before public launch.
4. If behind a reverse proxy, configure Express `trust proxy` to the exact trusted proxy topology before relying on client IP rate limiting. Do not accept untrusted `X-Forwarded-*` values.
5. This starter does not implement email verification, password reset, MFA, account recovery, session listing, or audit logging. Add those flows before using it for sensitive accounts.
6. Registration returns `409` for an existing email, which can disclose account existence. For public consumer signup, consider a verified-email flow with a uniform response.
7. Back up the SQLite database securely. Protect access to the database file and its WAL files; they contain password hashes and session digests.
8. Review and update dependencies regularly, use a lockfile in deployment, and run dependency vulnerability checks in CI.

Do not commit production secrets or database files to the repository.
