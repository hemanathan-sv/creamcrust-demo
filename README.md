# Northstar Authentication Starter

A small same-origin authentication app built with Express, TypeScript, SQLite, and Argon2id. It includes a responsive sign-in/register screen and a server API for registration, login, session inspection, and logout.

## Run locally

Requires Node.js 22 or newer. The SQLite database is created at `./data/auth.sqlite` on first start.

> This app requires a Node.js host with persistent disk. GitHub Pages can serve the static files, but it cannot run the authentication API or SQLite database by itself.

```sh
npm install
npm run dev
```

Open `http://localhost:3000`. To build and run the compiled server:

```sh
npm run build
npm start
```

Set `PORT` to change the listen port and `DATABASE_PATH` to change the SQLite file. In production also set `NODE_ENV=production` and `APP_ORIGIN` to the exact public HTTPS origin (for example `https://app.example.com`, with no trailing slash). Production mode requires HTTPS and sets a `__Host-sid` cookie. Put the app behind a TLS-enabled reverse proxy and configure proxy trust only when the deployment requires it; never trust arbitrary forwarded headers.

## Components

| Component | Responsibility |
| --- | --- |
| `public/index.html`, `public/app.js`, `public/styles.css` | Sign-in and account creation UI; sends same-origin JSON requests and never reads the session token. |
| `src/server.ts` | Express setup, security headers, JSON limits, origin checks, rate limits, API routes, and static file serving. |
| `src/auth.ts` | Email/password validation, Argon2id hashing and verification, opaque session issuance, cookie settings, and session lookup/revocation. |
| `src/db.ts` | SQLite schema, prepared statements, foreign keys, and database initialization. |
| `SECURITY.md` | Credential/token lifecycle, request sequence, and production hardening notes. |

## API

All endpoints use the app's origin. State-changing requests require the exact `Origin` configured by `APP_ORIGIN` and `Content-Type: application/json`.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/register` | Create an account and start a session. JSON: `{"email":"…","password":"…"}`. |
| `POST` | `/api/auth/login` | Verify credentials and start a session. Same JSON shape. |
| `GET` | `/api/auth/me` | Return the current user or `{"user":null}`. |
| `POST` | `/api/auth/logout` | Revoke the current session and clear the cookie. |

Registration accepts a valid email and a 12–128 character password. Login errors do not reveal whether an email is registered. Auth routes have a per-process rate limit of 20 attempts per IP per 15 minutes; see `SECURITY.md` before scaling horizontally.

## Request flow

1. The browser posts the email and password to the same-origin API over HTTPS in production.
2. The server validates the payload and origin. Registration hashes the password with Argon2id; login verifies the hash.
3. On success, the server generates a 256-bit random session token. Only its SHA-256 digest is stored in SQLite; the raw token is sent as an `HttpOnly`, `SameSite=Lax`, `Secure`-in-production cookie.
4. Later requests send the cookie automatically. `/api/auth/me` hashes its value and checks for a live matching server-side session.
5. Logout deletes that session row and expires the browser cookie. Sessions expire after 14 days.

No access token or password is stored in `localStorage`, `sessionStorage`, or browser-readable cookies. Details and deployment limits are documented in [`SECURITY.md`](SECURITY.md).
