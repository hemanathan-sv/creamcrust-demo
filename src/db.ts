import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const databasePath = resolve(process.env.DATABASE_PATH ?? "./data/auth.sqlite");
mkdirSync(dirname(databasePath), { recursive: true });

export const db = new Database(databasePath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.pragma("busy_timeout = 5000");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
`);

export type User = { id: string; email: string; created_at: number };

export const findUserByEmail = db.prepare(
  "SELECT id, email, password_hash FROM users WHERE email = ? COLLATE NOCASE",
);

export const createUser = db.prepare(
  "INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
);

export const findUserForSession = db.prepare(`
  SELECT users.id, users.email, users.created_at
  FROM sessions JOIN users ON users.id = sessions.user_id
  WHERE sessions.token_hash = ? AND sessions.expires_at > ?
`);

export const createSession = db.prepare(
  "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
);

export const deleteSession = db.prepare("DELETE FROM sessions WHERE token_hash = ?");
export const deleteExpiredSessions = db.prepare("DELETE FROM sessions WHERE expires_at <= ?");

export function asUser(value: unknown): User | undefined {
  return value as User | undefined;
}

export function asUserWithHash(value: unknown): (User & { password_hash: string }) | undefined {
  return value as (User & { password_hash: string }) | undefined;
}
