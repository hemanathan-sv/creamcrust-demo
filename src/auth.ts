import { randomBytes, randomUUID, createHash } from "node:crypto";
import argon2 from "argon2";
import type { Request, Response } from "express";
import {
  asUser,
  asUserWithHash,
  createSession,
  createUser,
  db,
  deleteExpiredSessions,
  deleteSession,
  findUserByEmail,
  findUserForSession,
  type User,
} from "./db.js";

const SESSION_LIFETIME_SECONDS = 60 * 60 * 24 * 14;
const production = process.env.NODE_ENV === "production";
export const cookieName = production ? "__Host-sid" : "sid";
const cookieOptions = {
  httpOnly: true,
  secure: production,
  sameSite: "lax" as const,
  path: "/",
  maxAge: SESSION_LIFETIME_SECONDS * 1000,
};

export function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;
  return email;
}

export function validPassword(value: unknown): value is string {
  return typeof value === "string" && value.length >= 12 && value.length <= 128;
}

function digest(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function issueSession(userId: string, response: Response): void {
  const now = Date.now();
  const rawToken = randomBytes(32).toString("base64url");
  deleteExpiredSessions.run(now);
  createSession.run(digest(rawToken), userId, now, now + SESSION_LIFETIME_SECONDS * 1000);
  response.cookie(cookieName, rawToken, cookieOptions);
}

export function currentUser(request: Request): User | undefined {
  const rawToken = request.cookies?.[cookieName];
  if (typeof rawToken !== "string" || rawToken.length > 128) return undefined;
  return asUser(findUserForSession.get(digest(rawToken), Date.now()));
}

export async function register(email: string, password: string, response: Response): Promise<User> {
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });
  const userId = randomUUID();
  createUser.run(userId, email, passwordHash, Date.now());
  issueSession(userId, response);
  return { id: userId, email, created_at: Date.now() };
}

let dummyPasswordHash: string | undefined;
export async function initializeAuth(): Promise<void> {
  dummyPasswordHash = await argon2.hash(randomBytes(24), { type: argon2.argon2id });
  deleteExpiredSessions.run(Date.now());
}

export async function login(email: string, password: string, response: Response): Promise<User | null> {
  const row = asUserWithHash(findUserByEmail.get(email));
  const valid = await argon2.verify(row?.password_hash ?? dummyPasswordHash!, password);
  if (!row || !valid) return null;
  issueSession(row.id, response);
  return { id: row.id, email: row.email, created_at: row.created_at };
}

export function logout(request: Request, response: Response): void {
  const rawToken = request.cookies?.[cookieName];
  if (typeof rawToken === "string" && rawToken.length <= 128) deleteSession.run(digest(rawToken));
  response.clearCookie(cookieName, {
    httpOnly: true,
    secure: production,
    sameSite: "lax",
    path: "/",
  });
}

export function emailAlreadyExists(email: string): boolean {
  return Boolean(db.prepare("SELECT 1 FROM users WHERE email = ? COLLATE NOCASE").get(email));
}
