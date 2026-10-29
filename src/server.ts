import express, { type NextFunction, type Request, type Response } from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { resolve } from "node:path";
import {
  currentUser,
  emailAlreadyExists,
  initializeAuth,
  login,
  logout,
  normalizeEmail,
  register,
  validPassword,
} from "./auth.js";

const port = Number(process.env.PORT ?? 3000);
const production = process.env.NODE_ENV === "production";
const appOrigin = process.env.APP_ORIGIN ?? `http://localhost:${port}`;

if (production && !process.env.APP_ORIGIN) {
  throw new Error("APP_ORIGIN must be set to the public HTTPS origin in production.");
}
if (production && !appOrigin.startsWith("https://")) {
  throw new Error("APP_ORIGIN must use HTTPS in production.");
}

const app = express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cookieParser());
app.use(express.json({ limit: "10kb", type: "application/json" }));
app.use(express.urlencoded({ extended: false, limit: "10kb" }));
app.use((request, response, next) => {
  response.setHeader("Cache-Control", "no-store");
  next();
});

// Exact-origin checks protect cookie-authenticated state changes against cross-site requests.
app.use("/api/auth", (request: Request, response: Response, next: NextFunction) => {
  if (!["POST", "PUT", "PATCH", "DELETE"].includes(request.method)) return next();
  if (request.get("origin") !== appOrigin) {
    return response.status(403).json({ error: "Request origin not allowed." });
  }
  if (!request.is("application/json")) {
    return response.status(415).json({ error: "Content-Type must be application/json." });
  }
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again later." },
});

function publicUser(user: { id: string; email: string; created_at: number }) {
  return { id: user.id, email: user.email, createdAt: new Date(user.created_at).toISOString() };
}

app.post("/api/auth/register", authLimiter, async (request, response, next) => {
  try {
    const email = normalizeEmail(request.body?.email);
    const password = request.body?.password;
    if (!email || !validPassword(password)) {
      return response.status(400).json({ error: "Enter a valid email and a password of 12–128 characters." });
    }
    if (emailAlreadyExists(email)) {
      return response.status(409).json({ error: "An account with that email already exists. Try signing in." });
    }
    const user = await register(email, password, response);
    response.status(201).json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/auth/login", authLimiter, async (request, response, next) => {
  try {
    const email = normalizeEmail(request.body?.email);
    const password = request.body?.password;
    if (!email || typeof password !== "string" || password.length > 128) {
      return response.status(400).json({ error: "Enter a valid email and password." });
    }
    const user = await login(email, password, response);
    if (!user) return response.status(401).json({ error: "Email or password is incorrect." });
    response.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/me", (request, response) => {
  const user = currentUser(request);
  if (!user) return response.status(200).json({ user: null });
  response.json({ user: publicUser(user) });
});

app.post("/api/auth/logout", (request, response) => {
  logout(request, response);
  response.status(204).end();
});

app.use("/api", (_request, response) => response.status(404).json({ error: "Not found." }));
app.use(express.static(resolve("public"), { extensions: ["html"] }));
app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
  // Never return exception messages or submitted credentials to clients.
  console.error("Request failed", error instanceof Error ? error.message : "Unknown error");
  if (typeof error === "object" && error !== null && "code" in error && error.code === "SQLITE_CONSTRAINT_UNIQUE") {
    return response.status(409).json({ error: "An account with that email already exists. Try signing in." });
  }
  response.status(500).json({ error: "Something went wrong. Please try again." });
});

await initializeAuth();
app.listen(port, () => console.log(`Auth demo listening on ${appOrigin}`));
