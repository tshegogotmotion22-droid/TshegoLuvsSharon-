import type { Config } from "@netlify/functions";
import { createHmac, randomBytes, randomUUID, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { and, asc, eq, gt, inArray, isNull, or, sql } from "drizzle-orm";
import Anthropic from "@anthropic-ai/sdk";
import { db } from "../../db/index.js";
import { eas, licenses, users } from "../../db/schema.js";

const scryptAsync = promisify(scrypt) as (pw: string, salt: Buffer, len: number) => Promise<Buffer>;
const TOKEN_TTL = 7 * 24 * 3600; // seconds
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AI_MODEL = "claude-sonnet-5-5";

class HttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}
const json = (data: unknown, status = 200) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store" } });
const fail = (status: number, message: string): never => { throw new HttpError(status, message); };

// ---------- env ----------
function jwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s) fail(500, "Server is not configured: JWT_SECRET environment variable is missing.");
  return s as string;
}
const adminEmail = () => (process.env.ADMIN_EMAIL || "").trim().toLowerCase();

// ---------- passwords (scrypt) ----------
async function hashPassword(pw: string) {
  const salt = randomBytes(16);
  const hash = await scryptAsync(pw, salt, 64);
  return `scrypt$${salt.toString("base64")}$${hash.toString("base64")}`;
}
async function checkPassword(pw: string, stored: string) {
  const [alg, salt, hash] = stored.split("$");
  if (alg !== "scrypt" || !salt || !hash) return false;
  const expected = Buffer.from(hash, "base64");
  const actual = await scryptAsync(pw, Buffer.from(salt, "base64"), expected.length);
  return timingSafeEqual(actual, expected);
}
// Used when the email doesn't exist so login takes the same time either way
const DUMMY_HASH = `scrypt$${randomBytes(16).toString("base64")}$${randomBytes(64).toString("base64")}`;

// ---------- JWT (HS256) ----------
const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64url");
function signToken(user: { id: number; email: string }) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64url(JSON.stringify({ sub: user.id, email: user.email, iat: now, exp: now + TOKEN_TTL }));
  const sig = createHmac("sha256", jwtSecret()).update(`${head}.${body}`).digest("base64url");
  return `${head}.${body}.${sig}`;
}
function verifyToken(token: string): { sub: number } | null {
  const [head, body, sig] = token.split(".");
  if (!head || !body || !sig) return null;
  const expected = createHmac("sha256", jwtSecret()).update(`${head}.${body}`).digest();
  const given = Buffer.from(sig, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  try {
    const h = JSON.parse(Buffer.from(head, "base64url").toString());
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    if (h.alg !== "HS256" || typeof p.sub !== "number" || !(p.exp > Date.now() / 1000)) return null;
    return p;
  } catch { return null; }
}

async function currentUser(req: Request) {
  const m = (req.headers.get("authorization") || "").match(/^Bearer\s+(.+)$/i);
  const payload = m ? verifyToken(m[1].trim()) : null;
  if (!payload) fail(401, "Please sign in.");
  const [u] = await db.select().from(users).where(eq(users.id, payload!.sub));
  if (!u) fail(401, "Your account no longer exists. Please sign in again.");
  return { ...u, admin: !!adminEmail() && u.email === adminEmail() };
}
async function requireAdmin(req: Request) {
  const u = await currentUser(req);
  if (!u.admin) fail(403, "Admin access only.");
  return u;
}

// ---------- input helpers ----------
async function readBody(req: Request): Promise<Record<string, any>> {
  if (!(req.headers.get("content-type") || "").includes("application/json"))
    fail(415, "Send the request body as JSON (Content-Type: application/json).");
  try {
    const b = await req.json();
    if (!b || typeof b !== "object" || Array.isArray(b)) throw 0;
    return b;
  } catch { return fail(400, "Request body is not valid JSON."); }
}
const str = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
function credentials(b: Record<string, any>) {
  const email = str(b.email, 254).toLowerCase();
  const password = typeof b.password === "string" ? b.password : "";
  if (!EMAIL_RE.test(email)) fail(400, "Enter a valid email address.");
  if (password.length < 8) fail(400, "Password must be at least 8 characters.");
  if (password.length > 200) fail(400, "Password is too long (200 characters max).");
  return { email, password };
}
const imageUrl = (v: unknown) =>
  typeof v === "string" && /^data:image\/(png|jpe?g|webp|gif);base64,/.test(v) && v.length < 3_000_000 ? v : undefined;
const KEY_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const newKey = () =>
  Array.from({ length: 4 }, () => Array.from(randomBytes(4), (n) => KEY_CHARS[n % KEY_CHARS.length]).join("")).join("-");
const ms = (d: Date | null) => (d ? d.getTime() : null);

// ---------- routes ----------
type Handler = (req: Request) => Promise<Response>;
const routes: Record<string, { GET?: Handler; POST?: Handler }> = {
  health: {
    GET: async () => {
      let database = false;
      try { await db.execute(sql`select 1`); database = true; } catch (e) { console.error("health: database check failed", (e as Error).message); }
      const checks = { jwtSecret: !!process.env.JWT_SECRET, adminEmail: !!adminEmail(), database };
      return json({ ok: checks.jwtSecret && checks.database, checks, time: new Date().toISOString() });
    },
  },

  signup: {
    POST: async (req) => {
      const b = await readBody(req);
      const { email, password } = credentials(b);
      jwtSecret();
      const [u] = await db.insert(users)
        .values({ email, name: str(b.name, 80), passwordHash: await hashPassword(password) })
        .onConflictDoNothing({ target: users.email })
        .returning();
      if (!u) fail(409, "An account with this email already exists. Sign in instead.");
      return json({ token: signToken(u) }, 201);
    },
  },

  login: {
    POST: async (req) => {
      const { email, password } = credentials(await readBody(req));
      jwtSecret();
      const [u] = await db.select().from(users).where(eq(users.email, email));
      const ok = await checkPassword(password, u ? u.passwordHash : DUMMY_HASH);
      if (!u || !ok) fail(401, "Incorrect email or password.");
      return json({ token: signToken(u) });
    },
  },

  me: {
    GET: async (req) => {
      const u = await currentUser(req);
      const mine = await db.select().from(licenses).where(and(
        eq(licenses.activatedBy, u.email), eq(licenses.revoked, false),
        or(isNull(licenses.expiresAt), gt(licenses.expiresAt, new Date())),
      ));
      const ids = [...new Set(mine.map((l) => l.eaId))];
      const list = u.admin
        ? await db.select().from(eas).orderBy(asc(eas.createdAt))
        : ids.length ? await db.select().from(eas).where(inArray(eas.id, ids)).orderBy(asc(eas.createdAt)) : [];
      return json({
        user: { email: u.email, name: u.name, admin: u.admin },
        eas: list.map(({ id, name, desc, logo, bg }) => ({ id, name, desc, logo, bg })),
        licenses: mine.map((l) => ({ eaId: l.eaId, expiresAt: ms(l.expiresAt) })),
        settings: u.settings,
      });
    },
  },

  settings: {
    POST: async (req) => {
      const u = await currentUser(req);
      const { settings } = await readBody(req);
      if (!settings || typeof settings !== "object" || Array.isArray(settings)) fail(400, "settings must be an object.");
      if (JSON.stringify(settings).length > 20_000) fail(413, "Settings are too large.");
      await db.update(users).set({ settings }).where(eq(users.id, u.id));
      return json({ ok: true });
    },
  },

  activate: {
    POST: async (req) => {
      const u = await currentUser(req);
      const key = str((await readBody(req)).key, 40).toUpperCase();
      if (!key) fail(400, "Enter a license key.");
      const [l] = await db.select().from(licenses).where(eq(licenses.key, key));
      if (!l || l.revoked) fail(404, "That license key is not valid.");
      if (l.activatedBy && l.activatedBy !== u.email) fail(409, "That license key has already been used.");
      if (l.activatedBy) {
        if (l.expiresAt && l.expiresAt.getTime() < Date.now()) fail(410, "That license key has expired.");
        return json({ ok: true });
      }
      const now = new Date();
      const [claimed] = await db.update(licenses)
        .set({ activatedBy: u.email, activatedAt: now, expiresAt: l.days ? new Date(now.getTime() + l.days * 86_400_000) : null })
        .where(and(eq(licenses.key, key), isNull(licenses.activatedBy)))
        .returning();
      if (!claimed) fail(409, "That license key has already been used.");
      return json({ ok: true });
    },
  },

  ai: {
    POST: async (req) => {
      await currentUser(req);
      const b = await readBody(req);
      const prompt = str(b.prompt, 20_000);
      if (!prompt) fail(400, "prompt is required.");
      const images = (Array.isArray(b.images) ? b.images : []).slice(0, 4).map(imageUrl).filter(Boolean) as string[];
      const content: Anthropic.ContentBlockParam[] = images.map((d) => {
        const [, mt, data] = d.match(/^data:(image\/[a-z]+);base64,(.*)$/)!;
        return { type: "image", source: { type: "base64", media_type: mt.replace("jpg", "jpeg") as "image/jpeg", data } };
      });
      content.push({ type: "text", text: prompt });
      try {
        const msg = await new Anthropic().messages.create({ model: AI_MODEL, max_tokens: 2048, messages: [{ role: "user", content }] });
        return json({ text: msg.content.map((c) => (c.type === "text" ? c.text : "")).join("") });
      } catch (e: any) {
        console.error("ai: request failed", e?.status, e?.message);
        if (e?.status === 429) fail(429, "The AI is busy right now. Try again in a minute.");
        return fail(502, "AI request failed. Try again.");
      }
    },
  },

  "admin/data": {
    GET: async (req) => {
      await requireAdmin(req);
      const [e, l, u] = await Promise.all([
        db.select({ id: eas.id, name: eas.name, desc: eas.desc }).from(eas).orderBy(asc(eas.createdAt)),
        db.select().from(licenses).orderBy(asc(licenses.createdAt)),
        db.select({ email: users.email }).from(users).orderBy(asc(users.createdAt)),
      ]);
      return json({
        eas: e,
        licenses: l.map((x) => ({ key: x.key, eaId: x.eaId, days: x.days, note: x.note, revoked: x.revoked, activatedBy: x.activatedBy, expiresAt: ms(x.expiresAt) })),
        users: u.map((x) => x.email),
      });
    },
  },

  "admin/ea": {
    POST: async (req) => {
      await requireAdmin(req);
      const b = await readBody(req);
      const name = str(b.name, 80);
      if (!name) fail(400, "Give the EA a name.");
      const values: Partial<typeof eas.$inferInsert> = { name, desc: str(b.desc, 300) };
      const logo = imageUrl(b.logo), bg = imageUrl(b.bg);
      if (logo) values.logo = logo;
      if (bg) values.bg = bg;
      if (b.id) {
        const [ea] = await db.update(eas).set(values).where(eq(eas.id, String(b.id))).returning({ id: eas.id });
        if (!ea) fail(404, "That EA no longer exists.");
        return json({ id: ea.id });
      }
      const [ea] = await db.insert(eas).values({ id: randomUUID(), name, ...values }).returning({ id: eas.id });
      return json({ id: ea.id }, 201);
    },
  },

  "admin/ea-delete": {
    POST: async (req) => {
      await requireAdmin(req);
      await db.delete(eas).where(eq(eas.id, str((await readBody(req)).id, 100)));
      return json({ ok: true });
    },
  },

  "admin/licenses": {
    POST: async (req) => {
      await requireAdmin(req);
      const b = await readBody(req);
      const eaId = str(b.eaId, 100);
      const count = Math.floor(Number(b.count));
      const days = Math.floor(Number(b.days));
      if (!eaId || !(await db.select({ id: eas.id }).from(eas).where(eq(eas.id, eaId))).length) fail(400, "Create an EA first, then pick it.");
      if (!(count >= 1 && count <= 100)) fail(400, "How many must be between 1 and 100.");
      if (!(days >= 0 && days <= 36500)) fail(400, "Days must be 0 (lifetime) or more.");
      const rows = Array.from({ length: count }, () => ({ key: newKey(), eaId, days, note: str(b.note, 120) }));
      await db.insert(licenses).values(rows);
      return json({ keys: rows.map((r) => r.key) }, 201);
    },
  },

  "admin/revoke": {
    POST: async (req) => {
      await requireAdmin(req);
      await db.update(licenses).set({ revoked: true }).where(eq(licenses.key, str((await readBody(req)).key, 40)));
      return json({ ok: true });
    },
  },
};

export default async (req: Request) => {
  const route = new URL(req.url).pathname.replace(/^\/api\/?/, "").replace(/\/(index\.html?)?$/, "");
  const r = routes[route];
  if (!r) return json({ error: `Unknown API route: /api/${route}` }, 404);
  // The app calls the API from the same origin, so no CORS headers are sent; preflights just get the allowed methods.
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: { Allow: Object.keys(r).join(", ") } });
  const h = r[req.method as "GET" | "POST"];
  if (!h) return Response.json({ error: `Method ${req.method} not allowed for /api/${route}` }, { status: 405, headers: { Allow: Object.keys(r).join(", ") } });
  try {
    return await h(req);
  } catch (e) {
    if (e instanceof HttpError) return json({ error: e.message }, e.status);
    console.error(`api /${route} failed:`, (e as Error)?.message);
    return json({ error: "Server error. Please try again." }, 500);
  }
};

export const config: Config = { path: "/api/*" };
