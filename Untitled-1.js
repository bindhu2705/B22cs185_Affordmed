// server.js
// URL Shortener Microservice (Express)
// Requirements satisfied:
// - Custom logging middleware (no console/inbuilt loggers): file-based JSON logs
// - Microservice (single service exposing endpoints)
// - No authentication required
// - Unique short codes
// - Default validity 30 minutes
// - Optional custom shortcode (validated + unique)
// - Basic analytics per short link

import fs from "fs";
import path from "path";
import crypto from "crypto";
import express from "express";
import bodyParser from "body-parser";
import { fileURLToPath } from "url";

// -------------------- Setup --------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(bodyParser.json());

// -------------------- Custom Logger Middleware --------------------
// No console.* or external loggers. We implement file-based structured logging.
const LOG_DIR = path.join(__dirname, "logs");
const LOG_FILE = path.join(LOG_DIR, "app.log");
fs.mkdirSync(LOG_DIR, { recursive: true });

function writeLog(event) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    ...event,
  }) + "\n";
  // Write synchronously to preserve order in simple eval setups
  fs.appendFileSync(LOG_FILE, line, { encoding: "utf8" });
}

// Request logging middleware
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  const rid = crypto.randomUUID();
  req.context = { requestId: rid };

  const meta = {
    requestId: rid,
    method: req.method,
    path: req.path,
    ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "",
    ua: req.headers["user-agent"] || "",
  };
  writeLog({ type: "request.received", ...meta });

  res.on("finish", () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    writeLog({
      type: "request.completed",
      ...meta,
      status: res.statusCode,
      durationMs: Math.round(durationMs),
    });
  });

  next();
});

// -------------------- In-memory Store --------------------
// For a real deployment, back this with Redis/Postgres.
// Structure: code -> { url, createdAt, expiresAt, clicks, lastAccessAt, hits: [] }
const store = new Map();

// -------------------- Helpers --------------------
const DEFAULT_VALIDITY_MIN = 30;
const MIN_CODE_LEN = 4;
const MAX_CODE_LEN = 24;
const CODE_ALPHABET =
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

function isValidUrl(u) {
  try {
    const url = new URL(u);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function isValidCode(code) {
  if (typeof code !== "string") return false;
  if (code.length < MIN_CODE_LEN || code.length > MAX_CODE_LEN) return false;
  return /^[A-Za-z0-9]+$/.test(code);
}

function genCode(len = 8) {
  // crypto-random base62
  const bytes = crypto.randomBytes(len);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
  }
  return out;
}

function genUniqueCode() {
  // Prevent infinite loop — try a few times, then grow length
  let length = 8;
  for (let attempts = 0; attempts < 50; attempts++) {
    const code = genCode(length);
    if (!store.has(code)) return code;
    if ((attempts + 1) % 10 === 0) length++; // ramp length slightly
  }
  // Fallback
  let code;
  do {
    code = genCode(12);
  } while (store.has(code));
  return code;
}

function now() {
  return new Date();
}

function minutesFromNow(mins) {
  return new Date(Date.now() + mins * 60 * 1000);
}

function isExpired(entry) {
  return entry.expiresAt && now() > entry.expiresAt;
}

// -------------------- Routes --------------------

/**
 * POST /api/urls
 * Body: { url: string, validityMinutes?: number, customCode?: string }
 * Rules:
 *  - url required, must be http(s)
 *  - validityMinutes integer (minutes). If not provided -> 30
 *  - customCode if provided -> alphanumeric [4..24], must be unique
 * Response: { code, shortUrl, url, createdAt, expiresAt }
 */
app.post("/api/urls", (req, res) => {
  const { url, validityMinutes, customCode } = req.body || {};

  if (!url || !isValidUrl(url)) {
    writeLog({
      type: "create.error",
      requestId: req.context.requestId,
      reason: "invalid_url",
      payload: { url },
    });
    return res.status(400).json({ error: "Invalid or missing 'url' (http/https required)." });
  }

  let ttl = Number.isInteger(validityMinutes) ? validityMinutes : DEFAULT_VALIDITY_MIN;
  if (ttl <= 0 || ttl > 365 * 24 * 60) {
    return res.status(400).json({ error: "validityMinutes must be a positive integer (minutes) and reasonable." });
  }

  let code;
  if (customCode !== undefined) {
    if (!isValidCode(customCode)) {
      return res.status(400).json({
        error: `customCode must be alphanumeric and ${MIN_CODE_LEN}-${MAX_CODE_LEN} chars.`,
      });
    }
    if (store.has(customCode)) {
      return res.status(409).json({ error: "customCode already in use. Choose another." });
    }
    code = customCode;
  } else {
    code = genUniqueCode();
  }

  const createdAt = now();
  const expiresAt = minutesFromNow(ttl);

  const entry = {
    code,
    url,
    createdAt,
    expiresAt,
    clicks: 0,
    lastAccessAt: null,
    hits: [], // { ts, ip, ua, ref }
  };
  store.set(code, entry);

  writeLog({
    type: "shortlink.created",
    requestId: req.context.requestId,
    code,
    url,
    expiresAt: expiresAt.toISOString(),
  });

  return res.status(201).json({
    code,
    shortUrl: `${req.protocol}://${req.get("host")}/${code}`,
    url,
    createdAt: createdAt.toISOString(),
    expiresAt: expiresAt.toISOString(),
  });
});

/**
 * GET /:code
 *  - Redirects to the original URL if exists & not expired
 *  - Tracks click analytics
 */
app.get("/:code", (req, res) => {
  const code = req.params.code;
  const entry = store.get(code);

  if (!entry) {
    writeLog({
      type: "redirect.miss",
      requestId: req.context.requestId,
      code,
    });
    return res.status(404).send("Short link not found.");
  }
  if (isExpired(entry)) {
    writeLog({
      type: "redirect.expired",
      requestId: req.context.requestId,
      code,
    });
    return res.status(410).send("Short link expired.");
  }

  entry.clicks += 1;
  entry.lastAccessAt = now();
  entry.hits.push({
    ts: entry.lastAccessAt.toISOString(),
    ip: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "",
    ua: req.headers["user-agent"] || "",
    ref: req.headers["referer"] || req.headers["referrer"] || "",
  });

  writeLog({
    type: "redirect.hit",
    requestId: req.context.requestId,
    code,
    url: entry.url,
  });

  res.redirect(entry.url);
});

/**
 * GET /api/urls/:code
 *  - Returns metadata for a short code (no secrets)
 */
app.get("/api/urls/:code", (req, res) => {
  const { code } = req.params;
  const entry = store.get(code);
  if (!entry) return res.status(404).json({ error: "Not found" });

  return res.json({
    code: entry.code,
    url: entry.url,
    createdAt: entry.createdAt.toISOString(),
    expiresAt: entry.expiresAt.toISOString(),
    clicks: entry.clicks,
    lastAccessAt: entry.lastAccessAt ? entry.lastAccessAt.toISOString() : null,
    expired: isExpired(entry),
  });
});

/**
 * GET /api/urls/:code/stats
 *  - Returns analytics (clicks + hit records)
 */
app.get("/api/urls/:code/stats", (req, res) => {
  const { code } = req.params;
  const entry = store.get(code);
  if (!entry) return res.status(404).json({ error: "Not found" });

  return res.json({
    code: entry.code,
    url: entry.url,
    clicks: entry.clicks,
    lastAccessAt: entry.lastAccessAt ? entry.lastAccessAt.toISOString() : null,
    expired: isExpired(entry),
    hits: entry.hits.slice(-1000), // cap in response to avoid huge payloads
  });
});

/**
 * DELETE /api/urls/:code
 *  - Soft-delete by expiring immediately (handy in tests)
 */
app.delete("/api/urls/:code", (req, res) => {
  const { code } = req.params;
  const entry = store.get(code);
  if (!entry) return res.status(404).json({ error: "Not found" });

  entry.expiresAt = now();
  writeLog({
    type: "shortlink.expired",
    requestId: req.context.requestId,
    code,
  });
  return res.json({ ok: true, expiredAt: entry.expiresAt.toISOString() });
});

// Health
app.get("/health", (_req, res) => {
  return res.json({ ok: true, uptimeSec: Math.round(process.uptime()) });
});

// -------------------- Start --------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  // Intentionally NOT using console.* — rely on file logs.
  writeLog({ type: "service.started", port: PORT });
});
