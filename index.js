import express from "express";
import cors from "cors";
import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import ffmpeg from "fluent-ffmpeg";
import ffmpegInstaller from "@ffmpeg-installer/ffmpeg";
import fs from "fs";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import fetch from "node-fetch";

// === Cognito ===
import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import crypto from "crypto";

import { pool, one, all, run } from "./db.js";

// ----- resolve __dirname -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ----- tiny .env loader -----
const envPath = path.join(process.cwd(), ".env");
if (fs.existsSync(envPath)) {
  for (const raw of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
    const s = raw.trim();
    if (!s || s.startsWith("#")) continue;
    const m = /^([\w.-]+)\s*=\s*(.*)$/.exec(s);
    if (!m) continue;
    const k = m[1];
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    if (process.env[k] == null || process.env[k] === "") process.env[k] = v;
  }
}

// ----- config -----
const PORT = Number(process.env.PORT || 8080);
const OPENSUBTITLES_API_KEY = process.env.OPENSUBTITLES_API_KEY || "";
ffmpeg.setFfmpegPath(ffmpegInstaller.path);
const log = (...a) => console.log(new Date().toISOString(), ...a);

// === Cognito config from env ===
const COG_REGION = process.env.COGNITO_REGION || "ap-southeast-2";
const COG_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || "";
const COG_CLIENT_ID = process.env.COGNITO_CLIENT_ID || "";
const COG_CLIENT_SECRET= process.env.COGNITO_CLIENT_SECRET || "";

const cogClient = new CognitoIdentityProviderClient({ region: COG_REGION });
const hasSecret = typeof COG_CLIENT_SECRET === "string" && COG_CLIENT_SECRET.length > 0;


function makeSecretHash(username) {
  if (!hasSecret) return null;
  const hmac = crypto.createHmac("sha256", COG_CLIENT_SECRET);
  hmac.update(`${username}${COG_CLIENT_ID}`);
  return hmac.digest("base64");
}

const idTokenVerifier = CognitoJwtVerifier.create({
  userPoolId: COG_USER_POOL_ID,
  clientId: COG_CLIENT_ID,
  tokenUse: "id",
});

// ----- data dirs -----
function safeDir(preferred) {
  try {
    fs.mkdirSync(preferred, { recursive: true });
    fs.accessSync(preferred, fs.constants.W_OK);
    return preferred;
  } catch {
    const tmp = path.join(os.tmpdir(), "video-api");
    fs.mkdirSync(tmp, { recursive: true });
    return tmp;
  }
}
const DATA_DIR = safeDir(path.join(process.cwd(), "data"));
const UP_DIR = path.join(DATA_DIR, "uploads");
const OUT_DIR = path.join(DATA_DIR, "outputs");
const THUMB_DIR = path.join(OUT_DIR, "thumbs");
<<<<<<< HEAD
for (const d of [UP_DIR, OUT_DIR, THUMB_DIR])
  fs.mkdirSync(d, { recursive: true });

// ----- database -----
const DB_FILE = path.join(DATA_DIR, "app.db");
const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS accounts (
  owner TEXT PRIMARY KEY,
  balance_cents INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  mime TEXT,
  uploaded_at TEXT NOT NULL,
  ext_meta TEXT
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  file_id TEXT NOT NULL,
  status TEXT NOT NULL,
  params TEXT NOT NULL,
  progress REAL NOT NULL DEFAULT 0,
  log TEXT NOT NULL DEFAULT '',
  charged_cents INTEGER NOT NULL DEFAULT 0,
  refunded_cents INTEGER NOT NULL DEFAULT 0,
  output_path TEXT,
  output_name TEXT,
  thumbnail_path TEXT,
  thumbnail_name TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_jobs_updated_at ON jobs(updated_at);
`);

function columnExists(table, col) {
  return db
    .prepare(`PRAGMA table_info(${table})`)
    .all()
    .some((c) => c.name === col);
}
function fkExists(table, refTable) {
  return db
    .prepare(`PRAGMA foreign_key_list(${table})`)
    .all()
    .some((r) => r.table === refTable);
}

// minimal migrations
(function migrate() {
  if (!columnExists("files", "ext_meta"))
    db.exec(`ALTER TABLE files ADD COLUMN ext_meta TEXT;`);
  for (const c of [
    ["thumbnail_path", "TEXT"],
    ["thumbnail_name", "TEXT"],
    ["progress", "REAL NOT NULL DEFAULT 0"],
    ["log", "TEXT NOT NULL DEFAULT ''"],
    ["charged_cents", "INTEGER NOT NULL DEFAULT 0"],
    ["refunded_cents", "INTEGER NOT NULL DEFAULT 0"],
    ["output_path", "TEXT"],
    ["output_name", "TEXT"],
  ]) {
    if (!columnExists("jobs", c[0]))
      db.exec(`ALTER TABLE jobs ADD COLUMN ${c[0]} ${c[1]};`);
  }
  if (!fkExists("jobs", "files")) {
    db.exec("PRAGMA foreign_keys=OFF;");
    db.exec(`
      CREATE TABLE IF NOT EXISTS jobs_new (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        file_id TEXT NOT NULL,
        status TEXT NOT NULL,
        params TEXT NOT NULL,
        progress REAL NOT NULL DEFAULT 0,
        log TEXT NOT NULL DEFAULT '',
        charged_cents INTEGER NOT NULL DEFAULT 0,
        refunded_cents INTEGER NOT NULL DEFAULT 0,
        output_path TEXT,
        output_name TEXT,
        thumbnail_path TEXT,
        thumbnail_name TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
      );
      INSERT INTO jobs_new
      SELECT id, owner, file_id, status, COALESCE(params,'{}'), COALESCE(progress,0),
             COALESCE(log,''), COALESCE(charged_cents,0), COALESCE(refunded_cents,0),
             output_path, output_name, thumbnail_path, thumbnail_name, created_at, updated_at
      FROM jobs;
      DROP TABLE jobs;
      ALTER TABLE jobs_new RENAME TO jobs;
      CREATE INDEX IF NOT EXISTS idx_jobs_updated_at ON jobs(updated_at);
    `);
    db.exec("PRAGMA foreign_keys=ON;");
  }
})();

db.prepare(
  `INSERT INTO accounts(owner,balance_cents,updated_at)
   VALUES('admin',1000,datetime('now'))
   ON CONFLICT(owner) DO NOTHING;`
).run();
db.prepare(
  `INSERT INTO accounts(owner,balance_cents,updated_at)
   VALUES('user',500,datetime('now'))
   ON CONFLICT(owner) DO NOTHING;`
).run();
=======
for (const d of [UP_DIR, OUT_DIR, THUMB_DIR]) fs.mkdirSync(d, { recursive: true });
>>>>>>> database

// ----- app -----
const app = express();
app.use(cors());
app.use(express.json());
app.use("/", express.static(path.join(__dirname, "public")));
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// === Cognito: signup / confirm / login ===
app.post("/auth/signup", async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password || !email)
    return res.status(400).json({ ok: false, error: "username, password, email required" });
  try {
    const params = {
      ClientId: COG_CLIENT_ID,
      Username: username,
      Password: password,
      UserAttributes: [{ Name: "email", Value: email }],
    };
    const sh = makeSecretHash(username);
    if (sh) params.SecretHash = sh;
    const out = await cogClient.send(new SignUpCommand(params));
    res.json({ ok: true, codeDelivery: out.CodeDeliveryDetails || null });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.name || "SignUpError", message: e.message });
  }
});

// ---- admin allowlist from env (可选，用你原来的 env 白名单) ----
const ADM_USERNAMES = (process.env.ADMIN_USERNAMES || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const ADM_EMAILS = (process.env.ADMIN_EMAILS || "")
  .split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const ADM_GROUPS = (process.env.ADMIN_GROUPS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

function isAdminByEnv(payload, username) {
  const u = (username || "").toLowerCase();
  const email = (payload?.email || "").toLowerCase();
  const groups = Array.isArray(payload?.["cognito:groups"]) ? payload["cognito:groups"] : [];
  if (ADM_USERNAMES.includes(u)) return true;
  if (email && ADM_EMAILS.includes(email)) return true;
  if (groups.some(g => ADM_GROUPS.includes(g))) return true;
  return false;
}

app.post("/auth/confirm", async (req, res) => {
  const { username, code } = req.body || {};
  if (!username || !code) {
    return res.status(400).json({ ok: false, error: "username, code required" });
  }
  try {
    const params = { ClientId: COG_CLIENT_ID, Username: username, ConfirmationCode: code };
    const sh = makeSecretHash(username);
    if (sh) params.SecretHash = sh;
    await cogClient.send(new ConfirmSignUpCommand(params));
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.name || "ConfirmError", message: e.message });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: "username, password required" });
  }

  let idToken;
  try {
    const authParams = { USERNAME: username, PASSWORD: password };
    const sh = makeSecretHash(username);
    if (sh) authParams.SECRET_HASH = sh;

    const out = await cogClient.send(new InitiateAuthCommand({
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: COG_CLIENT_ID,
      AuthParameters: authParams,
    }));

    idToken = out?.AuthenticationResult?.IdToken;
    if (!idToken) return res.status(401).json({ ok: false, error: "no token" });
  } catch (e) {
    // 这里不做任何硬编码用户名；把 Cognito 的真实错误原样返回，方便你前端提示
    console.error("[/login] Cognito error:", e.name, e.message);
    return res.status(401).json({ ok: false, error: e.name || "AuthError", message: e.message || "Login failed" });
  }

  // 登录成功 -> 立即把 token 返回前端，保证 UX；后面 DB 异步确保账户行（失败只记日志）
  res.json({ ok: true, authToken: idToken });

  try {
    await run(
      `INSERT INTO accounts(owner, balance_cents, updated_at)
       VALUES ($1, 0, now())
       ON CONFLICT (owner) DO NOTHING`,
      [username]
    );
  } catch (e) {
    console.warn("[login] ensure account row failed:", e.message);
  } 
});


// whoami
app.get("/auth/whoami", auth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// auth (Cognito ID token）
async function auth(req, res, next) {
  try {
    const m = (req.headers.authorization || "").match(/^Bearer (.+)$/i);
    if (!m) return res.status(401).json({ ok: false, error: "missing token" });

    const payload = await idTokenVerifier.verify(m[1]);
    const rawName = payload["cognito:username"];
    const username = typeof rawName === "string" ? rawName.trim() : "";
<<<<<<< HEAD
    const isAdmin = (username.toLowerCase() === "admin");
=======
>>>>>>> database

    req.user = {
      sub: username || payload.sub || "",
      email: payload.email || null,
      jwt: m[1],
<<<<<<< HEAD
      admin: isAdmin,
=======
      admin: isAdminByEnv(payload, username),  // ← 使用 env 白名单判断
>>>>>>> database
    };

    return next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "invalid token", detail: e.message });
  }
}


<<<<<<< HEAD

// ======================================new Added section=====================================
//  ===  Set up storage for files ===
//  ===  S3 client ===
=======
// === S3 ===
>>>>>>> database
const s3 = new S3Client({ region: process.env.AWS_REGION });
const BUCKET = process.env.AWS_S3_BUCKET;

// Multer 本地临时盘
const tmpDir = path.join(process.cwd(), "uploads");
<<<<<<< HEAD

// 確保資料夾存在
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true });
}


=======
if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
>>>>>>> database
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, tmpDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

// ----- helpers -----
function listParams(req, opt) {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const size = Math.min(100, Math.max(1, parseInt(req.query.size || "10", 10)));
  const q = (req.query.q || "").trim();
  const sort = opt.sortWhitelist.includes(req.query.sort) ? req.query.sort : opt.defaultSort;
  const order = (req.query.order || "desc").toLowerCase() === "asc" ? "asc" : "desc";
  const offset = (page - 1) * size;
  return { page, size, offset, q, sort, order };
}

// ----- account -----
app.get("/me", auth, async (req, res) => {
  const row = await one("SELECT balance_cents, updated_at FROM accounts WHERE owner=$1", [
    req.user.sub,
  ]);
  res.json({
    user: req.user.sub,
<<<<<<< HEAD
    admin: !!req.user.admin,   // ensure this is present
    balance_cents: a?.balance_cents ?? 0,
    updated_at: a?.updated_at ?? null,
  });
});


app.post("/accounts/topup", auth, (req, res) => {
=======
    admin: !!req.user.admin,
    balance_cents: row?.balance_cents ?? 0,
    updated_at: row?.updated_at ?? null,
  });
});

app.post("/accounts/topup", auth, async (req, res) => {
>>>>>>> database
  const amount = Number(req.body?.amount_cents ?? 0);
  if (!Number.isInteger(amount) || amount <= 0)
    return res.status(400).json({ ok: false, error: "invalid amount" });

  await run(
    `INSERT INTO accounts(owner,balance_cents,updated_at)
     VALUES ($1,$2,now())
     ON CONFLICT (owner) DO UPDATE
     SET balance_cents = accounts.balance_cents + EXCLUDED.balance_cents,
         updated_at    = now()`,
    [req.user.sub, amount]
  );
  res.json({ ok: true, added: amount });
});

// ----- files -----
app.post("/upload", auth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, error: "no file" });
  const id = uuidv4();
  const original = req.file.originalname || "upload.bin";
  const safeName = `${id}-${original.replace(/[^\w.\-]+/g, "_")}`;

  const username = req.user.sub;
  const s3Key = `${username}/uploaded/${safeName}`;
  const fileStream = fs.createReadStream(req.file.path);
  log("Temp file path:", req.file.path);

  try {
    await s3.send(
      new PutObjectCommand({
        Bucket: BUCKET,
        Key: s3Key,
        Body: fileStream,
        ContentType: req.file.mimetype,
      })
    );
    try {
      fs.unlinkSync(req.file.path);
    } catch {}

    await run(
      `INSERT INTO files (id,owner,filename,stored_path,size_bytes,mime,uploaded_at)
       VALUES ($1,$2,$3,$4,$5,$6,now())`,
      [id, username, original, s3Key, req.file.size, req.file.mimetype || null]
    );
    res.json({ ok: true, fileId: id, filename: original, s3Key });
  } catch (e) {
    console.error("Upload failed:", e);
    res.status(500).json({ ok: false, error: "upload failed: " + e.message });
  }
});

app.get("/files", auth, async (req, res) => {
  const { page, size, offset, q, sort, order } = listParams(req, {
    sortWhitelist: ["uploaded_at", "size_bytes", "filename"],
    defaultSort: "uploaded_at",
  });

  const where = ["owner = $1"];
  const params = [req.user.sub];
  if (q) {
    where.push(`filename ILIKE $${params.length + 1}`);
    params.push(`%${q}%`);
  }
  const whereSql = `WHERE ${where.join(" AND ")}`;

  const totalRow = await one(`SELECT COUNT(*)::int AS c FROM files ${whereSql}`, params);
  const total = totalRow?.c ?? 0;

  const rows = await all(
    `SELECT id, filename, size_bytes, mime, uploaded_at
     FROM files ${whereSql}
     ORDER BY ${sort} ${order}
     LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, size, offset]
  );

  res.set("X-Total-Count", String(total));
  res.set("X-Page", String(page));
  res.set("X-Page-Size", String(size));
  res.json({ items: rows, total, page, size, sort, order, q });
});

app.get("/files/:id/meta", auth, async (req, res) => {
  const row = await one(`SELECT ext_meta FROM files WHERE id=$1 AND owner=$2`, [
    req.params.id,
    req.user.sub,
  ]);
  if (!row) return res.sendStatus(404);
  const meta = row.ext_meta ?? null;
  res.json({ ok: true, meta });
});

// OpenSubtitles metadata
app.post("/files/:id/subs", auth, async (req, res) => {
  if (!OPENSUBTITLES_API_KEY)
    return res.status(400).json({ ok: false, error: "OPENSUBTITLES_API_KEY missing" });

  const f = await one(`SELECT id FROM files WHERE id=$1 AND owner=$2`, [
    req.params.id,
    req.user.sub,
  ]);
  if (!f) return res.sendStatus(404);

  const query = String(req.body?.query || "").trim();
  const languages = Array.isArray(req.body?.languages) ? req.body.languages : ["en"];
  if (!query) return res.status(400).json({ ok: false, error: "query required" });

  try {
    const url =
      `https://api.opensubtitles.com/api/v1/subtitles?` +
      `query=${encodeURIComponent(query)}&languages=${encodeURIComponent(languages.join(","))}` +
      `&order_by=downloads&order_direction=desc&ai_translated=exclude`;
    const r = await fetch(url, {
      headers: { "Api-Key": OPENSUBTITLES_API_KEY, Accept: "application/json" },
    });
    if (!r.ok) return res.status(502).json({ ok: false, error: `OpenSubtitles HTTP ${r.status}` });
    const j = await r.json();
    const top = Array.isArray(j?.data) ? j.data.slice(0, 5) : [];
    const payload = { opensubtitles: { query, languages, total: j?.total_count ?? top.length, top } };
    await run(
      `UPDATE files
         SET ext_meta = COALESCE(ext_meta, '{}'::jsonb) || $1::jsonb
       WHERE id=$2 AND owner=$3`,
      [JSON.stringify(payload), req.params.id, req.user.sub]
    );
    res.json({ ok: true, count: top.length });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.delete("/files/:id", auth, async (req, res) => {
  const row = await one(`SELECT stored_path FROM files WHERE id=$1 AND owner=$2`, [
    req.params.id,
    req.user.sub,
  ]);
  if (!row) return res.sendStatus(404);

  const r = await run(`DELETE FROM files WHERE id=$1 AND owner=$2`, [
    req.params.id,
    req.user.sub,
  ]);
  if (r.rowCount !== 1) return res.status(500).json({ ok: false, error: "delete failed" });

  // 可选：同时删 S3 对象
  // await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: row.stored_path }));
  res.json({ ok: true });
});

<<<<<<< HEAD




// ----- admin: list all users' files -----
app.get("/admin/files", auth, (req, res) => {
=======
// ----- admin: list all users' files -----
app.get("/admin/files", auth, async (req, res) => {
>>>>>>> database
  if (!req.user?.admin) return res.status(403).json({ ok: false, error: "forbidden" });

  const { page, size, offset, q, sort, order } = listParams(req, {
    sortWhitelist: ["uploaded_at", "size_bytes", "filename", "owner"],
    defaultSort: "uploaded_at",
  });

  const where = [];
  const params = [];
  if (q) {
<<<<<<< HEAD
    // search in filename OR owner
    where.push("(filename LIKE ? OR owner LIKE ?)");
    params.push(`%${q}%`, `%${q}%`);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const total = db.prepare(`SELECT COUNT(*) c FROM files ${whereSql}`).get(...params).c;
  const rows = db.prepare(
    `SELECT id, owner, filename, size_bytes, mime, uploaded_at
     FROM files ${whereSql}
     ORDER BY ${sort} ${order} LIMIT ? OFFSET ?`
  ).all(...params, size, offset);

  res.set("X-Total-Count", String(total));
  res.set("X-Page", String(page));
  res.set("X-Page-Size", String(size));
  res.json({ items: rows, total, page, size, sort, order, q });
});







app.get("/download/original/:fileId", auth, (req, res) => {
  const row = db
    .prepare(`SELECT stored_path,filename FROM files WHERE id=? AND owner=?`)
    .get(req.params.fileId, req.user.sub);
  if (!row || !fs.existsSync(row.stored_path)) return res.sendStatus(404);
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${path.basename(row.filename)}"`
=======
    where.push(`(filename ILIKE $1 OR owner ILIKE $1)`);
    params.push(`%${q}%`);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const totalRow = await one(`SELECT COUNT(*)::int AS c FROM files ${whereSql}`, params);
  const total = totalRow?.c ?? 0;

  const rows = await all(
    `SELECT id, owner, filename, size_bytes, mime, uploaded_at
       FROM files ${whereSql}
      ORDER BY ${sort} ${order}
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, size, offset]
>>>>>>> database
  );

  res.set("X-Total-Count", String(total));
  res.set("X-Page", String(page));
  res.set("X-Page-Size", String(size));
  res.json({ items: rows, total, page, size, sort, order, q });
});

app.get("/download/original/:fileId", auth, async (req, res) => {
  const row = await one(`SELECT stored_path, filename FROM files WHERE id=$1 AND owner=$2`, [
    req.params.fileId,
    req.user.sub,
  ]);
  if (!row) return res.sendStatus(404);

  try {
    const command = new GetObjectCommand({
      Bucket: BUCKET,
      Key: row.stored_path,
      ResponseContentDisposition: `attachment; filename="${row.filename}"`,
    });
    const url = await getSignedUrl(s3, command, { expiresIn: 60 });
    res.json({ downloadUrl: url });
  } catch (err) {
    console.error("Error generating pre-signed URL:", err);
    res.sendStatus(500);
  }
});

// ----- jobs -----
const TRANSCODE_COST_CENTS = 50;

async function createJobWithCharge(owner, fileId, cents, params) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const upd = await client.query(
      `UPDATE accounts
         SET balance_cents = balance_cents - $1, updated_at = now()
       WHERE owner=$2 AND balance_cents >= $1`,
      [cents, owner]
    );
    if (upd.rowCount !== 1) throw new Error("INSUFFICIENT_FUNDS");

    const jobId = uuidv4();
    await client.query(
      `INSERT INTO jobs
         (id, owner, file_id, status, params, charged_cents, created_at, updated_at)
       VALUES ($1,$2,$3,'queued',$4,$5, now(), now())`,
      [jobId, owner, fileId, JSON.stringify(params), cents]
    );
    await client.query("COMMIT");
    return jobId;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

app.get("/jobs", auth, async (req, res) => {
  const { page, size, offset, q, sort, order } = listParams(req, {
    sortWhitelist: ["created_at", "updated_at", "status"],
    defaultSort: "updated_at",
  });

  const status = (req.query.status || "").toLowerCase();
  const where = ["owner = $1"];
  const params = [req.user.sub];

  if (status && ["queued", "running", "completed", "failed"].includes(status)) {
    params.push(status);
    where.push(`LOWER(status) = $${params.length}`);
  }
  if (q) {
    params.push(`%${q}%`);
    where.push(`id::text ILIKE $${params.length}`);
  }
  const whereSql = `WHERE ${where.join(" AND ")}`;

  const totalRow = await one(`SELECT COUNT(*)::int AS c FROM jobs ${whereSql}`, params);
  const total = totalRow?.c ?? 0;

  const rows = await all(
    `SELECT id, file_id, status, progress, charged_cents, refunded_cents,
            created_at, updated_at,
            CASE WHEN thumbnail_path IS NOT NULL THEN 1 ELSE 0 END AS has_thumbnail
       FROM jobs ${whereSql}
      ORDER BY ${sort} ${order}
      LIMIT $${params.length + 1} OFFSET $${params.length + 2}`,
    [...params, size, offset]
  );

  res.set("X-Total-Count", String(total));
  res.set("X-Page", String(page));
  res.set("X-Page-Size", String(size));
  res.json({ items: rows, total, page, size, sort, order, status, q });
});

app.get("/jobs/:id/logs", auth, async (req, res) => {
  const row = await one(`SELECT log FROM jobs WHERE id=$1 AND owner=$2`, [
    req.params.id,
    req.user.sub,
  ]);
  if (!row) return res.sendStatus(404);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send(row.log || "");
});

app.get("/jobs/:id/thumbnail", auth, async (req, res) => {
  const row = await one(`SELECT owner, thumbnail_path, thumbnail_name FROM jobs WHERE id=$1`, [
    req.params.id,
  ]);
  if (!row || row.owner !== req.user.sub || !row.thumbnail_path) return res.sendStatus(404);

  try {
    const cmd = new GetObjectCommand({
      Bucket: BUCKET,
      Key: row.thumbnail_path,
      ResponseContentDisposition: `inline; filename="${path.basename(
        row.thumbnail_name || "thumb.jpg"
      )}"`,
    });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 60 });
    res.json({ url });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});

app.get("/download/transcoded/:jobId", auth, async (req, res) => {
  const j = await one(`SELECT owner,status,output_path,output_name FROM jobs WHERE id=$1`, [
    req.params.jobId,
  ]);
  if (!j || j.owner !== req.user.sub) return res.sendStatus(404);
  if (j.status !== "completed" || !j.output_path)
    return res.status(409).json({ ok: false, error: "not ready" });

  try {
    const command = new GetObjectCommand({
      Bucket: BUCKET,
      Key: j.output_path,
      ResponseContentDisposition: `attachment; filename="${path.basename(
        j.output_name || j.output_path
      )}"`,
    });
    const url = await getSignedUrl(s3, command, { expiresIn: 60 });
    res.json({ downloadUrl: url });
  } catch (err) {
    console.error("Error generating pre-signed URL:", err);
    res.sendStatus(500);
  }
});

app.post("/transcode/:fileId", auth, async (req, res) => {
  const f = await one(
    `SELECT id, stored_path, filename FROM files WHERE id=$1 AND owner=$2`,
    [req.params.fileId, req.user.sub]
  );
  if (!f) return res.sendStatus(404);

  const format = String(req.body?.format || "mp4").toLowerCase();
  const crf = String(req.body?.crf ?? "23");
  const preset = String(req.body?.preset ?? "medium");
  const scale = String(req.body?.scale ?? "1280:720");

  let jobId;
  try {
    jobId = await createJobWithCharge(req.user.sub, f.id, TRANSCODE_COST_CENTS, {
      format,
      crf,
      preset,
      scale,
    });
  } catch (e) {
    if (e.message === "INSUFFICIENT_FUNDS")
      return res.status(402).json({ ok: false, error: "insufficient funds" });
    return res.status(500).json({ ok: false, error: e.message });
  }

  // 立即响应
  res.json({ ok: true, jobId });
  await run(`UPDATE jobs SET status='running', updated_at=now() WHERE id=$1`, [jobId]);

  // 单任务专用 DB 连接（避免连接暴增）
  const dbConn = await pool.connect();

  // 输出文件路径（可能在失败时清理）
  const outId = uuidv4();
  const outName = `${outId}-${path.basename(f.filename, path.extname(f.filename))}.${format}`;
  const outPath = path.join(OUT_DIR, outName);
  let thumbPath = null;

  // —— 批量写日志 & 限频进度 —— //
  let buffered = "";
  let flushTimer = null;
  const flushLog = async () => {
    if (!buffered) return;
    const chunk = buffered;
    buffered = "";
    try {
      await dbConn.query(
        `UPDATE jobs SET log = COALESCE(log,'') || $1, updated_at = now() WHERE id = $2`,
        [chunk, jobId]
      );
    } catch {}
  };
  const appendLog = async (line) => {
    buffered += line + "\n";
    if (!flushTimer) {
      flushTimer = setTimeout(async () => {
        flushTimer = null;
        await flushLog();
      }, 800);
    }
  };
  let lastProgAt = 0;
  const tickProgress = async () => {
    const now = Date.now();
    if (now - lastProgAt > 1000) {
      lastProgAt = now;
      await dbConn.query(
        `UPDATE jobs
            SET progress = LEAST(95, COALESCE(progress,0) + 1),
                updated_at = now()
          WHERE id = $1`,
        [jobId]
      );
    }
  };

  try {
    // 1) 从 S3 读原始文件并转码到本地
    await new Promise(async (resolve, reject) => {
      const s3Object = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: f.stored_path }));
      const s3Stream = s3Object.Body;

      ffmpeg(s3Stream)
        .addOptions([
          "-y",
          "-vf",
          `scale=${scale}`,
          "-preset",
          preset,
          ...(format === "mp4" ? ["-vcodec", "libx264", "-crf", crf, "-movflags", "faststart"] : []),
          ...(format === "webm" ? ["-vcodec", "libvpx-vp9", "-crf", crf, "-b:v", "0"] : []),
        ])
        .on("start", (cmd) => appendLog("FFMPEG START: " + cmd))
        .on("stderr", async (line) => {
          await appendLog(line);
          await tickProgress();
        })
        .on("error", async (err) => {
          await flushLog();
          reject(err);
        })
        .on("end", async () => {
          await flushLog();
          resolve();
        })
        .save(outPath);
    });

    // 2) 上传转码结果到 S3
    const outputKey = `${req.user.sub}/transcoded/${outName}`;
    await s3.send(
      new PutObjectCommand({
        Bucket: BUCKET,
        Key: outputKey,
        Body: fs.createReadStream(outPath),
        ContentType: `video/${format}`,
      })
    );

    // 3) 生成缩略图（本地）
    fs.mkdirSync(THUMB_DIR, { recursive: true });
    const thumbName = `${uuidv4()}-${path.basename(f.filename, path.extname(f.filename))}.jpg`;
    thumbPath = path.join(THUMB_DIR, thumbName);
    await new Promise((resolve, reject) => {
      ffmpeg(outPath)
        .addOptions(["-y", "-ss", "5", "-frames:v", "1"])
        .on("start", (cmd) => appendLog("THUMB START: " + cmd))
        .on("error", async (err) => {
          await flushLog();
          reject(err);
        })
        .on("end", async () => {
          await flushLog();
          resolve();
        })
        .save(thumbPath);
    });

    // 4) 上传缩略图到 S3
    const thumbKey = `${req.user.sub}/thumbnails/${thumbName}`;
    await s3.send(
      new PutObjectCommand({
        Bucket: BUCKET,
        Key: thumbKey,
        Body: fs.createReadStream(thumbPath),
        ContentType: "image/jpeg",
      })
    );

    // 5) 清理本地临时文件
    try {
      fs.unlinkSync(thumbPath);
    } catch {}
    try {
      fs.unlinkSync(outPath);
    } catch {}

    // 6) 更新任务完成
    await dbConn.query(
      `UPDATE jobs SET status='completed', progress=100,
         output_path=$1, output_name=$2, thumbnail_path=$3, thumbnail_name=$4,
         updated_at=now()
       WHERE id=$5`,
      [outputKey, outName, thumbKey, thumbName, jobId]
    );
  } catch (e) {
    await appendLog("ERROR: " + e.message);
    await flushLog();
    await dbConn.query(`UPDATE jobs SET status='failed', updated_at=now() WHERE id=$1`, [jobId]);

    // 失败退款（幂等）
    try {
      await dbConn.query("BEGIN");
      const r = await dbConn.query(
        `SELECT refunded_cents FROM jobs WHERE id=$1 AND owner=$2 FOR UPDATE`,
        [jobId, req.user.sub]
      );
      const refunded = r.rows?.[0]?.refunded_cents ?? 0;
      if (refunded === 0) {
        await dbConn.query(
          `UPDATE accounts SET balance_cents = balance_cents + $1, updated_at=now() WHERE owner=$2`,
          [TRANSCODE_COST_CENTS, req.user.sub]
        );
        await dbConn.query(
          `UPDATE jobs SET refunded_cents = refunded_cents + $1, updated_at=now() WHERE id=$2`,
          [TRANSCODE_COST_CENTS, jobId]
        );
      }
      await dbConn.query("COMMIT");
    } catch (e2) {
      await dbConn.query("ROLLBACK");
      console.error("refund error:", e2);
    }

    // 清理本地临时文件（失败场景）
    try {
      if (thumbPath && fs.existsSync(thumbPath)) fs.unlinkSync(thumbPath);
    } catch {}
    try {
      if (fs.existsSync(outPath)) fs.unlinkSync(outPath);
    } catch {}
  } finally {
    await flushLog();
    if (flushTimer) clearTimeout(flushTimer);
    dbConn.release();
  }
});

app.get("/outputs", auth, (_req, res) => {
  const items = fs.readdirSync(OUT_DIR).filter((f) => !f.startsWith("."));
  res.json({ items });
});

// —— 启动时自动建表（可留可删，不影响既有表） —— //
async function ensureTables() {
  await run(`
    CREATE TABLE IF NOT EXISTS accounts (
      owner TEXT PRIMARY KEY,
      balance_cents INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files (
      id TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      filename TEXT NOT NULL,
      stored_path TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      mime TEXT,
      uploaded_at TIMESTAMPTZ NOT NULL,
      ext_meta JSONB
    );
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      file_id TEXT NOT NULL,
      status TEXT NOT NULL,
      params JSONB NOT NULL DEFAULT '{}'::jsonb,
      progress REAL NOT NULL DEFAULT 0,
      log TEXT NOT NULL DEFAULT '',
      charged_cents INTEGER NOT NULL DEFAULT 0,
      refunded_cents INTEGER NOT NULL DEFAULT 0,
      output_path TEXT,
      output_name TEXT,
      thumbnail_path TEXT,
      thumbnail_name TEXT,
      created_at TIMESTAMPTZ NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_jobs_updated_at ON jobs(updated_at);
  `);
}
await ensureTables();

// ===== DIAG (临时排查用，用完可删) =====
function mask(s) {
  if (!s) return null;
  return s.slice(0,4) + '...' + s.slice(-4);
}
app.get("/__diag", (_req, res) => {
  res.json({
    region: COG_REGION,
    userPool: COG_USER_POOL_ID,
    clientId: COG_CLIENT_ID,
    hasSecret: !!COG_CLIENT_SECRET,
    clientSecretMasked: mask(COG_CLIENT_SECRET),
    secretHash_admin_prefix: makeSecretHash("admin")?.slice(0,8) || null
  });
});

// 启动时也打一下（方便看控制台）
log("[COG] region=%s pool=%s clientId=%s hasSecret=%s secret=%s hash(admin)=%s",
  COG_REGION, COG_USER_POOL_ID, COG_CLIENT_ID, !!COG_CLIENT_SECRET,
  mask(COG_CLIENT_SECRET),
  makeSecretHash("admin")?.slice(0,8) || null
);

// ----- start -----
app.listen(PORT, () => {
  log(`Server listening on http://localhost:${PORT}`);
});
