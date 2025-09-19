import express from "express";
import cors from "cors";
import multer from "multer";
import Database from "better-sqlite3";
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
import fetch from "node-fetch"; // npm i node-fetch@2

// === Cognito ===
import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import crypto from "crypto";

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
    if (
      (v.startsWith('"') && v.endsWith('"')) ||
      (v.startsWith("'") && v.endsWith("'"))
    ) {
      v = v.slice(1, -1);
    }
    if (process.env[k] === undefined) process.env[k] = v;
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
const COG_CLIENT_SECRET = process.env.COGNITO_CLIENT_SECRET || "";

const cogClient = new CognitoIdentityProviderClient({ region: COG_REGION });

const hasSecret = !!COG_CLIENT_SECRET;

// HMAC
function makeSecretHash(username) {
  if (!hasSecret) return null;
  const hmac = crypto.createHmac("sha256", COG_CLIENT_SECRET);
  hmac.update(`${username}${COG_CLIENT_ID}`);
  return hmac.digest("base64");
}

// Verifier for Cognito ID token
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

// 预置两个账户
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

// ----- app -----
const app = express();
app.use(cors());
app.use(express.json());
app.use("/", express.static(path.join(__dirname, "public")));
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// === Cognito: signup / confirm / login ===
app.post("/auth/signup", async (req, res) => {
  const { username, password, email } = req.body || {};
  if (!username || !password || !email) {
    return res
      .status(400)
      .json({ ok: false, error: "username, password, email required" });
  }
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
    res
      .status(400)
      .json({ ok: false, error: e.name || "SignUpError", message: e.message });
  }
});

app.post("/auth/confirm", async (req, res) => {
  const { username, code } = req.body || {};
  if (!username || !code) {
    return res
      .status(400)
      .json({ ok: false, error: "username, code required" });
  }
  try {
    const params = {
      ClientId: COG_CLIENT_ID,
      Username: username,
      ConfirmationCode: code,
    };
    const sh = makeSecretHash(username);
    if (sh) params.SecretHash = sh;
    await cogClient.send(new ConfirmSignUpCommand(params));
    res.json({ ok: true });
  } catch (e) {
    res
      .status(400)
      .json({ ok: false, error: e.name || "ConfirmError", message: e.message });
  }
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password)
    return res
      .status(400)
      .json({ ok: false, error: "username, password required" });

  try {
    const authParams = {
      USERNAME: username,
      PASSWORD: password,
    };
    const sh = makeSecretHash(username);
    if (sh) authParams.SECRET_HASH = sh;

    const out = await cogClient.send(
      new InitiateAuthCommand({
        AuthFlow: "USER_PASSWORD_AUTH",
        ClientId: COG_CLIENT_ID,
        AuthParameters: authParams,
      })
    );

    const idToken = out?.AuthenticationResult?.IdToken;
    if (!idToken) return res.status(401).json({ ok: false, error: "no token" });

    db.prepare(
      `INSERT INTO accounts(owner,balance_cents,updated_at)
       VALUES(?,0,datetime('now')) ON CONFLICT(owner) DO NOTHING`
    ).run(username);

    res.json({ ok: true, authToken: idToken });
  } catch (e) {
    res
      .status(401)
      .json({ ok: false, error: e.name || "AuthError", message: e.message });
  }
});

// whoami：convenient for you to test whether Bearer token is included
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
    const isAdmin = username.toLowerCase() === "admin";

    req.user = {
      sub: username,
      email: payload.email || null,
      jwt: m[1],
      admin: false,
    };
    next();
  } catch (e) {
    return res
      .status(401)
      .json({ ok: false, error: "invalid token", detail: e.message });
  }
}

// ======================================new Added section=====================================
//  ===  Set up storage for files ===
//  ===  S3 client ===
const s3 = new S3Client({ region: process.env.AWS_REGION });
const BUCKET = process.env.AWS_S3_BUCKET;

// Multer 記憶體存放
// ----- Multer DiskStorage -----
const tmpDir = path.join(process.cwd(), "uploads");

// 確保資料夾存在
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, tmpDir),
  filename: (_req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
// ======================================new Added section=====================================

const upload = multer({ storage });
// ----- helpers -----

function listParams(req, opt) {
  const page = Math.max(1, parseInt(req.query.page || "1", 10));
  const size = Math.min(100, Math.max(1, parseInt(req.query.size || "10", 10)));
  const q = (req.query.q || "").trim();
  const sort = opt.sortWhitelist.includes(req.query.sort)
    ? req.query.sort
    : opt.defaultSort;
  const order =
    (req.query.order || "desc").toLowerCase() === "asc" ? "asc" : "desc";
  const offset = (page - 1) * size;
  return { page, size, offset, q, sort, order };
}

// ----- account -----
app.get("/me", auth, (req, res) => {
  const a = db
    .prepare(`SELECT balance_cents, updated_at FROM accounts WHERE owner=?`)
    .get(req.user.sub);
  res.json({
    user: req.user.sub,
    admin: !!req.user.admin, // ensure this is present
    balance_cents: a?.balance_cents ?? 0,
    updated_at: a?.updated_at ?? null,
  });
});

app.post("/accounts/topup", auth, (req, res) => {
  const amount = Number(req.body?.amount_cents ?? 0);
  if (!Number.isInteger(amount) || amount <= 0)
    return res.status(400).json({ ok: false, error: "invalid amount" });
  db.prepare(
    `INSERT INTO accounts(owner,balance_cents,updated_at)
     VALUES(?,?,datetime('now'))
     ON CONFLICT(owner) DO UPDATE
     SET balance_cents = balance_cents + excluded.balance_cents,
         updated_at = datetime('now')`
  ).run(req.user.sub, amount);
  res.json({ ok: true, added: amount });
});

// ----- files -----
app.post("/upload", auth, upload.single("file"), async (req, res) => {
  if (!req.file) return res.status(400).json({ ok: false, error: "no file" });
  const id = uuidv4();
  const original = req.file.originalname || "upload.bin";
  const safeName = `${id}-${original.replace(/[^\w.\-]+/g, "_")}`;

  // ======================================new Added section=====================================
  const username = req.user.sub;
  const s3Key = `${username}/uploaded/${safeName}`;
  const fileStream = fs.createReadStream(req.file.path);
  console.log("Temp file path:", req.file.path);
  try {
    // 上傳到 S3
    const command = new PutObjectCommand({
      Bucket: BUCKET,
      Key: s3Key,
      Body: fileStream,
      ContentType: req.file.mimetype,
    });
    await s3.send(command);

    // 上傳完成，刪掉本地暫存
    try {
      fs.unlinkSync(req.file.path);
    } catch {}

    // 存資料庫
    db.prepare(
      `INSERT INTO files (id,owner,filename,stored_path,size_bytes,mime,uploaded_at)
       VALUES (?,?,?,?,?,?,datetime('now'))`
    ).run(
      id,
      username,
      original,
      s3Key,
      req.file.size,
      req.file.mimetype || null
    );

    res.json({ ok: true, fileId: id, filename: original, s3Key });
  } catch (e) {
    console.error("Upload failed:", e);
    res.status(500).json({ ok: false, error: "upload failed: " + e.message });
  }
});
// ======================================new Added section=====================================

app.get("/files", auth, (req, res) => {
  const { page, size, offset, q, sort, order } = listParams(req, {
    sortWhitelist: ["uploaded_at", "size_bytes", "filename"],
    defaultSort: "uploaded_at",
  });
  const where = ["owner=?"];
  const params = [req.user.sub];
  if (q) {
    where.push("filename LIKE ?");
    params.push(`%${q}%`);
  }
  const whereSql = `WHERE ${where.join(" AND ")}`;
  const total = db
    .prepare(`SELECT COUNT(*) c FROM files ${whereSql}`)
    .get(...params).c;
  const rows = db
    .prepare(
      `SELECT id,filename,size_bytes,mime,uploaded_at
     FROM files ${whereSql}
     ORDER BY ${sort} ${order} LIMIT ? OFFSET ?`
    )
    .all(...params, size, offset);
  res.set("X-Total-Count", String(total));
  res.set("X-Page", String(page));
  res.set("X-Page-Size", String(size));
  res.json({ items: rows, total, page, size, sort, order, q });
});

app.get("/files/:id/meta", auth, (req, res) => {
  const row = db
    .prepare(`SELECT ext_meta FROM files WHERE id=? AND owner=?`)
    .get(req.params.id, req.user.sub);
  if (!row) return res.sendStatus(404);
  let meta = null;
  try {
    meta = row.ext_meta ? JSON.parse(row.ext_meta) : null;
  } catch {}
  res.json({ ok: true, meta });
});

// OpenSubtitles metadata
app.post("/files/:id/subs", auth, async (req, res) => {
  if (!OPENSUBTITLES_API_KEY)
    return res
      .status(400)
      .json({ ok: false, error: "OPENSUBTITLES_API_KEY missing" });

  const f = db
    .prepare(`SELECT id FROM files WHERE id=? AND owner=?`)
    .get(req.params.id, req.user.sub);
  if (!f) return res.sendStatus(404);

  const query = String(req.body?.query || "").trim();
  const languages = Array.isArray(req.body?.languages)
    ? req.body.languages
    : ["en"];
  if (!query)
    return res.status(400).json({ ok: false, error: "query required" });

  try {
    const url =
      `https://api.opensubtitles.com/api/v1/subtitles?` +
      `query=${encodeURIComponent(query)}&languages=${encodeURIComponent(
        languages.join(",")
      )}` +
      `&order_by=downloads&order_direction=desc&ai_translated=exclude`;
    const r = await fetch(url, {
      headers: { "Api-Key": OPENSUBTITLES_API_KEY, Accept: "application/json" },
    });
    if (!r.ok)
      return res
        .status(502)
        .json({ ok: false, error: `OpenSubtitles HTTP ${r.status}` });
    const j = await r.json();
    const top = Array.isArray(j?.data) ? j.data.slice(0, 5) : [];
    const payload = {
      opensubtitles: {
        query,
        languages,
        total: j?.total_count ?? top.length,
        top,
      },
    };
    db.prepare(
      `UPDATE files
       SET ext_meta=json_patch(COALESCE(ext_meta,'{}'), json(?))
       WHERE id=?`
    ).run(JSON.stringify(payload), req.params.id);
    res.json({ ok: true, count: top.length });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.delete("/files/:id", auth, (req, res) => {
  const row = db
    .prepare(`SELECT stored_path FROM files WHERE id=? AND owner=?`)
    .get(req.params.id, req.user.sub);
  if (!row) return res.sendStatus(404);
  const r = db
    .prepare(`DELETE FROM files WHERE id=? AND owner=?`)
    .run(req.params.id, req.user.sub);
  if (r.changes !== 1)
    return res.status(500).json({ ok: false, error: "delete failed" });
  try {
    fs.unlinkSync(row.stored_path);
  } catch (e) {
    log("unlink warn:", e.message);
  }
  res.json({ ok: true });
});

// ----- admin: list all users' files -----
app.get("/admin/files", auth, (req, res) => {
  if (!req.user?.admin)
    return res.status(403).json({ ok: false, error: "forbidden" });

  const { page, size, offset, q, sort, order } = listParams(req, {
    sortWhitelist: ["uploaded_at", "size_bytes", "filename", "owner"],
    defaultSort: "uploaded_at",
  });

  const where = [];
  const params = [];
  if (q) {
    // search in filename OR owner
    where.push("(filename LIKE ? OR owner LIKE ?)");
    params.push(`%${q}%`, `%${q}%`);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const total = db
    .prepare(`SELECT COUNT(*) c FROM files ${whereSql}`)
    .get(...params).c;
  const rows = db
    .prepare(
      `SELECT id, owner, filename, size_bytes, mime, uploaded_at
     FROM files ${whereSql}
     ORDER BY ${sort} ${order} LIMIT ? OFFSET ?`
    )
    .all(...params, size, offset);

  res.set("X-Total-Count", String(total));
  res.set("X-Page", String(page));
  res.set("X-Page-Size", String(size));
  res.json({ items: rows, total, page, size, sort, order, q });
});

app.get("/download/original/:fileId", auth, async (req, res) => {
  const row = db
    .prepare(`SELECT stored_path, filename FROM files WHERE id=? AND owner=?`)
    .get(req.params.fileId, req.user.sub);

  if (!row) return res.sendStatus(404);

  try {
    // 假設 stored_path 存的是 S3 key（例如 "uploads/xxx.mp4"）
    const command = new GetObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: row.stored_path,
      ResponseContentDisposition: `attachment; filename="${row.filename}"`, // 保留原檔名
    });

    // 簽發 60 秒的 pre-signed URL
    const url = await getSignedUrl(s3, command, { expiresIn: 60 });

    res.json({ downloadUrl: url });
  } catch (err) {
    console.error("Error generating pre-signed URL:", err);
    res.sendStatus(500);
  }
});

// app.get("/download/original/:fileId", auth, (req, res) => {
//   const row = db
//     .prepare(`SELECT stored_path,filename FROM files WHERE id=? AND owner=?`)
//     .get(req.params.fileId, req.user.sub);
//   if (!row || !fs.existsSync(row.stored_path)) return res.sendStatus(404);
//   res.setHeader(
//     "Content-Disposition",
//     `attachment; filename="${path.basename(row.filename)}"`
//   );
//   res.sendFile(row.stored_path);
// });

// ----- jobs -----
const TRANSCODE_COST_CENTS = 50;
const createJobWithCharge = db.transaction((owner, fileId, cents, params) => {
  const u = db
    .prepare(
      `UPDATE accounts
     SET balance_cents = balance_cents - ?, updated_at = datetime('now')
     WHERE owner=? AND balance_cents >= ?`
    )
    .run(cents, owner, cents);
  if (u.changes !== 1) throw new Error("INSUFFICIENT_FUNDS");
  const jobId = uuidv4();
  db.prepare(
    `INSERT INTO jobs (id,owner,file_id,status,params,charged_cents,created_at,updated_at)
     VALUES (?,?,?,?,?,'queued',datetime('now'),datetime('now'))`
  ).run(jobId, owner, fileId, JSON.stringify(params), cents);
  return jobId;
});

app.get("/jobs", auth, (req, res) => {
  const { page, size, offset, q, sort, order } = listParams(req, {
    sortWhitelist: ["created_at", "updated_at", "status"],
    defaultSort: "updated_at",
  });
  const status = (req.query.status || "").toLowerCase();
  const where = ["owner=?"];
  const params = [req.user.sub];
  if (status && ["queued", "running", "completed", "failed"].includes(status)) {
    where.push("LOWER(status)=?");
    params.push(status);
  }
  if (q) {
    where.push("id LIKE ?");
    params.push(`%${q}%`);
  }
  const whereSql = `WHERE ${where.join(" AND ")}`;
  const total = db
    .prepare(`SELECT COUNT(*) c FROM jobs ${whereSql}`)
    .get(...params).c;
  const rows = db
    .prepare(
      `SELECT id,file_id,status,progress,charged_cents,refunded_cents,created_at,updated_at,
            CASE WHEN thumbnail_path IS NOT NULL THEN 1 ELSE 0 END AS has_thumbnail
     FROM jobs ${whereSql}
     ORDER BY ${sort} ${order} LIMIT ? OFFSET ?`
    )
    .all(...params, size, offset);
  res.set("X-Total-Count", String(total));
  res.set("X-Page", String(page));
  res.set("X-Page-Size", String(size));
  res.json({ items: rows, total, page, size, sort, order, status, q });
});

app.get("/jobs/:id/logs", auth, (req, res) => {
  const row = db
    .prepare(`SELECT log FROM jobs WHERE id=? AND owner=?`)
    .get(req.params.id, req.user.sub);
  if (!row) return res.sendStatus(404);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.send(row.log || "");
});

app.get("/jobs/:id/thumbnail", auth, (req, res) => {
  const row = db
    .prepare(`SELECT owner,thumbnail_path,thumbnail_name FROM jobs WHERE id=?`)
    .get(req.params.id);
  if (
    !row ||
    row.owner !== req.user.sub ||
    !row.thumbnail_path ||
    !fs.existsSync(row.thumbnail_path)
  )
    return res.sendStatus(404);
  res.setHeader(
    "Content-Disposition",
    `inline; filename="${path.basename(row.thumbnail_name || "thumb.jpg")}"`
  );
  res.sendFile(row.thumbnail_path);
});

app.get("/download/transcoded/:jobId", auth, async (req, res) => {
  const j = db
    .prepare(`SELECT owner,status,output_path,output_name FROM jobs WHERE id=?`)
    .get(req.params.jobId);

  if (!j || j.owner !== req.user.sub) return res.sendStatus(404);

  // 檔案還沒完成或沒有 S3 Key
  if (j.status !== "completed" || !j.output_path)
    return res.status(409).json({ ok: false, error: "not ready" });

  try {
    const command = new GetObjectCommand({
      Bucket: process.env.AWS_S3_BUCKET,
      Key: j.output_path, // 這裡必須是 S3 Key
      ResponseContentDisposition: `attachment; filename="${path.basename(j.output_name || j.output_path)}"`,
    });

    const url = await getSignedUrl(s3, command, { expiresIn: 60 });

    res.json({ downloadUrl: url });
  } catch (err) {
    console.error("Error generating pre-signed URL:", err);
    res.sendStatus(500);
  }
});


  //   return res.status(409).json({ ok: false, error: "not ready" });
  // res.setHeader(
  //   "Content-Disposition",
  //   `attachment; filename="${path.basename(j.output_name || j.output_path)}"`
  // );
  // res.sendFile(j.output_path);


app.post("/transcode/:fileId", auth, async (req, res) => {
  const f = db
    .prepare(`SELECT id,stored_path,filename FROM files WHERE id=? AND owner=?`)
    .get(req.params.fileId, req.user.sub);
  if (!f) return res.sendStatus(404);

  const format = String(req.body?.format || "mp4").toLowerCase();
  const crf = String(req.body?.crf ?? "23");
  const preset = String(req.body?.preset ?? "medium");
  const scale = String(req.body?.scale ?? "1280:720");

  let jobId;
  try {
    jobId = createJobWithCharge(req.user.sub, f.id, TRANSCODE_COST_CENTS, {
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

  res.json({ ok: true, jobId });
  db.prepare(
    `UPDATE jobs SET status='running', updated_at=datetime('now') WHERE id=?`
  ).run(jobId);

  const outId = uuidv4();
  const outName = `${outId}-${path.basename(
    f.filename,
    path.extname(f.filename)
  )}.${format}`;
  const outPath = path.join(OUT_DIR, outName);
  let logBuf = "";
  const appendLog = (s) => {
    logBuf += s + "\n";
    db.prepare(
      `UPDATE jobs SET log=?, updated_at=datetime('now') WHERE id=?`
    ).run(logBuf, jobId);
  };

  // Transcoding
  try {
    await new Promise(async (resolve, reject) => {
      const getCommand = new GetObjectCommand({
        Bucket: BUCKET,
        Key: f.stored_path,
      });
      const s3Object = await s3.send(getCommand);
      const s3Stream = s3Object.Body; // Readable stream

      ffmpeg(s3Stream)
        .addOptions([
          "-y",
          `-vf`,
          `scale=${scale}`,
          "-preset",
          preset,
          ...(format === "mp4"
            ? ["-vcodec", "libx264", "-crf", crf, "-movflags", "faststart"]
            : []),
          ...(format === "webm"
            ? ["-vcodec", "libvpx-vp9", "-crf", crf, "-b:v", "0"]
            : []),
        ])
        .on("start", (cmd) => appendLog("FFMPEG START: " + cmd))
        .on("stderr", (line) => {
          appendLog(line);
          const cur =
            db.prepare(`SELECT progress FROM jobs WHERE id=?`).get(jobId)
              ?.progress ?? 0;
          const p = Math.min(95, cur + 1);
          db.prepare(
            `UPDATE jobs SET progress=?, updated_at=datetime('now') WHERE id=?`
          ).run(p, jobId);
        })
        .on("error", (err) => reject(err))
        .on("end", () => resolve())
        .save(outPath); // 還是存到本地暫存再上傳到 S3
    });

    // 2️⃣ 上傳轉檔結果到 S3
    const outputKey = `${req.user.sub}/transcoded/${outName}`;
    await s3.send(
      new PutObjectCommand({
        Bucket: BUCKET,
        Key: outputKey,
        Body: fs.createReadStream(outPath),
        ContentType: `video/${format}`,
      })
    );
    // fs.unlinkSync(outPath); // 刪掉本地暫存

    // thumbnail
    fs.mkdirSync(THUMB_DIR, { recursive: true });
    const thumbName = `${uuidv4()}-${path.basename(
      f.filename,
      path.extname(f.filename)
    )}.jpg`;
    const thumbPath = path.join(THUMB_DIR, thumbName);
    await new Promise(async (resolve, reject) => {
      // const s3ObjectThumb = await s3.send(getCommand);
      // const s3StreamThumb = s3ObjectThumb.Body; // Readable stream
      ffmpeg(outPath)
        .addOptions(["-y", "-ss", "5", "-frames:v", "1"])
        .on("start", (cmd) => appendLog("THUMB START: " + cmd))
        .on("error", (err) => reject(err))
        .on("end", () => resolve())
        .save(thumbPath);
    });

    // 4️⃣ 上傳縮圖到 S3
    const thumbKey = `${req.user.sub}/thumbnails/${thumbName}`;
    await s3.send(
      new PutObjectCommand({
        Bucket: BUCKET,
        Key: thumbKey,
        Body: fs.createReadStream(thumbPath),
        ContentType: "image/jpeg",
      })
    );
    fs.unlinkSync(thumbPath); // 刪掉本地暫存
    fs.unlinkSync(outPath); // 刪掉本地暫存

    // update DB
    db.prepare(
      `UPDATE jobs SET status='completed', progress=100,
        output_path=?, output_name=?, thumbnail_path=?, thumbnail_name=?,
        updated_at=datetime('now')
       WHERE id=?`
    ).run(outputKey, outName, thumbKey, thumbName, jobId);
  } catch (e) {
    appendLog("ERROR: " + e.message);
    db.prepare(
      `UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?`
    ).run(jobId);
    // refund
    db.transaction((owner, amount) => {
      const row = db
        .prepare(`SELECT refunded_cents FROM jobs WHERE id=? AND owner=?`)
        .get(jobId, owner);
      if (!row || row.refunded_cents > 0) return;
      db.prepare(
        `UPDATE accounts SET balance_cents=balance_cents+?, updated_at=datetime('now') WHERE owner=?`
      ).run(amount, owner);
      db.prepare(
        `UPDATE jobs SET refunded_cents=refunded_cents+?, updated_at=datetime('now') WHERE id=?`
      ).run(amount, jobId);
    })(req.user.sub, TRANSCODE_COST_CENTS);
  }
});

app.get("/outputs", auth, (_req, res) => {
  const items = fs.readdirSync(OUT_DIR).filter((f) => !f.startsWith("."));
  res.json({ items });
});

// ----- start -----
app.listen(PORT, () => {
  log(`Server listening on http://localhost:${PORT}`);
  log(`DATA_DIR: ${DATA_DIR}`);
});
