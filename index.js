import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import multer from "multer";
import { v4 as uuidv4 } from "uuid";
import ffmpeg from "fluent-ffmpeg";
import ffmpegInstaller from "@ffmpeg-installer/ffmpeg";
import fs from "fs";
import path from "path";

const log = (...args) => console.log(new Date().toISOString(), ...args);
const nowIso = () => new Date().toISOString();

// ---------- App ----------
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

app.use(cors());
app.use(express.json());
app.use("/", express.static("public")); // web client

// ---------- FFmpeg ----------
ffmpeg.setFfmpegPath(ffmpegInstaller.path);

// ---------- Data directories ----------
const DATA_DIR = path.join(process.cwd(), "data");
const UP_DIR = path.join(DATA_DIR, "uploads");
const OUT_DIR = path.join(DATA_DIR, "outputs");
for (const d of [DATA_DIR, UP_DIR, OUT_DIR]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// ---------- Database (RDS first, SQLite fallback) ----------
let dbType = "sqlite";
let pool = null;      // mysql2/promise pool (for MySQL/RDS)
let sqliteDb = null;  // better-sqlite3 instance (for local fallback)

await initDb();

// Try to use MySQL (RDS). If env vars are missing, fall back to SQLite.
async function initDb() {
  if (process.env.RDS_HOST) {
    const mysql = await import("mysql2/promise");
    pool = mysql.createPool({
      host: process.env.RDS_HOST,
      user: process.env.RDS_USER,
      password: process.env.RDS_PASSWORD,
      database: process.env.RDS_DB,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });
    dbType = "mysql";
    log("DB: Using MySQL (RDS)");
    await ensureSchemaMySQL();
  } else {
    const Database = (await import("better-sqlite3")).default;
    sqliteDb = new Database(path.join(DATA_DIR, "app.db"));
    sqliteDb.pragma("journal_mode = WAL"); // durability for SQLite
    dbType = "sqlite";
    log("DB: Using SQLite (WAL) fallback");
    ensureSchemaSQLite();
  }
}

// Create tables for MySQL (RDS)
async function ensureSchemaMySQL() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS files (
      id VARCHAR(36) PRIMARY KEY,
      owner VARCHAR(255) NOT NULL,
      filename VARCHAR(255) NOT NULL,
      size BIGINT NOT NULL,
      uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS jobs (
      id VARCHAR(36) PRIMARY KEY,
      owner VARCHAR(255) NOT NULL,
      file_id VARCHAR(36) NOT NULL,
      status VARCHAR(20) NOT NULL,
      params TEXT NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      output_filename VARCHAR(255)
    )
  `);
}

// Create/guard tables for SQLite (schema matches your original)
function ensureSchemaSQLite() {
  const wantFiles = ["id", "owner", "filename", "size", "uploaded_at"];
  const wantJobs  = ["id", "owner", "file_id", "status", "params", "created_at", "updated_at", "output_filename"];
  const cols = (t) => sqliteDb.prepare(`PRAGMA table_info(${t});`).all().map(r => r.name);
  let filesCols = []; let jobsCols = [];
  try { filesCols = cols("files"); } catch {}
  try { jobsCols  = cols("jobs"); }  catch {}
  const same = (got, want) => got.length && want.every(c => got.includes(c)) && got.length === want.length;

  if (!same(filesCols, wantFiles) || !same(jobsCols, wantJobs)) {
    log("SCHEMA: mismatch -> recreate tables", { filesCols, jobsCols });
    sqliteDb.exec(`
      DROP TABLE IF EXISTS files;
      DROP TABLE IF EXISTS jobs;
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        filename TEXT NOT NULL,
        size INTEGER NOT NULL,
        uploaded_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        file_id TEXT NOT NULL,
        status TEXT NOT NULL,
        params TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        output_filename TEXT
      );
    `);
  }
}

// ---------- Users (hard-coded, same as your latest) ----------
const USERS = {
  admin: { password: "admin123", role: "admin" },
  user:  { password: "alice123", role: "alice" },
};

// ---------- Auth middleware ----------
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer (.+)$/);
  if (!m) return res.status(401).json({ ok: false, error: "missing bearer token" });
  try { req.user = jwt.verify(m[1], JWT_SECRET); next(); }
  catch { return res.status(401).json({ ok: false, error: "invalid token" }); }
}

// ---------- Routes ----------
app.get("/", (_req, res) => {
  res.json({ ok: true, msg: "Video API is up" });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (!u || u.password !== password) return res.status(401).json({ ok: false, error: "bad credentials" });
  const token = jwt.sign({ sub: username, role: u.role }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ ok: true, token, user: { username, role: u.role } });
});

// ---------- Upload (stores file metadata into DB) ----------
const upload = multer({ dest: UP_DIR });
app.post("/upload", auth, upload.single("video"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: "no file" });
    const fileId = uuidv4();
    const ext = path.extname(req.file.originalname || ".mp4") || ".mp4";
    const finalName = `${fileId}${ext}`;
    fs.renameSync(req.file.path, path.join(UP_DIR, finalName));

    if (dbType === "mysql") {
      await pool.query(
        "INSERT INTO files (id, owner, filename, size) VALUES (?, ?, ?, ?)",
        [fileId, req.user.sub, finalName, req.file.size]
      );
      const [rows] = await pool.query("SELECT COUNT(*) AS c FROM files WHERE owner=?", [req.user.sub]);
      const total = rows[0]?.c ?? 0;
      log("UPLOAD: ok", { owner: req.user.sub, fileId, size: req.file.size });
      return res.json({ ok: true, fileId, filename: finalName, totalFiles: total });
    } else {
      sqliteDb.prepare(
        "INSERT INTO files (id, owner, filename, size, uploaded_at) VALUES (?, ?, ?, ?, datetime('now'))"
      ).run(fileId, req.user.sub, finalName, req.file.size);
      const total = sqliteDb.prepare("SELECT COUNT(*) AS c FROM files WHERE owner=?").get(req.user.sub).c;
      log("UPLOAD: ok", { owner: req.user.sub, fileId, size: req.file.size });
      return res.json({ ok: true, fileId, filename: finalName, totalFiles: total });
    }
  } catch (e) {
    log("UPLOAD: error", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------- List files (paged) ----------
app.get("/files", auth, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const size = Math.min(50, Math.max(1, parseInt(req.query.size || "10", 10)));
    const offset = (page - 1) * size;

    if (dbType === "mysql") {
      const [items] = await pool.query(
        "SELECT id, filename, size, uploaded_at FROM files WHERE owner=? ORDER BY uploaded_at DESC LIMIT ? OFFSET ?",
        [req.user.sub, size, offset]
      );
      const [rows] = await pool.query("SELECT COUNT(*) AS c FROM files WHERE owner=?", [req.user.sub]);
      const total = rows[0]?.c ?? 0;
      log("FILES:", { owner: req.user.sub, page, size, count: items.length, total });
      return res.json({ ok: true, page, size, total, items });
    } else {
      const items = sqliteDb.prepare(
        "SELECT id, filename, size, uploaded_at FROM files WHERE owner=? ORDER BY uploaded_at DESC LIMIT ? OFFSET ?"
      ).all(req.user.sub, size, offset);
      const total = sqliteDb.prepare("SELECT COUNT(*) AS c FROM files WHERE owner=?").get(req.user.sub).c;
      log("FILES:", { owner: req.user.sub, page, size, count: items.length, total });
      return res.json({ ok: true, page, size, total, items });
    }
  } catch (e) {
    log("FILES: error", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------- List jobs (paged) ----------
app.get("/jobs", auth, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const size = Math.min(50, Math.max(1, parseInt(req.query.size || "10", 10)));
    const offset = (page - 1) * size;

    if (dbType === "mysql") {
      const [items] = await pool.query(
        `SELECT id, file_id, status, created_at, updated_at, output_filename
         FROM jobs WHERE owner=? ORDER BY created_at DESC LIMIT ? OFFSET ?`,
        [req.user.sub, size, offset]
      );
      const [rows] = await pool.query("SELECT COUNT(*) AS c FROM jobs WHERE owner=?", [req.user.sub]);
      const total = rows[0]?.c ?? 0;
      log("JOBS(list):", { owner: req.user.sub, page, size, count: items.length, total });
      return res.json({ ok: true, page, size, total, items });
    } else {
      const items = sqliteDb.prepare(
        `SELECT id, file_id, status, created_at, updated_at, output_filename
         FROM jobs WHERE owner=? ORDER BY created_at DESC LIMIT ? OFFSET ?`
      ).all(req.user.sub, size, offset);
      const total = sqliteDb.prepare("SELECT COUNT(*) AS c FROM jobs WHERE owner=?").get(req.user.sub).c;
      log("JOBS(list):", { owner: req.user.sub, page, size, count: items.length, total });
      return res.json({ ok: true, page, size, total, items });
    }
  } catch (e) {
    log("JOBS(list): error", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ---------- Single job ----------
app.get("/jobs/:jobId", auth, async (req, res) => {
  let j;
  if (dbType === "mysql") {
    const [rows] = await pool.query("SELECT * FROM jobs WHERE id=? AND owner=?", [req.params.jobId, req.user.sub]);
    j = rows[0];
  } else {
    j = sqliteDb.prepare("SELECT * FROM jobs WHERE id=? AND owner=?").get(req.params.jobId, req.user.sub);
  }
  if (!j) return res.status(404).json({ ok: false, error: "not found" });
  res.json({ ok: true, job: { ...j, params: JSON.parse(j.params) } });
});

// ---------- Job logs (in-memory, unchanged) ----------
const jobLogs = new Map(); // jobId => lines[]
app.get("/jobs/:jobId/logs", auth, async (req, res) => {
  let j;
  if (dbType === "mysql") {
    const [rows] = await pool.query("SELECT id FROM jobs WHERE id=? AND owner=?", [req.params.jobId, req.user.sub]);
    j = rows[0];
  } else {
    j = sqliteDb.prepare("SELECT id FROM jobs WHERE id=? AND owner=?").get(req.params.jobId, req.user.sub);
  }
  if (!j) return res.status(404).json({ ok: false, error: "not found" });
  res.json({ ok: true, logs: jobLogs.get(req.params.jobId) || [] });
});

// ---------- Download ----------
app.get("/download/original/:fileId", auth, async (req, res) => {
  let f;
  if (dbType === "mysql") {
    const [rows] = await pool.query("SELECT * FROM files WHERE id=? AND owner=?", [req.params.fileId, req.user.sub]);
    f = rows[0];
  } else {
    f = sqliteDb.prepare("SELECT * FROM files WHERE id=? AND owner=?").get(req.params.fileId, req.user.sub);
  }
  if (!f) return res.status(404).json({ ok: false, error: "not found" });
  res.download(path.join(UP_DIR, f.filename));
});

app.get("/download/transcoded/:jobId", auth, async (req, res) => {
  let j;
  if (dbType === "mysql") {
    const [rows] = await pool.query("SELECT * FROM jobs WHERE id=? AND owner=?", [req.params.jobId, req.user.sub]);
    j = rows[0];
  } else {
    j = sqliteDb.prepare("SELECT * FROM jobs WHERE id=? AND owner=?").get(req.params.jobId, req.user.sub);
  }
  if (!j || j.status !== "succeeded" || !j.output_filename) {
    return res.status(404).json({ ok: false, error: "not ready" });
  }
  res.download(path.join(OUT_DIR, j.output_filename));
});

// ---------- Codec helper (same behavior as your version) ----------
function codecsFor(format) {
  if (format === "webm") {
    return { v: "libvpx-vp9", a: "libopus", extra: ["-b:v", "0"] };
  }
  // mp4/mov/mkv/avi
  return { v: "libx264", a: "aac", extra: [] };
}

// ---------- Transcode (progress + logging preserved) ----------
app.post("/transcode/:fileId", auth, async (req, res) => {
  let f;
  if (dbType === "mysql") {
    const [rows] = await pool.query("SELECT * FROM files WHERE id=? AND owner=?", [req.params.fileId, req.user.sub]);
    f = rows[0];
  } else {
    f = sqliteDb.prepare("SELECT * FROM files WHERE id=? AND owner=?").get(req.params.fileId, req.user.sub);
  }
  if (!f) return res.status(404).json({ ok: false, error: "file not found" });

  const allowed = ["mp4", "mkv", "mov", "avi", "webm"];
  const {
    preset  = process.env.DEFAULT_PRESET  || "medium",
    crf     = Number(process.env.DEFAULT_CRF ?? 28),
    threads = Number(process.env.DEFAULT_THREADS ?? 1),
    scale   = process.env.DEFAULT_SCALE   || null,
    format  = (req.body && req.body.format) ? String(req.body.format).toLowerCase() : "mp4",
  } = req.body || {};

  if (!allowed.includes(format)) {
    return res.status(400).json({ ok: false, error: `unsupported format. allowed: ${allowed.join(", ")}` });
  }

  const jobId   = uuidv4();
  const outName = `${jobId}.${format}`;
  const inputPath  = path.join(UP_DIR, f.filename);
  const outputPath = path.join(OUT_DIR, outName);

  // Create job (running)
  const paramsJson = JSON.stringify({ preset, crf, threads, scale, format });
  if (dbType === "mysql") {
    await pool.query(
      "INSERT INTO jobs (id, owner, file_id, status, params) VALUES (?, ?, ?, 'running', ?)",
      [jobId, req.user.sub, f.id, paramsJson]
    );
  } else {
    sqliteDb.prepare(
      `INSERT INTO jobs (id, owner, file_id, status, params, created_at, updated_at)
       VALUES (?, ?, ?, 'running', ?, datetime('now'), datetime('now'))`
    ).run(jobId, req.user.sub, f.id, paramsJson);
  }

  // In-memory logs (same as your original)
  jobLogs.set(jobId, []);
  const pushLog = (line) => {
    const arr = jobLogs.get(jobId) || [];
    arr.push(String(line));
    if (arr.length > 200) arr.splice(0, arr.length - 200);
    jobLogs.set(jobId, arr);
  };

  log("TRANSCODE: start", { jobId, fileId: f.id, preset, crf, threads, scale, format });
  pushLog(`start: ${nowIso()}`);
  pushLog(`input: ${inputPath}`);
  pushLog(`output: ${outputPath}`);

  const co = codecsFor(format);
  const common = [
    "-preset", String(preset),
    "-crf", String(crf),
    "-threads", String(threads),
    "-y"
  ];
  if (format === "mp4" || format === "mov") common.push("-movflags", "faststart");

  const cmd = ffmpeg(inputPath)
    .format(format)
    .videoCodec(co.v)
    .audioCodec(co.a)
    .outputOptions([...common, ...co.extra])
    .on("start", (cmdline) => {
      pushLog(`ffmpeg cmd: ${cmdline}`);
      if (dbType === "mysql") pool.query("UPDATE jobs SET updated_at=NOW() WHERE id=?", [jobId]).catch(() => {});
      else sqliteDb.prepare("UPDATE jobs SET updated_at=datetime('now') WHERE id=?").run(jobId);
    })
    .on("progress", (p) => {
      pushLog(`progress: ${JSON.stringify(p)}`);
      if (dbType === "mysql") pool.query("UPDATE jobs SET updated_at=NOW() WHERE id=?", [jobId]).catch(() => {});
      else sqliteDb.prepare("UPDATE jobs SET updated_at=datetime('now') WHERE id=?").run(jobId);
    })
    .on("stderr", (line) => pushLog(line))
    .on("error", (err) => {
      log("TRANSCODE: ffmpeg error", err.message);
      pushLog(`error: ${err.message}`);
      if (dbType === "mysql") pool.query("UPDATE jobs SET status='failed', updated_at=NOW() WHERE id=?", [jobId]).catch(() => {});
      else sqliteDb.prepare("UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?").run(jobId);
    })
    .on("end", () => {
      try {
        const stat = fs.statSync(outputPath);
        if (!stat || stat.size === 0) {
          pushLog("end: output size is 0 -> failed");
          if (dbType === "mysql") pool.query("UPDATE jobs SET status='failed', updated_at=NOW() WHERE id=?", [jobId]).catch(() => {});
          else sqliteDb.prepare("UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?").run(jobId);
          return;
        }
        pushLog(`end: ok size=${stat.size}`);
        log("TRANSCODE: end", { jobId, outName, size: stat.size });
        if (dbType === "mysql") {
          pool.query("UPDATE jobs SET status='succeeded', output_filename=?, updated_at=NOW() WHERE id=?", [outName, jobId]).catch(() => {});
        } else {
          sqliteDb.prepare(
            "UPDATE jobs SET status='succeeded', output_filename=?, updated_at=datetime('now') WHERE id=?"
          ).run(outName, jobId);
        }
      } catch (e) {
        pushLog(`end-check error: ${e.message}`);
        if (dbType === "mysql") pool.query("UPDATE jobs SET status='failed', updated_at=NOW() WHERE id=?", [jobId]).catch(() => {});
        else sqliteDb.prepare("UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?").run(jobId);
      }
    });

  if (scale) cmd.videoFilters(`scale=${scale}`);
  cmd.save(outputPath);

  res.json({ ok: true, jobId });
});

// ---------- Start server ----------
app.listen(PORT, () => {
  console.log(`API listening on ${PORT}`);
});
