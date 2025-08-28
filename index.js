// index.js — Video API (users: admin/admin123, user/user123)
import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import multer from "multer";
import Database from "better-sqlite3";
import { v4 as uuidv4 } from "uuid";
import ffmpeg from "fluent-ffmpeg";
import ffmpegInstaller from "@ffmpeg-installer/ffmpeg";
import fs from "fs";
import path from "path";

const log = (...args) => console.log(new Date().toISOString(), ...args);

// --- app ---
const app = express();
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

app.use(cors());
app.use(express.json());
app.use("/app", express.static("public")); // web client

// --- ffmpeg ---
ffmpeg.setFfmpegPath(ffmpegInstaller.path);

// --- data dirs ---
const DATA_DIR = path.join(process.cwd(), "data");
const UP_DIR = path.join(DATA_DIR, "uploads");
const OUT_DIR = path.join(DATA_DIR, "outputs");
for (const d of [DATA_DIR, UP_DIR, OUT_DIR]) if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });

// --- db + schema guard ---
const db = new Database(path.join(DATA_DIR, "app.db"));
function ensureSchema() {
  const wantFiles = ["id", "owner", "filename", "size", "uploaded_at"];
  const wantJobs  = ["id", "owner", "file_id", "status", "params", "created_at", "updated_at", "output_filename"];
  const cols = (t) => db.prepare(`PRAGMA table_info(${t});`).all().map(r => r.name);
  const hasSame = (got, want) => got.length && want.every(c => got.includes(c)) && got.length === want.length;

  let filesCols = []; let jobsCols = [];
  try { filesCols = cols("files"); } catch {}
  try { jobsCols  = cols("jobs"); }  catch {}

  if (!hasSame(filesCols, wantFiles) || !hasSame(jobsCols, wantJobs)) {
    log("SCHEMA: mismatch -> recreate tables", { filesCols, jobsCols });
    db.exec(`
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
  } else {
    db.exec(`PRAGMA journal_mode = WAL;`);
  }
}
ensureSchema();

// --- users (hardcoded) ---
const USERS = {
  admin: { password: "admin123", role: "admin" },
  user:  { password: "alice123",  role: "alice"  }, 
};

// --- auth middleware ---
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer (.+)$/);
  if (!m) return res.status(401).json({ ok: false, error: "missing bearer token" });
  try { req.user = jwt.verify(m[1], JWT_SECRET); next(); }
  catch { return res.status(401).json({ ok: false, error: "invalid token" }); }
}

// --- routes ---
app.get("/", (req, res) => {
  res.json({
    ok: true,
    msg: "Video API is up",
    env: {
      DEFAULT_PRESET: process.env.DEFAULT_PRESET || "medium",
      DEFAULT_CRF: Number(process.env.DEFAULT_CRF ?? 28),
      DEFAULT_THREADS: Number(process.env.DEFAULT_THREADS ?? 1),
      DEFAULT_SCALE: process.env.DEFAULT_SCALE ?? null
    }
  });
});

app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  const u = USERS[username];
  if (!u || u.password !== password) return res.status(401).json({ ok: false, error: "bad credentials" });
  const token = jwt.sign({ sub: username, role: u.role }, JWT_SECRET, { expiresIn: "2h" });
  res.json({ ok: true, token, user: { username, role: u.role } });
});

// upload
const upload = multer({ dest: UP_DIR });
app.post("/upload", auth, upload.single("video"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: "no file" });
    const fileId = uuidv4();
    const ext = path.extname(req.file.originalname || ".mp4") || ".mp4";
    const finalName = `${fileId}${ext}`;
    fs.renameSync(req.file.path, path.join(UP_DIR, finalName));
    db.prepare("INSERT INTO files (id, owner, filename, size, uploaded_at) VALUES (?, ?, ?, ?, datetime('now'))")
      .run(fileId, req.user.sub, finalName, req.file.size);
    const total = db.prepare("SELECT COUNT(*) AS c FROM files WHERE owner=?").get(req.user.sub).c;
    log("UPLOAD: ok", { owner: req.user.sub, fileId, size: req.file.size });
    res.json({ ok: true, fileId, filename: finalName, totalFiles: total });
  } catch (e) {
    log("UPLOAD: error", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// list files
app.get("/files", auth, (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const size = Math.min(50, Math.max(1, parseInt(req.query.size || "10", 10)));
    const offset = (page - 1) * size;
    const items = db.prepare(
      "SELECT id, filename, size, uploaded_at FROM files WHERE owner=? ORDER BY uploaded_at DESC LIMIT ? OFFSET ?"
    ).all(req.user.sub, size, offset);
    const total = db.prepare("SELECT COUNT(*) AS c FROM files WHERE owner=?").get(req.user.sub).c;
    log("FILES:", { owner: req.user.sub, page, size, count: items.length, total });
    res.json({ ok: true, page, size, total, items });
  } catch (e) {
    log("FILES: error", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// list jobs
app.get("/jobs", auth, (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || "1", 10));
    const size = Math.min(50, Math.max(1, parseInt(req.query.size || "10", 10)));
    const offset = (page - 1) * size;
    const items = db.prepare(
      `SELECT id, file_id, status, created_at, updated_at, output_filename
       FROM jobs WHERE owner=? ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).all(req.user.sub, size, offset);
    const total = db.prepare("SELECT COUNT(*) AS c FROM jobs WHERE owner=?").get(req.user.sub).c;
    log("JOBS(list):", { owner: req.user.sub, page, size, count: items.length, total });
    res.json({ ok: true, page, size, total, items });
  } catch (e) {
    log("JOBS(list): error", e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

// single job
app.get("/jobs/:jobId", auth, (req, res) => {
  const j = db.prepare("SELECT * FROM jobs WHERE id=? AND owner=?").get(req.params.jobId, req.user.sub);
  if (!j) return res.status(404).json({ ok: false, error: "not found" });
  res.json({ ok: true, job: { ...j, params: JSON.parse(j.params) } });
});

// job logs (in-memory)
const jobLogs = new Map(); // jobId => lines[]
app.get("/jobs/:jobId/logs", auth, (req, res) => {
  const j = db.prepare("SELECT id FROM jobs WHERE id=? AND owner=?").get(req.params.jobId, req.user.sub);
  if (!j) return res.status(404).json({ ok: false, error: "not found" });
  res.json({ ok: true, logs: jobLogs.get(req.params.jobId) || [] });
});

// download
app.get("/download/original/:fileId", auth, (req, res) => {
  const f = db.prepare("SELECT * FROM files WHERE id=? AND owner=?").get(req.params.fileId, req.user.sub);
  if (!f) return res.status(404).json({ ok: false, error: "not found" });
  res.download(path.join(UP_DIR, f.filename));
});
app.get("/download/transcoded/:jobId", auth, (req, res) => {
  const j = db.prepare("SELECT * FROM jobs WHERE id=? AND owner=?").get(req.params.jobId, req.user.sub);
  if (!j || j.status !== "succeeded" || !j.output_filename) return res.status(404).json({ ok: false, error: "not ready" });
  res.download(path.join(OUT_DIR, j.output_filename));
});

// transcode (robust, with logs/progress)
app.post("/transcode/:fileId", auth, (req, res) => {
  const f = db.prepare("SELECT * FROM files WHERE id=? AND owner=?").get(req.params.fileId, req.user.sub);
  if (!f) return res.status(404).json({ ok: false, error: "file not found" });

  const {
    preset  = process.env.DEFAULT_PRESET  || "medium",
    crf     = Number(process.env.DEFAULT_CRF ?? 28),
    threads = Number(process.env.DEFAULT_THREADS ?? 1),
    scale   = process.env.DEFAULT_SCALE   || null
  } = req.body || {};

  const jobId   = uuidv4();
  const outName = `${jobId}.mp4`;
  const inputPath  = path.join(UP_DIR, f.filename);
  const outputPath = path.join(OUT_DIR, outName);

  db.prepare(
    `INSERT INTO jobs (id, owner, file_id, status, params, created_at, updated_at)
     VALUES (?, ?, ?, 'running', ?, datetime('now'), datetime('now'))`
  ).run(jobId, req.user.sub, f.id, JSON.stringify({ preset, crf, threads, scale }));

  jobLogs.set(jobId, []);
  const pushLog = (line) => {
    const arr = jobLogs.get(jobId) || [];
    arr.push(String(line));
    if (arr.length > 200) arr.splice(0, arr.length - 200);
    jobLogs.set(jobId, arr);
  };

  log("TRANSCODE: start", { jobId, fileId: f.id, preset, crf, threads, scale });
  pushLog(`start: ${new Date().toISOString()}`);
  pushLog(`input: ${inputPath}`);
  pushLog(`output: ${outputPath}`);

  const cmd = ffmpeg(inputPath)
    .format("mp4")
    .videoCodec("libx264")
    .audioCodec("aac")
    .outputOptions([
      "-preset", String(preset),
      "-crf",    String(crf),
      "-threads",String(threads),
      "-movflags","faststart",
      "-y"
    ])
    .on("start", (cmdline) => {
      pushLog(`ffmpeg cmd: ${cmdline}`);
      db.prepare("UPDATE jobs SET updated_at=datetime('now') WHERE id=?").run(jobId);
    })
    .on("progress", (p) => {
      pushLog(`progress: ${JSON.stringify(p)}`);
      db.prepare("UPDATE jobs SET updated_at=datetime('now') WHERE id=?").run(jobId);
    })
    .on("stderr", (line) => pushLog(line))
    .on("error", (err) => {
      log("TRANSCODE: ffmpeg error", err.message);
      pushLog(`error: ${err.message}`);
      db.prepare("UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?").run(jobId);
    })
    .on("end", () => {
      try {
        const stat = fs.statSync(outputPath);
        if (!stat || stat.size === 0) {
          pushLog("end: output size is 0 -> failed");
          db.prepare("UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?").run(jobId);
          return;
        }
        pushLog(`end: ok size=${stat.size}`);
        log("TRANSCODE: end", { jobId, outName, size: stat.size });
        db.prepare("UPDATE jobs SET status='succeeded', output_filename=?, updated_at=datetime('now') WHERE id=?")
          .run(outName, jobId);
      } catch (e) {
        pushLog(`end-check error: ${e.message}`);
        db.prepare("UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?").run(jobId);
      }
    });

  if (scale) cmd.videoFilters(`scale=${scale}`);
  cmd.save(outputPath);

  res.json({ ok: true, jobId });
});

// --- start ---
app.listen(PORT, "0.0.0.0", () => {
  console.log(`API listening on http://0.0.0.0:${PORT}`);
});
