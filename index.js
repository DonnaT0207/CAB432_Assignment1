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
import { fileURLToPath } from "url";
import os from "os"; 

// calculate __dirname / __filename（ESM）
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ===== tiny .env loader =====
const envPath = path.join(process.cwd(), ".env");
if (fs.existsSync(envPath)) {
  const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([\w.-]+)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    const key = m[1];
    let val = m[2];
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (process.env[key] === undefined) process.env[key] = val;
  }
}

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const OPENSUBTITLES_API_KEY = process.env.OPENSUBTITLES_API_KEY || ""; 
ffmpeg.setFfmpegPath(ffmpegInstaller.path);

// ---------- dirs ----------
const DATA_DIR = path.join(process.cwd(), "data");
const UP_DIR = path.join(DATA_DIR, "uploads");
const OUT_DIR = path.join(DATA_DIR, "outputs");
const THUMB_DIR = path.join(OUT_DIR, "thumbs");
for (const d of [DATA_DIR, UP_DIR, OUT_DIR, THUMB_DIR]) if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });

const log = (...a) => console.log(new Date().toISOString(), ...a);

// ---------- DB ----------
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
  status TEXT NOT NULL,               -- queued|running|completed|failed
  params TEXT NOT NULL,               -- json
  progress REAL NOT NULL DEFAULT 0.0,
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
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col);
}
function fkExists(table, refTable) {
  return db.prepare(`PRAGMA foreign_key_list(${table})`).all().some(r => r.table === refTable);
}

// migrations
(function migrate(){
  if (!columnExists("files","ext_meta")) db.exec(`ALTER TABLE files ADD COLUMN ext_meta TEXT;`);
  if (!columnExists("jobs","thumbnail_path")) db.exec(`ALTER TABLE jobs ADD COLUMN thumbnail_path TEXT;`);
  if (!columnExists("jobs","thumbnail_name")) db.exec(`ALTER TABLE jobs ADD COLUMN thumbnail_name TEXT;`);
  if (!columnExists("jobs","progress")) db.exec(`ALTER TABLE jobs ADD COLUMN progress REAL NOT NULL DEFAULT 0.0;`);
  if (!columnExists("jobs","log")) db.exec(`ALTER TABLE jobs ADD COLUMN log TEXT NOT NULL DEFAULT '';`);
  if (!columnExists("jobs","charged_cents")) db.exec(`ALTER TABLE jobs ADD COLUMN charged_cents INTEGER NOT NULL DEFAULT 0;`);
  if (!columnExists("jobs","refunded_cents")) db.exec(`ALTER TABLE jobs ADD COLUMN refunded_cents INTEGER NOT NULL DEFAULT 0;`);
  if (!columnExists("jobs","output_path")) db.exec(`ALTER TABLE jobs ADD COLUMN output_path TEXT;`);
  if (!columnExists("jobs","output_name")) db.exec(`ALTER TABLE jobs ADD COLUMN output_name TEXT;`);
  if (!fkExists("jobs","files")) {
    db.exec("PRAGMA foreign_keys=OFF;");
    db.exec(`
      CREATE TABLE IF NOT EXISTS jobs_new (
        id TEXT PRIMARY KEY,
        owner TEXT NOT NULL,
        file_id TEXT NOT NULL,
        status TEXT NOT NULL,
        params TEXT NOT NULL,
        progress REAL NOT NULL DEFAULT 0.0,
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
      SELECT id, owner, file_id, status, COALESCE(params,'{}'),
             COALESCE(progress,0.0), COALESCE(log,''), COALESCE(charged_cents,0),
             COALESCE(refunded_cents,0), output_path, output_name, thumbnail_path, thumbnail_name, created_at, updated_at
      FROM jobs;
      DROP TABLE jobs;
      ALTER TABLE jobs_new RENAME TO jobs;
      CREATE INDEX IF NOT EXISTS idx_jobs_updated_at ON jobs(updated_at);
    `);
    db.exec("PRAGMA foreign_keys=ON;");
  }
})();

// Initialize the balance
db.prepare(`INSERT INTO accounts(owner,balance_cents,updated_at) VALUES('admin',1000,datetime('now')) ON CONFLICT(owner) DO NOTHING;`).run();
db.prepare(`INSERT INTO accounts(owner,balance_cents,updated_at) VALUES('user',500,datetime('now')) ON CONFLICT(owner) DO NOTHING;`).run();

// ---------- auth ----------
const USERS = {
  admin: { password: "admin123", admin: true },
  user:  { password: "user123", admin: false },
};
const signToken = (sub, isAdmin) => jwt.sign({ sub, admin:isAdmin }, JWT_SECRET, { expiresIn:"2h" });
function auth(req,res,next){
  const m=(req.headers.authorization||"").match(/^Bearer (.+)$/i);
  if(!m) return res.status(401).json({ok:false,error:"missing token"});
  try{ req.user = jwt.verify(m[1], JWT_SECRET); next(); }
  catch{ return res.status(401).json({ok:false,error:"invalid token"}); }
}

// ---------- app ----------
const app = express();
app.use(cors());
app.use(express.json());

// Static and Home Page
app.use("/public", express.static(path.join(__dirname,"public")));
app.get("/", (_req,res)=> res.sendFile(path.join(__dirname, "public/index.html")) );

app.post("/login",(req,res)=>{
  const {username,password} = req.body||{};
  const u = USERS[username];
  if(!u || u.password!==password) return res.sendStatus(401);
  res.json({authToken:signToken(username,u.admin)});
});

app.get("/healthz",(_req,res)=>res.json({ok:true}));

// accounts
app.get("/me",auth,(req,res)=>{
  const a=db.prepare(`SELECT balance_cents,updated_at FROM accounts WHERE owner=?`).get(req.user.sub);
  res.json({ user:req.user.sub, admin:!!req.user.admin, balance_cents:a?.balance_cents??0, updated_at:a?.updated_at??null });
});
app.post("/accounts/topup",auth,(req,res)=>{
  const amount=Number(req.body?.amount_cents??0);
  if(!Number.isInteger(amount)||amount<=0) return res.status(400).json({ok:false,error:"invalid amount"});
  db.prepare(`
    INSERT INTO accounts(owner,balance_cents,updated_at)
    VALUES(?,?,datetime('now'))
    ON CONFLICT(owner) DO UPDATE SET balance_cents=balance_cents+excluded.balance_cents, updated_at=datetime('now')
  `).run(req.user.sub,amount);
  res.json({ok:true,added:amount});
});

// ---------- helpers ----------
const upload = multer({ dest: os.tmpdir() });
function listParams(req,opt){
  const page=Math.max(1,parseInt(req.query.page||"1",10));
  const size=Math.min(100,Math.max(1,parseInt(req.query.size||"10",10)));
  const q=(req.query.q||"").trim();
  const sort=opt.sortWhitelist.includes(req.query.sort)?req.query.sort:opt.defaultSort;
  const order=(req.query.order||"desc").toLowerCase()==="asc"?"asc":"desc";
  const offset=(page-1)*size;
  return {page,size,offset,q,sort,order};
}

// ---------- files ----------
app.post("/upload",auth,upload.single("file"),(req,res)=>{
  if(!req.file) return res.status(400).json({ok:false,error:"no file"});

  const id = uuidv4();
  const original = req.file.originalname || "upload.bin";
  const safeName = `${id}-${original.replace(/[^\w.\-]+/g,"_")}`;
  const finalPath = path.join(UP_DIR, safeName);

  try{ fs.renameSync(req.file.path, finalPath); }
  catch(e){ try{fs.unlinkSync(req.file.path);}catch{}; return res.status(500).json({ok:false,error:"rename failed: "+e.message}); }

  try{
    db.transaction(()=>{ 
      db.prepare(`
        INSERT INTO files (id,owner,filename,stored_path,size_bytes,mime,uploaded_at)
        VALUES (?,?,?,?,?,?,datetime('now'))
      `).run(id, req.user.sub, original, finalPath, req.file.size, req.file.mimetype||null);
    })();
    res.json({ok:true,fileId:id,filename:original});
  }catch(e){
    try{fs.unlinkSync(finalPath);}catch{}
    res.status(500).json({ok:false,error:"db insert failed: "+e.message});
  }
});

app.get("/files",auth,(req,res)=>{
  const {page,size,offset,q,sort,order}=listParams(req,{
    sortWhitelist:["uploaded_at","size_bytes","filename"],
    defaultSort:"uploaded_at"
  });
  const where=["owner=?"]; const params=[req.user.sub];
  if(q){ where.push("filename LIKE ?"); params.push(`%${q}%`); }
  const whereSql=`WHERE ${where.join(" AND ")}`;
  const total=db.prepare(`SELECT COUNT(*) c FROM files ${whereSql}`).get(...params).c;
  const rows=db.prepare(
    `SELECT id,filename,size_bytes,mime,uploaded_at FROM files ${whereSql} ORDER BY ${sort} ${order} LIMIT ? OFFSET ?`
  ).all(...params,size,offset);
  res.set("X-Total-Count",String(total));
  res.set("X-Page",String(page));
  res.set("X-Page-Size",String(size));
  res.json({ items:rows, total, page, size, sort, order, q });
});

app.get("/files/:id/meta",auth,(req,res)=>{
  const row=db.prepare(`SELECT ext_meta FROM files WHERE id=? AND owner=?`).get(req.params.id,req.user.sub);
  if(!row) return res.sendStatus(404);
  try{ res.json({ ok:true, meta: row.ext_meta ? JSON.parse(row.ext_meta) : null }); }
  catch{ res.json({ ok:true, meta: null }); }
});

// OpenSubtitles：Search for subtitles and write ext_meta.opensubtitles
app.post("/files/:id/subs", auth, async (req,res)=>{
  if (!OPENSUBTITLES_API_KEY) return res.status(400).json({ok:false,error:"OPENSUBTITLES_API_KEY missing"});
  const f=db.prepare(`SELECT id FROM files WHERE id=? AND owner=?`).get(req.params.id,req.user.sub);
  if(!f) return res.sendStatus(404);

  const query = String(req.body?.query || "").trim();
  const languages = Array.isArray(req.body?.languages) ? req.body.languages : ["en"];
  if (!query) return res.status(400).json({ok:false,error:"query required"});

  try {
    const url = `https://api.opensubtitles.com/api/v1/subtitles?query=${encodeURIComponent(query)}&languages=${encodeURIComponent(languages.join(","))}&order_by=downloads&order_direction=desc&ai_translated=exclude`;
    const r = await fetch(url, { headers: { "Api-Key": OPENSUBTITLES_API_KEY, "Accept": "application/json" }});
    if (!r.ok) return res.status(502).json({ ok:false, error:`OpenSubtitles HTTP ${r.status}` });
    const j = await r.json();
    const top = Array.isArray(j?.data) ? j.data.slice(0,5) : [];
    const payload = { opensubtitles: { query, languages, total: j?.total_count ?? top.length, top } };
    db.prepare(`UPDATE files SET ext_meta=json_patch(COALESCE(ext_meta,'{}'), json(?)) WHERE id=?`)
      .run(JSON.stringify(payload), req.params.id);
    res.json({ ok:true, count: top.length });
  } catch (e) {
    res.status(500).json({ ok:false, error: e.message });
  }
});

app.delete("/files/:id",auth,(req,res)=>{
  const row=db.prepare(`SELECT stored_path FROM files WHERE id=? AND owner=?`).get(req.params.id,req.user.sub);
  if(!row) return res.sendStatus(404);
  const r=db.prepare(`DELETE FROM files WHERE id=? AND owner=?`).run(req.params.id,req.user.sub);
  if(r.changes!==1) return res.status(500).json({ok:false,error:"delete failed"});
  try{fs.unlinkSync(row.stored_path);}catch(e){log("unlink warn:",e.message);}
  res.json({ok:true});
});

app.get("/download/original/:fileId",auth,(req,res)=>{
  const row=db.prepare(`SELECT stored_path,filename FROM files WHERE id=? AND owner=?`).get(req.params.fileId,req.user.sub);
  if(!row || !fs.existsSync(row.stored_path)) return res.sendStatus(404);
  res.setHeader("Content-Disposition", `attachment; filename="${path.basename(row.filename)}"`);
  res.sendFile(row.stored_path);
});

// ---------- jobs (ACID) ----------
const TRANSCODE_COST_CENTS = 50;

const createJobWithCharge = db.transaction((owner,fileId,cents,params)=>{
  const u=db.prepare(
    `UPDATE accounts SET balance_cents=balance_cents-?, updated_at=datetime('now')
     WHERE owner=? AND balance_cents>=?`
  ).run(cents,owner,cents);
  if(u.changes!==1) throw new Error("INSUFFICIENT_FUNDS");

  const jobId=uuidv4();
  db.prepare(`
    INSERT INTO jobs (id,owner,file_id,status,params,charged_cents,created_at,updated_at)
    VALUES (?,?,?,'queued',?,?,datetime('now'),datetime('now'))
  `).run(jobId,owner,fileId,JSON.stringify(params),cents);

  return jobId;
});

app.get("/jobs",auth,(req,res)=>{
  const {page,size,offset,q,sort,order}=listParams(req,{
    sortWhitelist:["created_at","updated_at","status"],
    defaultSort:"updated_at"
  });
  const status = (req.query.status||"").toLowerCase();
  const where = ["owner=?"]; const params=[req.user.sub];
  if(status && ["queued","running","completed","failed"].includes(status)){
    where.push("LOWER(status)=?"); params.push(status);
  }
  if(q){ where.push("id LIKE ?"); params.push(`%${q}%`); }

  const whereSql = `WHERE ${where.join(" AND ")}`;
  const total = db.prepare(`SELECT COUNT(*) c FROM jobs ${whereSql}`).get(...params).c;
  const rows = db.prepare(
    `SELECT id,file_id,status,progress,charged_cents,refunded_cents,created_at,updated_at,
            CASE WHEN thumbnail_path IS NOT NULL THEN 1 ELSE 0 END AS has_thumbnail
     FROM jobs ${whereSql} ORDER BY ${sort} ${order} LIMIT ? OFFSET ?`
  ).all(...params,size,offset);

  res.set("X-Total-Count",String(total));
  res.set("X-Page",String(page));
  res.set("X-Page-Size",String(size));
  res.json({ items:rows, total, page, size, sort, order, status, q });
});

app.get("/jobs/:id",auth,(req,res)=>{
  const job=db.prepare(
    `SELECT id,owner,file_id,status,params,progress,charged_cents,refunded_cents,log,output_name,thumbnail_name,created_at,updated_at
     FROM jobs WHERE id=? AND owner=?`
  ).get(req.params.id,req.user.sub);
  if(!job) return res.sendStatus(404);
  res.json(job);
});

app.get("/jobs/:id/logs",auth,(req,res)=>{
  const row=db.prepare(`SELECT log FROM jobs WHERE id=? AND owner=?`).get(req.params.id,req.user.sub);
  if(!row) return res.sendStatus(404);
  res.setHeader("Content-Type","text/plain; charset=utf-8");
  res.send(row.log||"");
});

app.get("/jobs/:id/thumbnail",auth,(req,res)=>{
  const row=db.prepare(`SELECT owner,thumbnail_path,thumbnail_name FROM jobs WHERE id=?`).get(req.params.id);
  if(!row || row.owner!==req.user.sub || !row.thumbnail_path || !fs.existsSync(row.thumbnail_path)) return res.sendStatus(404);
  res.setHeader("Content-Disposition", `inline; filename="${path.basename(row.thumbnail_name||'thumb.jpg')}"`);
  res.sendFile(row.thumbnail_path);
});

app.get("/download/transcoded/:jobId",auth,(req,res)=>{
  const j=db.prepare(`SELECT owner,status,output_path,output_name FROM jobs WHERE id=?`).get(req.params.jobId);
  if(!j || j.owner!==req.user.sub) return res.sendStatus(404);
  if(j.status!=="completed" || !j.output_path || !fs.existsSync(j.output_path))
    return res.status(409).json({ok:false,error:"not ready"});
  res.setHeader("Content-Disposition", `attachment; filename="${path.basename(j.output_name||j.output_path)}"`);
  res.sendFile(j.output_path);
});

app.post("/transcode/:fileId",auth, async (req,res)=>{
  const f=db.prepare(`SELECT id,stored_path,filename FROM files WHERE id=? AND owner=?`).get(req.params.fileId,req.user.sub);
  if(!f) return res.sendStatus(404);

  const format=(req.body?.format||"mp4").toLowerCase(); // mp4|webm
  const crf=String(req.body?.crf??"23");
  const preset=String(req.body?.preset??"medium");
  const scale=String(req.body?.scale??"1280:720");
  const costCents=TRANSCODE_COST_CENTS;

  let jobId;
  try{ jobId = createJobWithCharge(req.user.sub,f.id,costCents,{format,crf,preset,scale}); }
  catch(e){
    if(e.message==="INSUFFICIENT_FUNDS") return res.status(402).json({ok:false,error:"insufficient funds"});
    return res.status(500).json({ok:false,error:e.message});
  }
  res.json({ok:true,jobId});

  db.prepare(`UPDATE jobs SET status='running', updated_at=datetime('now') WHERE id=?`).run(jobId);

  const outId=uuidv4();
  const outName=`${outId}-${path.basename(f.filename, path.extname(f.filename))}.${format}`;
  const outPath=path.join(OUT_DIR,outName);

  let logBuf="";
  const appendLog=(s)=>{
    logBuf+=s+"\n";
    db.prepare(`UPDATE jobs SET log=?, updated_at=datetime('now') WHERE id=?`).run(logBuf,jobId);
  };

  try{
    await new Promise((resolve,reject)=>{
      ffmpeg(f.stored_path)
        .addOptions([
          "-y",
          "-vf", `scale=${scale}`,
          "-preset", preset,
          ...(format==="mp4" ? ["-vcodec","libx264","-crf",crf,"-movflags","faststart"] : []),
          ...(format==="webm"? ["-vcodec","libvpx-vp9","-crf",crf,"-b:v","0"] : []),
        ])
        .on("start", cmd => appendLog("FFMPEG START: "+cmd))
        .on("stderr", line => {
          appendLog(line);
          const cur = db.prepare(`SELECT progress FROM jobs WHERE id=?`).get(jobId)?.progress ?? 0;
          const p = Math.min(95, cur+1);
          db.prepare(`UPDATE jobs SET progress=?, updated_at=datetime('now') WHERE id=?`).run(p,jobId);
        })
        .on("error", err => reject(err))
        .on("end", () => resolve())
        .save(outPath);
    });

    // Generate thumbnails
    const thumbName = `${uuidv4()}-${path.basename(f.filename, path.extname(f.filename))}.jpg`;
    const thumbPath = path.join(THUMB_DIR, thumbName);
    await new Promise((resolve,reject)=>{
      ffmpeg(f.stored_path)
        .addOptions(["-y", "-ss", "5", "-frames:v", "1"])
        .on("start", cmd => appendLog("THUMB START: "+cmd))
        .on("error", err => reject(err))
        .on("end", () => resolve())
        .save(thumbPath);
    });

    db.prepare(`
      UPDATE jobs
      SET status='completed', progress=100,
          output_path=?, output_name=?, 
          thumbnail_path=?, thumbnail_name=?,
          updated_at=datetime('now')
      WHERE id=?
    `).run(outPath, outName, thumbPath, thumbName, jobId);

  }catch(e){
    appendLog("ERROR: "+e.message);
    db.prepare(`UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?`).run(jobId);

    // Automatic refund in case of failure 
    const refund = db.transaction((owner, amount)=>{
      const row=db.prepare(`SELECT refunded_cents FROM jobs WHERE id=? AND owner=?`).get(jobId,owner);
      if(!row || row.refunded_cents>0) return;
      db.prepare(`UPDATE accounts SET balance_cents=balance_cents+?, updated_at=datetime('now') WHERE owner=?`).run(amount,owner);
      db.prepare(`UPDATE jobs SET refunded_cents=refunded_cents+?, updated_at=datetime('now') WHERE id=?`).run(amount,jobId);
    });
    refund(req.user.sub,costCents);
  }
});

// optional: list outputs
app.get("/outputs",auth,(_req,res)=>{
  const items=fs.readdirSync(OUT_DIR).filter(f=>!f.startsWith("."));
  res.json({items});
});

app.listen(PORT, ()=>log(`Server listening on http://0.0.0.0:${PORT}`));
