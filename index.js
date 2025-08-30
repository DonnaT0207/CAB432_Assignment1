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
import os from "os";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
ffmpeg.setFfmpegPath(ffmpegInstaller.path);

const DATA_DIR = path.join(process.cwd(), "data");
const UP_DIR = path.join(DATA_DIR, "uploads");
const OUT_DIR = path.join(DATA_DIR, "outputs");
for (const d of [DATA_DIR, UP_DIR, OUT_DIR]) if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });

const log = (...a) => console.log(new Date().toISOString(), ...a);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- DB ----------
const DB_FILE = path.join(DATA_DIR, "app.db");
const db = new Database(DB_FILE);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS files (
  id TEXT PRIMARY KEY,
  owner TEXT NOT NULL,
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  mime TEXT,
  uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
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
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS accounts (
  owner TEXT PRIMARY KEY,
  balance_cents INTEGER NOT NULL CHECK (balance_cents >= 0),
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jobs_updated_at ON jobs(updated_at);
`);

function columnExists(table, col) {
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col);
}
function fkExists(table, refTable) {
  return db.prepare(`PRAGMA foreign_key_list(${table})`).all().some(r => r.table === refTable);
}

// safe migrations
(function migrate(){
  if (!columnExists("files","stored_path")) db.exec(`ALTER TABLE files ADD COLUMN stored_path TEXT;`);
  if (!columnExists("files","size_bytes")) db.exec(`ALTER TABLE files ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0;`);
  if (!columnExists("files","mime"))       db.exec(`ALTER TABLE files ADD COLUMN mime TEXT;`);
  if (!columnExists("jobs","progress"))    db.exec(`ALTER TABLE jobs ADD COLUMN progress REAL NOT NULL DEFAULT 0.0;`);
  if (!columnExists("jobs","log"))         db.exec(`ALTER TABLE jobs ADD COLUMN log TEXT NOT NULL DEFAULT '';`);
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
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
      );
      INSERT INTO jobs_new
      SELECT id, owner, file_id, status, COALESCE(params,'{}'),
             COALESCE(progress,0.0), COALESCE(log,''), COALESCE(charged_cents,0),
             COALESCE(refunded_cents,0), output_path, output_name, created_at, updated_at
      FROM jobs;
      DROP TABLE jobs;
      ALTER TABLE jobs_new RENAME TO jobs;
      CREATE INDEX IF NOT EXISTS idx_jobs_updated_at ON jobs(updated_at);
    `);
    db.exec("PRAGMA foreign_keys=ON;");
  }
})();

// legacy compat: if old 'files.size' exists, fill it on insert
const FILES_HAS_LEGACY_SIZE = columnExists("files","size");

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
app.use("/", express.static(path.join(__dirname,"public")));

app.post("/login",(req,res)=>{
  const {username,password} = req.body||{};
  const u = USERS[username];
  if(!u || u.password!==password) return res.sendStatus(401);
  res.json({authToken:signToken(username,u.admin)});
});

app.get("/healthz",(_req,res)=>res.json({ok:true}));

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

// ---------- files ----------
const upload = multer({ dest: os.tmpdir() });

app.post("/upload",auth,upload.single("file"),(req,res)=>{
  if(!req.file) return res.status(400).json({ok:false,error:"no file"});

  const id = uuidv4();
  const original = req.file.originalname || "upload.bin";
  const safeName = `${id}-${original.replace(/[^\w.\-]+/g,"_")}`;
  const finalPath = path.join(UP_DIR, safeName);

  try{ fs.renameSync(req.file.path, finalPath); }
  catch(e){ try{fs.unlinkSync(req.file.path);}catch{}; return res.status(500).json({ok:false,error:"rename failed: "+e.message}); }

  try{
    const sql = `
      INSERT INTO files (id,owner,filename,stored_path,size_bytes,mime,uploaded_at ${FILES_HAS_LEGACY_SIZE?", size":""})
      VALUES (?,?,?,?,?,?,datetime('now') ${FILES_HAS_LEGACY_SIZE?", ?":""})
    `;
    const args = [id, req.user.sub, original, finalPath, req.file.size, req.file.mimetype||null];
    if(FILES_HAS_LEGACY_SIZE) args.push(req.file.size);

    db.transaction(()=>{ db.prepare(sql).run(...args); })();
    res.json({ok:true,fileId:id,filename:original});
  }catch(e){
    try{fs.unlinkSync(finalPath);}catch{}
    res.status(500).json({ok:false,error:"db insert failed: "+e.message});
  }
});

function listParams(req,opt){
  const page=Math.max(1,parseInt(req.query.page||"1",10));
  const size=Math.min(100,Math.max(1,parseInt(req.query.size||"10",10)));
  const q=(req.query.q||"").trim();
  const sort=opt.sortWhitelist.includes(req.query.sort)?req.query.sort:opt.defaultSort;
  const order=(req.query.order||"desc").toLowerCase()==="asc"?"asc":"desc";
  const offset=(page-1)*size;
  return {page,size,offset,q,sort,order};
}

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
  res.json({items:rows,total,page,size});
});

app.delete("/files/:id",auth,(req,res)=>{
  const row=db.prepare(`SELECT stored_path FROM files WHERE id=? AND owner=?`).get(req.params.id,req.user.sub);
  if(!row) return res.sendStatus(404);
  const r=db.prepare(`DELETE FROM files WHERE id=? AND owner=?`).run(req.params.id,req.user.sub);
  if(r.changes!==1) return res.status(500).json({ok:false,error:"delete failed"});
  try{fs.unlinkSync(row.stored_path);}catch(e){log("unlink warn:",e.message);}
  res.json({ok:true});
});

// download original by fileId (auth)
app.get("/download/original/:fileId",auth,(req,res)=>{
  const row=db.prepare(`SELECT stored_path,filename FROM files WHERE id=? AND owner=?`).get(req.params.fileId,req.user.sub);
  if(!row || !fs.existsSync(row.stored_path)) return res.sendStatus(404);
  res.setHeader("Content-Disposition", `attachment; filename="${path.basename(row.filename)}"`);
  res.sendFile(row.stored_path);
});

// ---------- jobs (ACID) ----------
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
  const where=["owner=?"]; const params=[req.user.sub];
  if(q){
    const s=q.toLowerCase();
    if(["queued","running","completed","failed"].includes(s)){ where.push("LOWER(status)=?"); params.push(s); }
    else { where.push("id LIKE ?"); params.push(`%${q}%`); }
  }
  const whereSql=`WHERE ${where.join(" AND ")}`;
  const total=db.prepare(`SELECT COUNT(*) c FROM jobs ${whereSql}`).get(...params).c;
  const rows=db.prepare(
    `SELECT id,file_id,status,progress,charged_cents,refunded_cents,created_at,updated_at
     FROM jobs ${whereSql} ORDER BY ${sort} ${order} LIMIT ? OFFSET ?`
  ).all(...params,size,offset);
  res.set("X-Total-Count",String(total));
  res.set("X-Page",String(page));
  res.set("X-Page-Size",String(size));
  res.json({items:rows,total,page,size});
});

app.get("/jobs/:id",auth,(req,res)=>{
  const job=db.prepare(
    `SELECT id,owner,file_id,status,params,progress,charged_cents,refunded_cents,log,output_name,created_at,updated_at
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

// only downloadable when completed
app.get("/download/transcoded/:jobId",auth,(req,res)=>{
  const j=db.prepare(`SELECT owner,status,output_path,output_name FROM jobs WHERE id=?`).get(req.params.jobId);
  if(!j || j.owner!==req.user.sub) return res.sendStatus(404);
  if(j.status!=="completed" || !j.output_path || !fs.existsSync(j.output_path))
    return res.status(409).json({ok:false,error:"not ready"});
  res.setHeader("Content-Disposition", `attachment; filename="${path.basename(j.output_name||j.output_path)}"`);
  res.sendFile(j.output_path);
});

// start transcode (cost 50c), worker updates status in-place
app.post("/transcode/:fileId",auth,async (req,res)=>{
  const f=db.prepare(`SELECT id,stored_path,filename FROM files WHERE id=? AND owner=?`).get(req.params.fileId,req.user.sub);
  if(!f) return res.sendStatus(404);

  const format=(req.body?.format||"mp4").toLowerCase(); // mp4|webm
  const crf=String(req.body?.crf??"23");
  const preset=String(req.body?.preset??"medium");
  const scale=String(req.body?.scale??"1280:720");
  const costCents=50;

  let jobId;
  try{
    jobId = createJobWithCharge(req.user.sub,f.id,costCents,{format,crf,preset,scale});
  }catch(e){
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
      .on("error", err => appendLog("ERROR: "+err.message))
      .on("end", () => {
        appendLog("FFMPEG END");
        db.prepare(`
          UPDATE jobs
          SET status='completed', progress=100, output_path=?, output_name=?, updated_at=datetime('now')
          WHERE id=?
        `).run(outPath, outName, jobId);
      })
      .save(outPath);
  }catch(e){
    db.prepare(`UPDATE jobs SET status='failed', updated_at=datetime('now') WHERE id=?`).run(jobId);
    appendLog("WORKER FAILED: "+e.message);
    const refund = db.transaction((owner, amount)=>{
      const row=db.prepare(`SELECT refunded_cents FROM jobs WHERE id=? AND owner=?`).get(jobId,owner);
      if(!row || row.refunded_cents>0) return;
      db.prepare(`UPDATE accounts SET balance_cents=balance_cents+?, updated_at=datetime('now') WHERE owner=?`).run(amount,owner);
      db.prepare(`UPDATE jobs SET refunded_cents=refunded_cents+?, updated_at=datetime('now') WHERE id=?`).run(amount,jobId);
    });
    refund(req.user.sub,costCents);
  }
});

// optional: list outputs (not used by UI for gating)
app.get("/outputs",auth,(_req,res)=>{
  const items=fs.readdirSync(OUT_DIR).filter(f=>!f.startsWith("."));
  res.json({items});
});

app.listen(PORT, ()=>log(`Server listening on ${PORT}`));
