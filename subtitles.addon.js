// subtitles.addon.js
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';
import { v4 as uuidv4 } from 'uuid';

const SUB_DIR = path.resolve('data/subtitles');
if (!fs.existsSync(SUB_DIR)) fs.mkdirSync(SUB_DIR, { recursive: true });

export function ensureSubTables(db){
  db.exec(`
    CREATE TABLE IF NOT EXISTS subtitles (
      id TEXT PRIMARY KEY,
      file_id TEXT NOT NULL,
      lang TEXT,
      filename TEXT,
      storage_path TEXT NOT NULL,
      provider TEXT NOT NULL DEFAULT 'opensubtitles',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_subtitles_file ON subtitles(file_id);
  `);
}

async function opensubtitlesSearchAndDownload({ apiKey, query, lang }) {
  const headers = { 'Api-Key': apiKey, 'Content-Type': 'application/json', 'Accept':'application/json' };

  // 1) 搜索字幕（按标题+语言）
  const searchUrl = `https://api.opensubtitles.com/api/v1/subtitles?query=${encodeURIComponent(query)}&languages=${encodeURIComponent(lang)}`;
  const sr = await fetch(searchUrl, { headers });
  if (!sr.ok) throw new Error(`OpenSubtitles search failed: ${sr.status}`);
  const sj = await sr.json();
  const item = sj?.data?.[0];
  if (!item) throw new Error('No subtitles found');

  // 2) 请求下载链接（需要 file_id）
  const fileId = item.attributes.files?.[0]?.file_id || item.attributes?.file_id || item.id;
  const dlr = await fetch('https://api.opensubtitles.com/api/v1/download', {
    method:'POST', headers, body: JSON.stringify({ file_id: fileId })
  });
  if (!dlr.ok) throw new Error(`OpenSubtitles download ticket failed: ${dlr.status}`);
  const dj = await dlr.json();
  if (!dj?.link) throw new Error('No download link from OpenSubtitles');

  // 3) 真正下载 srt/vtt
  const fr = await fetch(dj.link);
  if (!fr.ok) throw new Error(`Subtitle download failed: ${fr.status}`);
  const buff = await fr.arrayBuffer();
  // 文件名后缀尝试用 .srt
  const filename = (item.attributes?.files?.[0]?.file_name || `subtitle_${fileId}.srt`).replace(/[/\\]/g,'_');
  return { buffer: Buffer.from(buff), filename };
}

export function attachSubtitles(app, db, ensureAuth){
  ensureSubTables(db);

  // 拉取字幕并保存
  app.post('/files/:id/subtitles', ensureAuth, async (req, res) => {
    try {
      const apiKey = process.env.OPENSUBTITLES_API_KEY;
      if (!apiKey) return res.status(500).json({ ok:false, error:'OPENSUBTITLES_API_KEY missing' });

      const fileId = req.params.id;
      const { lang = 'eng' } = req.body || {};
      const row = db.prepare(`SELECT id, filename FROM files WHERE id=?`).get(fileId);
      if (!row) return res.status(404).json({ ok:false, error:'file not found' });

      // 用文件名（去扩展名和分隔）作为 query
      const baseTitle = String(row.filename || '').replace(/\.[a-z0-9]+$/i,'').replace(/[_\-.]+/g,' ').trim() || 'video';

      const { buffer, filename } = await opensubtitlesSearchAndDownload({ apiKey, query: baseTitle, lang });

      // 落地保存 + 事务写库（ACID）
      const sid = uuidv4();
      const saveName = `${sid}-${filename}`;
      const savePath = path.join(SUB_DIR, saveName);
      fs.writeFileSync(savePath, buffer);

      const insert = db.prepare(`INSERT INTO subtitles (id,file_id,lang,filename,storage_path) VALUES (?,?,?,?,?)`);
      const tx = db.transaction((p)=> insert.run(...p));
      tx([sid, fileId, lang, filename, savePath]);

      res.json({ ok:true, items:[{ id:sid, lang, filename }] });
    } catch (e) {
      console.error('subtitle error', e);
      res.status(500).json({ ok:false, error:String(e.message||e) });
    }
  });

  // 列出字幕
  app.get('/files/:id/subtitles', ensureAuth, (req,res)=>{
    const fileId = req.params.id;
    const rows = db.prepare(`SELECT id, lang, filename, created_at FROM subtitles WHERE file_id=? ORDER BY created_at DESC`).all(fileId);
    res.json({ ok:true, items: rows });
  });

  // 下载字幕
  app.get('/subtitles/:sid/download', ensureAuth, (req,res)=>{
    const sid = req.params.sid;
    const row = db.prepare(`SELECT filename, storage_path FROM subtitles WHERE id=?`).get(sid);
    if(!row) return res.status(404).send('Not found');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(row.filename||sid)}"`);
    res.sendFile(path.resolve(row.storage_path));
  });
}

// 在你的 /transcode/:fileId 路由里用到：把字幕烧进视频
export function subtitleBurnArgs(db, subtitleId){
  if(!subtitleId) return [];
  const row = db.prepare(`SELECT storage_path FROM subtitles WHERE id=?`).get(subtitleId);
  if(!row) return [];
  // ffmpeg 字幕滤镜（自动识别 srt/vtt）
  return ['-vf', `subtitles='${row.storage_path.replace(/'/g,"\\'")}'`];
}
