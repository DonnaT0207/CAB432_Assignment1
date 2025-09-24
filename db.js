// db.js
import pg from "pg";
import fs from "fs";
import path from "path";
import 'dotenv/config';

// 先加载 .env，确保 Pool 能拿到 PG* 变量
// const envPath = path.join(process.cwd(), ".env");
// if (fs.existsSync(envPath)) {
//   for (const raw of fs.readFileSync(envPath, "utf8").split(/\r?\n/)) {
//     const s = raw.trim();
//     if (!s || s.startsWith("#")) continue;
//     const m = /^([\w.-]+)\s*=\s*(.*)$/.exec(s);
//     if (!m) continue;
//     const k = m[1];
//     let v = m[2];
//     if (
//       (v.startsWith('"') && v.endsWith('"')) ||
//       (v.startsWith("'") && v.endsWith("'"))
//     )
//       v = v.slice(1, -1);
//     if (process.env[k] === undefined) process.env[k] = v;
//   }
// }

let pool;
// export const pool = new pg.Pool({
export function initializePool(secretConfig) {
  // const pool = new pg.Pool({
  pool = new pg.Pool({
    host: process.env.PGHOST,
    port: Number(process.env.PGPORT || 5432),
    user: secretConfig.user,
    password: secretConfig.password,
    database: process.env.PGDATABASE,
    max: 3, // ★★★ 限制连接数，避免超过你账号上限
    idleTimeoutMillis: 30000, // 空闲连接 5s 回收
    connectionTimeoutMillis: 5000,
    ssl: { rejectUnauthorized: false },
  });

  pool.on("connect", async (c) => {
    const schema = process.env.PGSCHEMA || "public";
    try {
      await c.query(`SET search_path TO ${schema}, public;`);
      await c.query(`SET statement_timeout = 15000;`); // 防止长时间占用连接
    } catch {}
  });
  
  pool.on('connect', client => {
  client.query('SET search_path TO s400, public;').catch(() => {});
});


  return pool;
}

export async function one(q, p = []) {
  const { rows } = await pool.query(q, p);
  return rows[0] ?? null;
}
export async function all(q, p = []) {
  const { rows } = await pool.query(q, p);
  return rows;
}
export async function run(q, p = []) {
  return pool.query(q, p);
}
