// db.js
import pg from "pg";
import fs from "fs";
import path from "path";
import 'dotenv/config';

import { CONFIG } from "./index.js";


let pool;
// export const pool = new pg.Pool({
export function initializePool(secretConfig) {
  // const pool = new pg.Pool({
  pool = new pg.Pool({
    host: CONFIG.PGHOST,
    port: Number(CONFIG.PGPORT || 5432),
    user: secretConfig.user,
    password: secretConfig.password,
    database: CONFIG.PGDATABASE,
    max: 3, // ★★★ 限制连接数，避免超过你账号上限
    idleTimeoutMillis: 30000, // 空闲连接 5s 回收
    connectionTimeoutMillis: 5000,
    ssl: { rejectUnauthorized: false },
  });

  pool.on("connect", async (client) => {
    const schema = process.env.PGSCHEMA || "public"; // 從 .env 讀取 schema
    try {
      // 設定 search_path，並加上 public 作 fallback
      await client.query(`SET search_path TO ${schema}, public;`);
      // 設定 statement_timeout 防止長時間占用
      await client.query(`SET statement_timeout = 15000;`);
    } catch (err) {
      console.error("Failed to configure client:", err);
    }
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
