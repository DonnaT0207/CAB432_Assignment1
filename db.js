import pg from "pg";
import fs from "fs";
import path from "path";
import 'dotenv/config';
import { CONFIG } from "./index.js";


let pool;
export function initializePool(secretConfig) {
  // const pool = new pg.Pool({
  pool = new pg.Pool({
    host: CONFIG.PGHOST,
    port: Number(CONFIG.PGPORT || 5432),
    user: secretConfig.user,
    password: secretConfig.password,
    database: CONFIG.PGDATABASE,
    max: 3, // Limit the number of connections to avoid exceeding your account quota
    idleTimeoutMillis: 30000, //Release idle connections after 30s
    connectionTimeoutMillis: 5000,
    ssl: { rejectUnauthorized: false },
  });

  pool.on("connect", async (client) => {
    const schema = process.env.PGSCHEMA || "public"; // Read schema from .env
    try {
      // Set search_path with fallback to public
      await client.query(`SET search_path TO ${schema}, public;`);
      // Set statement timeout to prevent long-running queries
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
