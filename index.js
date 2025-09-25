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
  HeadObjectCommand,
  DeleteObjectCommand,
} from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import fetch from "node-fetch";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";

// === Cognito ===
import {
  CognitoIdentityProviderClient,
  SignUpCommand,
  ConfirmSignUpCommand,
  InitiateAuthCommand,
  AssociateSoftwareTokenCommand,   // ← 新增
  VerifySoftwareTokenCommand,      // ← 新增
  SetUserMFAPreferenceCommand,     // ← 新增
  RespondToAuthChallengeCommand    // ← 新增
} from "@aws-sdk/client-cognito-identity-provider";
import { CognitoJwtVerifier } from "aws-jwt-verify";
import crypto from "crypto";

import { initializePool, one, all, run } from "./db.js";
import { fromIni } from "@aws-sdk/credential-provider-ini";
// for screte manager
import {
  SecretsManagerClient,
  GetSecretValueCommand,
} from "@aws-sdk/client-secrets-manager";
import { defaultProvider } from "@aws-sdk/credential-provider-node";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
// import { CONFIG, initConfig } from "./config.js";

import "dotenv/config";
//  -----public variables from env file----------------------
const AWS_REGION = process.env.AWS_REGION;

// ----- resolve __dirname -----
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export let CONFIG = {};


(async () => {

// Utility: decide how to load credentials
async function getCredentialsProvider() {
  if (process.env.IS_EC2 === "true") {
    return defaultProvider(); // 直接回傳 provider function
  } else {
    return fromIni({ profile: "default" });
  }
}
const creds = await getCredentialsProvider();

// ---- load params from the param store ----

const client_param = new SSMClient({
  region: AWS_REGION,
  credentials: creds,
});

const paramResponse = await client_param.send(
  new GetParameterCommand({ Name: process.env.PARAMETER_NAME, WithDecryption: true })
);
CONFIG = JSON.parse(paramResponse.Parameter?.Value || "{}");
console.log("COGNITO_USER_POOL_ID222:"+CONFIG.COGNITO_USER_POOL_ID);


// ---- load secret keys from the secret manager ----
const secret_name = process.env.AWS_SECRET_NAME;
const client = new SecretsManagerClient({
  region: AWS_REGION,
  credentials: creds,
});
let response;

try {
  response = await client.send(
    new GetSecretValueCommand({
      SecretId: secret_name,
      VersionStage: "AWSCURRENT", // VersionStage defaults to AWSCURRENT if unspecified
    })
  );
} catch (error) {
  // For a list of exceptions thrown, see
  // https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
  throw error;
}
const secret = JSON.parse(response.SecretString);

// === S3 ===
const s3 = new S3Client({
  region: AWS_REGION,
  credentials: creds,
});
const BUCKET = CONFIG.AWS_S3_BUCKET;

// export DB secret key for DB.js to access
const pool = initializePool({
  user: secret.PGUSER,
  password: secret.PGPASSWORD,
  client: CONFIG.DB_CLIENT,
  host: CONFIG.PGHOST,
  port: CONFIG.PGPORT,
  database: CONFIG.PGDATABASE,
});

// ----- config -----
const PORT = Number(process.env.PORT || 8080);
const OPENSUBTITLES_API_KEY = secret.OPENSUBTITLES_API_KEY || "";
ffmpeg.setFfmpegPath(ffmpegInstaller.path);
const log = (...a) => console.log(new Date().toISOString(), ...a);

// === Cognito config from env ===
// const COG_REGION = process.env.COGNITO_REGION || "ap-southeast-2";
const COG_USER_POOL_ID = CONFIG.COGNITO_USER_POOL_ID || "";
const COG_CLIENT_ID = secret.COGNITO_CLIENT_ID || "";
const COG_CLIENT_SECRET = secret.COGNITO_CLIENT_SECRET || "";

const cogClient = new CognitoIdentityProviderClient({ region: AWS_REGION });
const hasSecret =
  typeof COG_CLIENT_SECRET === "string" && COG_CLIENT_SECRET.length > 0;

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
for (const d of [UP_DIR, OUT_DIR, THUMB_DIR])
  fs.mkdirSync(d, { recursive: true });

// ---- admin allowlist from env ----
const ADM_USERNAMES = (CONFIG.ADMIN_USERNAMES || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

const ADM_EMAILS = (CONFIG.ADMIN_EMAILS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
const ADM_GROUPS = (CONFIG.ADMIN_GROUPS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
console.log("ADM_USERNAMES:", ADM_USERNAMES);

function isAdminByEnv(username) {
  const u = (username || "").toLowerCase();
  return ADM_USERNAMES.includes(u);
}


// auth middleware
async function auth(req, res, next) {
  try {
    const m = (req.headers.authorization || "").match(/^Bearer (.+)$/i);
    if (!m) return res.status(401).json({ ok: false, error: "missing token" });

    const token = m[1];
    const payload = await idTokenVerifier.verify(token);
    const rawName = payload["cognito:username"];
    const username = typeof rawName === "string" ? rawName.trim() : "";

    // 从 token 中提取 groups
    const groups = Array.isArray(payload["cognito:groups"])
      ? payload["cognito:groups"]
      : [];

    // 判断是否 admin
    // const isAdmin = groups.includes("Admin") || isAdminByEnv(payload, username);
    const isAdmin = groups.includes("Admin") || isAdminByEnv(username);

    req.user = {
      sub: username,
      email: payload.email || null,
      groups,
      jwt: token,
      admin: isAdmin,
    };

    next();
  } catch (e) {
    return res
      .status(401)
      .json({ ok: false, error: "invalid token", detail: e.message });
  }
}

// Multer temp
const tmpDir = path.join(process.cwd(), "uploads");
if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, tmpDir),
  filename: (_req, file, cb) => cb(null, `${nowTs()}-${file.originalname}`),
});
function nowTs() {
  return Date.now();
}
const upload = multer({ storage });

// helpers
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
    return res
      .status(400)
      .json({ ok: false, error: "username, password, email required" });
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

// app.post("/login", async (req, res) => {
//   const { username, password } = req.body || {};
//   if (!username || !password) {
//     return res
//       .status(400)
//       .json({ ok: false, error: "username, password required" });
//   }

//   let idToken;
//   try {
//     const authParams = { USERNAME: username, PASSWORD: password };
//     const sh = makeSecretHash(username);
//     if (sh) authParams.SECRET_HASH = sh;

//     const out = await cogClient.send(
//       new InitiateAuthCommand({
//         AuthFlow: "USER_PASSWORD_AUTH",
//         ClientId: COG_CLIENT_ID,
//         AuthParameters: authParams,
//       })
//     );

//     idToken = out?.AuthenticationResult?.IdToken;
//     if (!idToken) return res.status(401).json({ ok: false, error: "no token" });
//   } catch (e) {
//     console.error("[/login] Cognito error:", e.name, e.message);
//     return res.status(401).json({
//       ok: false,
//       error: e.name || "AuthError",
//       message: e.message || "Login failed",
//     });
//   }

//   res.json({ ok: true, authToken: idToken });

//   try {
//     await run(
//       `INSERT INTO accounts(owner, balance_cents, updated_at)
//        VALUES ($1, 0, now())
//        ON CONFLICT (owner) DO NOTHING`,
//       [username]
//     );
//   } catch (e) {
//     console.warn("[login] ensure account row failed:", e.message);
//   }
// });


app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ ok: false, error: "username and password required" });
  }

  try {
    // 组装登录参数
    const authParams = { USERNAME: username, PASSWORD: password };
    const sh = makeSecretHash(username);
    if (sh) authParams.SECRET_HASH = sh;

    // 调用 Cognito 登录
    const out = await cogClient.send(new InitiateAuthCommand({
      AuthFlow: "USER_PASSWORD_AUTH",
      ClientId: COG_CLIENT_ID,
      AuthParameters: authParams,
    }));

    // ========== 处理 MFA 挑战 ==========
    if (out.ChallengeName === "SOFTWARE_TOKEN_MFA") {
      return res.json({
        ok: true,
        challenge: "SOFTWARE_TOKEN_MFA",
        session: out.Session,
        username
      });
    }

    // ========== 正常登录 ==========
    const idToken = out?.AuthenticationResult?.IdToken;
    const accessToken = out?.AuthenticationResult?.AccessToken;

    if (!idToken || !accessToken) {
      return res.status(401).json({ ok: false, error: "no token" });
    }

    // 在本地数据库里初始化账户余额（Postgres 版本，与你现有 schema 一致）
    await run(
      `INSERT INTO accounts(owner, balance_cents, updated_at)
        VALUES ($1, 0, now())
      ON CONFLICT (owner) DO NOTHING`,
      [username]
    );


    return res.json({ ok: true, authToken: idToken, accessToken });
  } catch (e) {
    console.error("login error", e);
    return res.status(401).json({ ok: false, error: e.name || "AuthError", message: e.message });
  }
});

app.post("/auth/mfa/verify-login", async (req, res) => {
  const { username, code, session } = req.body || {};
  if (!username || !code || !session) {
    return res.status(400).json({ ok: false, error: "username, code, session required" });
  }
  try {
    const sh = makeSecretHash(username);
    const out = await cogClient.send(new RespondToAuthChallengeCommand({
      ClientId: COG_CLIENT_ID,
      ChallengeName: "SOFTWARE_TOKEN_MFA",
      Session: session,
      ChallengeResponses: {
        USERNAME: username,
        SOFTWARE_TOKEN_MFA_CODE: String(code).trim(),
        ...(sh ? { SECRET_HASH: sh } : {})
      }
    }));
    const idToken = out?.AuthenticationResult?.IdToken;
    const accessToken = out?.AuthenticationResult?.AccessToken;
    if (!idToken || !accessToken) {
      return res.status(401).json({ ok: false, error: "no token after mfa" });
    }
    return res.json({ ok: true, authToken: idToken, accessToken });
  } catch (e) {
    return res.status(401).json({ ok: false, error: e.name || "MFAChallengeError", message: e.message });
  }
});

app.post("/auth/mfa/setup", auth, async (req, res) => {
  const { accessToken, issuer = "VideoAPI" } = req.body || {};
  if (!accessToken) return res.status(400).json({ ok: false, error: "accessToken required" });

  try {
    const assoc = await cogClient.send(new AssociateSoftwareTokenCommand({
      AccessToken: accessToken
    }));
    const secret = assoc.SecretCode; // Base32
    if (!secret) return res.status(500).json({ ok: false, error: "no secret from cognito" });
    const label = encodeURIComponent(`${issuer}:${req.user.sub}`);
    const issuerEnc = encodeURIComponent(issuer);
    const otpauthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${issuerEnc}&algorithm=SHA1&digits=6&period=30`;
    return res.json({ ok: true, secret, otpauthUrl });
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.name || "MFASetupError", message: e.message });
  }
});

app.post("/auth/mfa/enable", auth, async (req, res) => {
  const { accessToken, code } = req.body || {};
  if (!accessToken || !code) return res.status(400).json({ ok: false, error: "accessToken, code required" });

  try {
    const verify = await cogClient.send(new VerifySoftwareTokenCommand({
      AccessToken: accessToken,
      UserCode: String(code).trim(),
      FriendlyDeviceName: "auth-app"
    }));
    if (verify.Status !== "SUCCESS") {
      return res.status(401).json({ ok: false, error: "verify_failed" });
    }

    await cogClient.send(new SetUserMFAPreferenceCommand({
      AccessToken: accessToken,
      SoftwareTokenMfaSettings: { Enabled: true, PreferredMfa: true }
    }));
    return res.json({ ok: true });
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.name || "MFAEnableError", message: e.message });
  }
});







// whoami
app.get("/auth/whoami", auth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

// ----- account -----
app.get("/me", auth, async (req, res) => {
  const row = await one(
    "SELECT balance_cents, updated_at FROM accounts WHERE owner=$1",
    [req.user.sub]
  );
  res.json({
    user: req.user.sub,
    admin: !!req.user.admin,
    balance_cents: row?.balance_cents ?? 0,
    updated_at: row?.updated_at ?? null,
  });
});

app.post("/accounts/topup", auth, async (req, res) => {
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
app.post("/upload-url", auth, async (req, res) => {
  const id = uuidv4();
  const original = req.body.filename || "upload.bin";
  const safeName = `${id}-${original.replace(/[^\w.\-]+/g, "_")}`;
  const username = req.user.sub;
  const fileSize = req.body.size;
  const fileType = req.body.mimetype;
  const s3Key = `${username}/uploaded/${safeName}`;

  try {
    // 建立 presigned PUT URL
    const command = new PutObjectCommand({
      Bucket: BUCKET,
      Key: s3Key,
      ContentType: fileType || "application/octet-stream",
    });

    const uploadUrl = await getSignedUrl(s3, command, { expiresIn: 3600 });
    console.log("Presigned upload URL generated!");

    // 存 DB（只存 metadata，不存檔案）
    const insert = run(
      `INSERT INTO files (id,owner,filename,stored_path,size_bytes,mime,uploaded_at,owner_groups)
      VALUES ($1,$2,$3,$4,$5,$6,now(),$7)`,
      [
        id,
        username,
        original,
        s3Key,
        fileSize,
        fileType || null,
        JSON.stringify(req.user.groups || []),
      ]
    );

    res.json({
      ok: true,
      fileId: id,
      s3Key,
      uploadUrl,
    });
  } catch (err) {
    console.error("Error generating upload URL:", err);
    res.status(500).json({ ok: false, error: "failed to generate URL" });
  }
});

app.get("/debug/aws", async (_req, res) => {
  try {
    const sts = new STSClient({ region: AWS_REGION });
    const out = await sts.send(new GetCallerIdentityCommand({}));
    res.json({
      ok: true,
      account: out.Account,
      arn: out.Arn,
      userId: out.UserId,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.name, message: e.message });
  }
});

app.get("/debug/db", async (_req, res) => {
  try {
    const r = await one("SELECT 1 AS ok");
    res.json({ ok: true, db: r?.ok === 1 });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
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

  const totalRow = await one(
    `SELECT COUNT(*)::int AS c FROM files ${whereSql}`,
    params
  );
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

// ----- 简化版 OpenSubtitles subtitles meta -----
app.post("/files/:id/subs", auth, async (req, res) => {
  if (!OPENSUBTITLES_API_KEY) {
    return res
      .status(400)
      .json({ ok: false, error: "OPENSUBTITLES_API_KEY missing" });
  }

  const OS_USER_AGENT =
    secret.OPENSUBTITLES_USER_AGENT || "video-api-client/1.0";

  // 确认文件存在
  const f = await one(`SELECT id FROM files WHERE id=$1 AND owner=$2`, [
    req.params.id,
    req.user.sub,
  ]);
  if (!f) return res.sendStatus(404);

  const query = String(req.body?.query || "").trim();
  const languages = Array.isArray(req.body?.languages)
    ? req.body.languages
    : ["en"];
  if (!query) {
    return res.status(400).json({ ok: false, error: "query required" });
  }

  try {
    const url =
      `https://api.opensubtitles.com/api/v1/subtitles?` +
      `query=${encodeURIComponent(query)}&languages=${encodeURIComponent(
        languages.join(",")
      )}` +
      `&order_by=downloads&order_direction=desc`;

    const r = await fetch(url, {
      headers: {
        "Api-Key": OPENSUBTITLES_API_KEY,
        "User-Agent": OS_USER_AGENT,
        Accept: "application/json",
      },
    });

    const text = await r.text();
    if (!r.ok) {
      return res.status(502).json({
        ok: false,
        error: "OpenSubtitlesHTTP",
        message: `HTTP ${r.status}: ${text}`,
      });
    }

    const j = JSON.parse(text);
    const top = Array.isArray(j?.data) ? j.data.slice(0, 5) : [];

    const payload = {
      opensubtitles: {
        query,
        languages,
        total: j?.total_count ?? top.length,
        top,
        fetched_at: new Date().toISOString(),
      },
    };

    await run(
      `UPDATE files
         SET ext_meta = COALESCE(ext_meta, '{}'::jsonb) || $1::jsonb
       WHERE id=$2 AND owner=$3`,
      [JSON.stringify(payload), req.params.id, req.user.sub]
    );

    res.json({ ok: true, count: top.length, meta: payload });
  } catch (e) {
    res
      .status(500)
      .json({ ok: false, error: "SubsFetchError", message: e.message });
  }
});


app.delete("/files/:id", auth, async (req, res) => {
  const fileId = req.params.id;
  const owner = req.user.sub;

  // 先查出 S3 Key（stored_path），以便稍后异步删除
  const row = await one(
    `SELECT stored_path FROM files WHERE id=$1 AND owner=$2`,
    [fileId, owner]
  );
  if (!row) return res.sendStatus(404);
  const s3Key = row.stored_path;

  // 1) 事务：解除 jobs 关联并删除 files 记录
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // 解除关联：不让历史转码任务受到 FK/业务影响
    await client.query(
      `UPDATE jobs SET file_id = NULL WHERE file_id=$1 AND owner=$2`,
      [fileId, owner]
    );

    // 删除文件记录
    const del = await client.query(
      `DELETE FROM files WHERE id=$1 AND owner=$2`,
      [fileId, owner]
    );

    if (del.rowCount !== 1) {
      await client.query("ROLLBACK");
      return res
        .status(404)
        .json({ ok: false, error: "file not found or already deleted" });
    }

    await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    console.error("[DELETE /files/:id] DB error:", e);
    return res.status(500).json({ ok: false, error: "DB delete failed" });
  } finally {
    client.release();
  }

  // 2) 先立即回应前端成功，让 UI 能刷新
  res.json({ ok: true });

  // 3) S3 删除改为“尽力而为”，失败只打日志，不影响用户体验
  (async () => {
    try {
      await s3.send(
        new DeleteObjectCommand({
          Bucket: BUCKET,
          Key: s3Key,
        })
      );
    } catch (e) {
      // S3 删除失败一般不阻断流程（可能文件早已不存在）
      console.warn("[DELETE /files/:id] S3 delete warn:", e?.message || e);
    }
  })().catch(() => {});
});

// ----- admin: list all users' files -----
app.get("/admin/files", auth, async (req, res) => {
  if (!req.user?.admin)
    return res.status(403).json({ ok: false, error: "forbidden" });

  const { page, size, offset, q, sort, order } = listParams(req, {
    sortWhitelist: ["uploaded_at", "size_bytes", "filename", "owner"],
    defaultSort: "uploaded_at",
  });

  const where = [];
  const params = [];
  if (q) {
    where.push(`(filename ILIKE $1 OR owner ILIKE $1)`);
    params.push(`%${q}%`);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const totalRow = await one(
    `SELECT COUNT(*)::int AS c FROM files ${whereSql}`,
    params
  );
  const total = totalRow?.c ?? 0;

  const rows = await all(
    `SELECT id, owner, filename, size_bytes, mime, uploaded_at, owner_groups
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

// download (self-only)

app.get("/download/original/:fileId", auth, async (req, res) => {
  const row = await one(
    `SELECT stored_path, filename FROM files WHERE id=$1 AND owner=$2`,
    [req.params.fileId, req.user.sub]
  );
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

  const totalRow = await one(
    `SELECT COUNT(*)::int AS c FROM jobs ${whereSql}`,
    params
  );
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
  const row = await one(
    `SELECT owner, thumbnail_path, thumbnail_name FROM jobs WHERE id=$1`,
    [req.params.id]
  );
  if (!row || row.owner !== req.user.sub || !row.thumbnail_path)
    return res.sendStatus(404);

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
  const j = await one(
    `SELECT owner,status,output_path,output_name FROM jobs WHERE id=$1`,
    [req.params.jobId]
  );
  if (!j || j.owner !== req.user.sub) return res.sendStatus(404);
  if (j.status !== "completed" || !j.output_path)
    return res.status(409).json({ ok: false, error: "not ready" });

  try {
    const command = new GetObjectCommand({
      Bucket: BUCKET,
      Key: j.output_path, // 這裡必須是 S3 Key
      ResponseContentDisposition: `attachment; filename="${path.basename(
        j.output_name || j.output_path
      )}"`,
    });

    // use pre-sign url to download.
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
    jobId = await createJobWithCharge(
      req.user.sub,
      f.id,
      TRANSCODE_COST_CENTS,
      {
        format,
        crf,
        preset,
        scale,
      }
    );
  } catch (e) {
    if (e.message === "INSUFFICIENT_FUNDS")
      return res.status(402).json({ ok: false, error: "insufficient funds" });
    return res.status(500).json({ ok: false, error: e.message });
  }

  // 立即响应
  res.json({ ok: true, jobId });
  await run(`UPDATE jobs SET status='running', updated_at=now() WHERE id=$1`, [
    jobId,
  ]);

  // 单任务专用 DB 连接（避免连接暴增）
  const dbConn = await pool.connect();

  // 输出文件路径（可能在失败时清理）
  const outId = uuidv4();
  const outName = `${outId}-${path.basename(
    f.filename,
    path.extname(f.filename)
  )}.${format}`;
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
      const s3Object = await s3.send(
        new GetObjectCommand({ Bucket: BUCKET, Key: f.stored_path })
      );
      const s3Stream = s3Object.Body;

      ffmpeg(s3Stream)
        .addOptions([
          "-y",
          "-vf",
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
    const thumbName = `${uuidv4()}-${path.basename(
      f.filename,
      path.extname(f.filename)
    )}.jpg`;
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
    await dbConn.query(
      `UPDATE jobs SET status='failed', updated_at=now() WHERE id=$1`,
      [jobId]
    );

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

// file_id TEXT, -- 注意：不再 NOT NULL
const schema = process.env.PGSCHEMA || "public";
async function ensureTables() {
  // 指定 schema========================change to the schema name
  await run(`SET search_path TO "${schema}";`);

  // 建立表格
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
      file_id TEXT,
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
    ALTER TABLE files ADD COLUMN IF NOT EXISTS owner_groups JSONB;
  `);
}
await ensureTables();

// ----- start -----
const HOST = process.env.IS_EC2 === "true" ? "0.0.0.0" : "localhost";

app.listen(PORT, HOST, () => {
  const displayHost =
    HOST === "0.0.0.0" ? process.env.EC2_PUBLIC_URL || "0.0.0.0" : "localhost";
  console.log(`Server listening on http://${displayHost}:${PORT}`);
});

})();