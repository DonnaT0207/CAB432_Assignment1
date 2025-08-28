import fetch from "node-fetch";

// envs
const BASE = process.env.BASE || "http://localhost:8080";
const USERNAME = process.env.USERNAME || "admin";
const PASSWORD = process.env.PASSWORD || "admin123";
const FILE_ID = process.env.FILE_ID; // must be provided
const CONCURRENCY = Number(process.env.C || 4);
const DURATION = Number(process.env.T || 300);
const PRESET = process.env.PRESET || "veryslow";
const CRF = Number(process.env.CRF || 18);
const THREADS = Number(process.env.THREADS || 1);
const SCALE = process.env.SCALE || "1920:1080";

if (!FILE_ID) {
  console.error("Please set FILE_ID env to an uploaded file id.");
  process.exit(1);
}

async function login() {
  const r = await fetch(`${BASE}/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: USERNAME, password: PASSWORD })
  });
  const j = await r.json();
  if (!j.ok) throw new Error("login failed");
  return j.token;
}

async function once(token) {
  const r = await fetch(`${BASE}/transcode/${FILE_ID}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({ preset: PRESET, crf: CRF, threads: THREADS, scale: SCALE })
  });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  const j = await r.json();
  if (!j.ok) throw new Error("job not ok");
  return j.jobId;
}

(async () => {
  const token = await login();
  let ok = 0, fail = 0;
  const endAt = Date.now() + DURATION * 1000;

  function worker() {
    if (Date.now() >= endAt) return;
    once(token).then(() => { ok++; worker(); }).catch(() => { fail++; worker(); });
  }
  for (let i = 0; i < CONCURRENCY; i++) worker();

  const iv = setInterval(() => {
    const left = Math.max(0, Math.ceil((endAt - Date.now()) / 1000));
    process.stdout.write(`\rtime_left=${left}s OK=${ok} FAIL=${fail}      `);
    if (Date.now() >= endAt) { clearInterval(iv); console.log("\nDone"); process.exit(0); }
  }, 1000);
})();
