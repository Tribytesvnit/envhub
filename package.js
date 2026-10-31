#!/usr/bin/env node
const fs = require("fs");
const path = require("path");

/**
 * Pulls variables from EnvHub using a User API Key and Project ID,
 * and writes them to a .env file.
 */
async function pull(options = {}) {
  const {
    apiKey = options.token || process.env.ENVHUB_API_KEY || process.env.ENVHUB_TOKEN,
    projectId = process.env.ENVHUB_PROJECT_ID,
    environment = process.env.ENVHUB_ENV || "development",
    path: targetPath = path.resolve(process.cwd(), ".env"),
    endpoint = process.env.ENVHUB_URL || "http://localhost:3000",
    timeoutMs = 10000
  } = options;

  if (!apiKey) throw new Error("[envhub] Missing API key. Pass 'apiKey' (--key) or set ENVHUB_API_KEY.");
  if (!projectId) throw new Error("[envhub] Missing projectId. Pass 'projectId' (--project) or set ENVHUB_PROJECT_ID.");

  const url = new URL("/api/envs", endpoint);
  url.search = new URLSearchParams({ projectId, environment, format: "raw" }).toString();

  let res;
  try {
    res = await fetch(url, {
      headers: { Authorization: `Bearer ${apiKey}`, "x-api-key": apiKey },
      signal: AbortSignal.timeout(timeoutMs)
    });
  } catch (err) {
    throw new Error(`[envhub] Could not reach ${url.origin}: ${err.message}`);
  }

  if (!res.ok) {
    let detail = await res.text();
    try { detail = JSON.parse(detail).error || detail; } catch { /* plain text */ }
    throw new Error(`[envhub] Failed to pull config (${res.status}): ${detail}`);
  }

  const rawEnv = await res.text();

  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  const tmp = `${targetPath}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, rawEnv, { encoding: "utf8", mode: 0o600 });
  try {
    fs.renameSync(tmp, targetPath);
  } catch {
    fs.copyFileSync(tmp, targetPath);
    fs.unlinkSync(tmp);
  }

  const count = rawEnv.split("\n").filter((l) => l.trim()).length;
  return { path: targetPath, count, projectId, environment };
}

/**
 * Pushes a local .env file to EnvHub (requires 'editor', 'admin', or 'owner' role).
 */
async function push(options = {}) {
  const {
    apiKey = options.token || process.env.ENVHUB_API_KEY || process.env.ENVHUB_TOKEN,
    projectId = process.env.ENVHUB_PROJECT_ID,
    environment = process.env.ENVHUB_ENV || "development",
    path: sourcePath = path.resolve(process.cwd(), ".env"),
    endpoint = process.env.ENVHUB_URL || "http://localhost:3000",
    timeoutMs = 10000
  } = options;

  if (!apiKey) throw new Error("[envhub] Missing API key. Pass 'apiKey' (--key) or set ENVHUB_API_KEY.");
  if (!projectId) throw new Error("[envhub] Missing projectId. Pass 'projectId' (--project) or set ENVHUB_PROJECT_ID.");
  if (!fs.existsSync(sourcePath)) throw new Error(`[envhub] Local file not found: ${sourcePath}`);

  const rawEnv = fs.readFileSync(sourcePath, "utf8");
  const url = new URL("/api/envs/bulk", endpoint);

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
      "x-api-key": apiKey
    },
    body: JSON.stringify({ projectId, environment, rawEnv }),
    signal: AbortSignal.timeout(timeoutMs)
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(`[envhub] Failed to push config (${res.status}): ${data.error || res.statusText}`);
  }

  return { path: sourcePath, count: data.count, projectId, environment };
}

module.exports = { pull, push };

// ---------- CLI ----------
if (require.main === module) {
  const args = process.argv.slice(2);
  const flag = (name) => {
    const i = args.indexOf(`--${name}`);
    return i !== -1 ? args[i + 1] : undefined;
  };

  if (args.includes("--help") || args.includes("-h")) {
    console.log(`
⚡ EnvHub CLI
Usage:
  Pull: node package.js --key <API_KEY> --project <PROJECT_ID> [--env <stage>] [--out <file>]
  Push: node package.js --push --key <API_KEY> --project <PROJECT_ID> [--env <stage>] [--in <file>]
`);
    process.exit(0);
  }

  const isPush = args.includes("--push");
  const action = isPush ? push : pull;
  const fileFlag = isPush ? (flag("in") || flag("out")) : flag("out");

  action({
    apiKey: flag("key") || flag("token"),
    projectId: flag("project"),
    environment: flag("env"),
    endpoint: flag("url"),
    path: fileFlag && path.resolve(fileFlag)
  })
    .then(({ path: p, count, projectId, environment }) => {
      if (isPush) {
        console.log(`✔ [envhub] Pushed ${count} variable(s) from ${p} -> ${projectId} (${environment})`);
      } else {
        console.log(`✔ [envhub] Pulled ${count} variable(s) from ${projectId} (${environment}) -> ${p}`);
      }
    })
    .catch((err) => {
      console.error(`❌ ${err.message}`);
      process.exit(1);
    });
}
