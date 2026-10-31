require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const path = require("path");
const {
  encrypt,
  decrypt,
  blindIndex,
  generateApiKey,
  generateProjectId
} = require("./cryptoHelper");

// ---------- Config ----------
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI
const JWT_SECRET = process.env.JWT_SECRET 
const DB_NAME = "envguard_db";
const TOKEN_TTL = "7d";
const ENVIRONMENTS = ["development", "staging", "production"];

const ROLE_RANK = { viewer: 1, editor: 2, admin: 3, owner: 4 };
const ASSIGNABLE_ROLES = ["admin", "editor", "viewer"];

if (JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters");
}

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "250kb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 50,
  standardHeaders: true,
  legacyHeaders: false
});

let usersCol, projectsCol, envsCol, logsCol;

// ---------- Helpers ----------
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const normEmail = (e) => String(e || "").toLowerCase().trim();
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const KEY_RE = /^[A-Z_][A-Z0-9_]*$/;
const DUMMY_HASH = bcrypt.hashSync("dummy-password", 10);

const signToken = (user) =>
  jwt.sign({ userId: String(user._id), email: user.email }, JWT_SECRET, { expiresIn: TOKEN_TTL });

/** Format a value so standard .env parsers read it back accurately. */
function dotenvValue(v) {
  if (/^[\w@%+=:,./-]*$/.test(v)) return v;
  if (!v.includes('"')) return `"${v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n")}"`;
  if (!/['\n]/.test(v)) return `'${v}'`;
  if (!/[`\n]/.test(v)) return `\`${v}\``;
  return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n")}"`;
}

/** Parse raw .env text into [{ key, value }] pairs */
function parseDotenv(rawText) {
  const result = [];
  const lines = String(rawText || "").split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const cleaned = line.startsWith("export ") ? line.slice(7).trim() : line;
    const eqIdx = cleaned.indexOf("=");
    if (eqIdx === -1) continue;
    const key = cleaned.slice(0, eqIdx).trim().toUpperCase();
    let val = cleaned.slice(eqIdx + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    val = val.replace(/\\n/g, "\n");
    if (KEY_RE.test(key) && key.length <= 128 && val.length <= 10000) {
      result.push({ key, value: val });
    }
  }
  return result;
}

/** Record an event in the project audit trail */
async function logActivity(projectObjId, actorEmail, action, details = {}) {
  try {
    await logsCol.insertOne({
      projectId: projectObjId,
      actorEmail,
      action,
      details,
      createdAt: new Date()
    });
  } catch (err) {
    console.error("Audit log error:", err);
  }
}

/** Ensures a user document has an API key */
async function ensureUserApiKey(user) {
  if (user.encryptedApiKey) {
    const existing = decrypt(user.encryptedApiKey);
    if (existing) return existing;
  }
  const rawKey = generateApiKey();
  await usersCol.updateOne(
    { _id: user._id },
    {
      $set: {
        apiKeyHash: blindIndex(rawKey),
        encryptedApiKey: encrypt(rawKey),
        apiKeyUpdatedAt: new Date()
      }
    }
  );
  return rawKey;
}

/** Ensures a project document has a short prj_... ID */
async function ensureShortProjectId(project) {
  if (project.projectId) return project.projectId;
  const newId = generateProjectId();
  await projectsCol.updateOne({ _id: project._id }, { $set: { projectId: newId } });
  project.projectId = newId;
  return newId;
}

// ---------- Middleware ----------
const requireUser = ah(async (req, res, next) => {
  const apiKeyHeader = req.headers["x-api-key"];
  const authHeader = req.headers.authorization || "";
  const [scheme, bearerVal] = authHeader.split(" ");

  const rawToken = apiKeyHeader || (scheme === "Bearer" ? bearerVal : "");
  if (!rawToken) return res.status(401).json({ error: "Missing authentication token or API key" });

  if (rawToken.startsWith("ehk_")) {
    const user = await usersCol.findOne({ apiKeyHash: blindIndex(rawToken) });
    if (!user) return res.status(401).json({ error: "Invalid API key" });
    req.user = { userId: String(user._id), email: user.email, viaApiKey: true };
    return next();
  }

  try {
    req.user = jwt.verify(rawToken, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired session" });
  }
});

/** Resolves project and attaches req.project and req.memberRole */
const requireProjectAccess = ah(async (req, res, next) => {
  const rawId = String(
    req.params?.projectId || req.query?.projectId || req.body?.projectId || ""
  ).trim();

  if (!rawId) {
    return res.status(400).json({ error: "Missing projectId" });
  }

  const idFilter = ObjectId.isValid(rawId)
    ? { $or: [{ projectId: rawId }, { _id: new ObjectId(rawId) }] }
    : { projectId: rawId };

  const project = await projectsCol.findOne({
    ...idFilter,
    "members.email": req.user.email
  });

  if (!project) {
    return res.status(403).json({ error: "Project not found or access denied" });
  }

  await ensureShortProjectId(project);
    const userEmail = normEmail(req.user.email);
    const memberEntry = (project.members || []).find((m) => normEmail(m.email) === userEmail);
    req.memberRole = normEmail(project.ownerEmail) === userEmail ? "owner" : (memberEntry?.role || "viewer");
    req.project = project;
  next();
});

/** Enforces minimum role rank ('viewer' | 'editor' | 'admin' | 'owner') */
const requireMinRole = (minRole) => (req, res, next) => {
  const userRank = ROLE_RANK[req.memberRole] || 0;
  const requiredRank = ROLE_RANK[minRole] || 99;
  if (userRank < requiredRank) {
    return res.status(403).json({
      error: `Permission denied: requires '${minRole}' role or higher (your role is '${req.memberRole}')`
    });
  }
  next();
};

// ---------- Routes ----------
function registerRoutes() {
  // ----- Auth -----
  app.post("/api/auth/signup", authLimiter, ah(async (req, res) => {
    const email = normEmail(req.body.email);
    const password = String(req.body.password || "");
    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: "Enter a valid email" });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });

    const rawApiKey = generateApiKey();
    try {
      const user = {
        email,
        password: await bcrypt.hash(password, 12),
        apiKeyHash: blindIndex(rawApiKey),
        encryptedApiKey: encrypt(rawApiKey),
        createdAt: new Date()
      };
      const result = await usersCol.insertOne(user);
      res.status(201).json({
        token: signToken({ _id: result.insertedId, email }),
        email,
        apiKey: rawApiKey
      });
    } catch (err) {
      if (err.code === 11000) return res.status(409).json({ error: "An account with this email already exists" });
      throw err;
    }
  }));

  app.post("/api/auth/login", authLimiter, ah(async (req, res) => {
    const email = normEmail(req.body.email);
    const password = String(req.body.password || "");
    const user = await usersCol.findOne({ email });
    const ok = await bcrypt.compare(password, user ? user.password : DUMMY_HASH);
    if (!user || !ok) return res.status(401).json({ error: "Invalid credentials" });

    const apiKey = await ensureUserApiKey(user);
    res.json({ token: signToken(user), email: user.email, apiKey });
  }));

  app.get("/api/auth/me", requireUser, ah(async (req, res) => {
    const user = await usersCol.findOne({ _id: new ObjectId(req.user.userId) });
    if (!user) return res.status(401).json({ error: "User not found" });
    const apiKey = await ensureUserApiKey(user);
    res.json({ email: user.email, apiKey });
  }));

  app.post("/api/auth/api-key/regenerate", requireUser, ah(async (req, res) => {
    const newKey = generateApiKey();
    await usersCol.updateOne(
      { _id: new ObjectId(req.user.userId) },
      {
        $set: {
          apiKeyHash: blindIndex(newKey),
          encryptedApiKey: encrypt(newKey),
          apiKeyUpdatedAt: new Date()
        }
      }
    );
    res.json({ apiKey: newKey });
  }));

  // ----- Projects & Team Role Management -----
// Inside app.get("/api/projects", ...) in index.js:
    app.get("/api/projects", requireUser, ah(async (req, res) => {
        const userEmail = normEmail(req.user.email);
        const list = await projectsCol.find({ "members.email": userEmail }).sort({ createdAt: 1 }).toArray();
        for (const p of list) {
            if (!p.projectId) await ensureShortProjectId(p);
            const me = (p.members || []).find((m) => normEmail(m.email) === userEmail);
            p.myRole = normEmail(p.ownerEmail) === userEmail ? "owner" : (me?.role || "viewer");
        }
        res.json(list);
    }));

  app.post("/api/projects", requireUser, ah(async (req, res) => {
    const name = String(req.body.name || "").trim().slice(0, 80) || "Untitled Project";
    const projectId = generateProjectId();
    const doc = {
      projectId,
      name,
      ownerEmail: req.user.email,
      members: [{ email: req.user.email, role: "owner", addedAt: new Date() }],
      createdAt: new Date()
    };
    const result = await projectsCol.insertOne(doc);
    await logActivity(result.insertedId, req.user.email, "PROJECT_CREATED", { name, projectId });
    res.status(201).json({ _id: result.insertedId, projectId, name, myRole: "owner" });
  }));

  // Delete entire project (Owner only)
  app.delete("/api/projects/:projectId", requireUser, requireProjectAccess, requireMinRole("owner"), ah(async (req, res) => {
    await envsCol.deleteMany({ projectId: req.project._id });
    await logsCol.deleteMany({ projectId: req.project._id });
    await projectsCol.deleteOne({ _id: req.project._id });
    res.json({ success: true, message: `Deleted project ${req.project.name}` });
  }));

  // Invite Teammate with Role (Owner or Admin)
  app.post("/api/projects/:projectId/invite", requireUser, requireProjectAccess, requireMinRole("admin"), ah(async (req, res) => {
    const targetEmail = normEmail(req.body.email);
    const role = ASSIGNABLE_ROLES.includes(req.body.role) ? req.body.role : "editor";

    if (!EMAIL_RE.test(targetEmail)) return res.status(400).json({ error: "Provide a valid email to invite" });
    if (role === "admin" && req.memberRole !== "owner") {
      return res.status(403).json({ error: "Only the project owner can assign the admin role" });
    }

    const alreadyMember = req.project.members.some((m) => m.email === targetEmail);
    if (alreadyMember) {
      return res.status(409).json({ error: `${targetEmail} is already a member of this project` });
    }

    await projectsCol.updateOne(
      { _id: req.project._id },
      { $push: { members: { email: targetEmail, role, addedAt: new Date() } } }
    );
    await logActivity(req.project._id, req.user.email, "MEMBER_INVITED", { targetEmail, role });
    res.json({ success: true, message: `Invited ${targetEmail} as ${role}` });
  }));

  // Change Member Role (Owner or Admin)
  app.patch("/api/projects/:projectId/members", requireUser, requireProjectAccess, requireMinRole("admin"), ah(async (req, res) => {
    const targetEmail = normEmail(req.body.email);
    const newRole = req.body.role;

    if (!ASSIGNABLE_ROLES.includes(newRole)) {
      return res.status(400).json({ error: "Role must be admin, editor, or viewer" });
    }
    if (targetEmail === req.project.ownerEmail) {
      return res.status(400).json({ error: "Cannot change the project owner's role" });
    }

    const targetMember = req.project.members.find((m) => m.email === targetEmail);
    if (!targetMember) return res.status(404).json({ error: "Member not found in project" });

    // Admins cannot modify other admins or promote to admin
    if (req.memberRole !== "owner" && (targetMember.role === "admin" || newRole === "admin")) {
      return res.status(403).json({ error: "Only the project owner can manage admin roles" });
    }

    await projectsCol.updateOne(
      { _id: req.project._id, "members.email": targetEmail },
      { $set: { "members.$.role": newRole } }
    );
    await logActivity(req.project._id, req.user.email, "ROLE_UPDATED", {
      targetEmail,
      oldRole: targetMember.role,
      newRole
    });
    res.json({ success: true, message: `Updated ${targetEmail} to ${newRole}` });
  }));

  // Remove Member or Leave Project
  app.delete("/api/projects/:projectId/members", requireUser, requireProjectAccess, ah(async (req, res) => {
    const targetEmail = normEmail(req.body.email);
    if (!targetEmail) return res.status(400).json({ error: "Target email is required" });

    if (targetEmail === req.project.ownerEmail) {
      return res.status(400).json({ error: "The project owner cannot be removed" });
    }

    const isSelf = targetEmail === req.user.email;
    const targetMember = req.project.members.find((m) => m.email === targetEmail);
    if (!targetMember) return res.status(404).json({ error: "Member not found" });

    if (!isSelf) {
      if (ROLE_RANK[req.memberRole] < ROLE_RANK.admin) {
        return res.status(403).json({ error: "Only owners and admins can remove members" });
      }
      if (req.memberRole !== "owner" && targetMember.role === "admin") {
        return res.status(403).json({ error: "Only the project owner can remove an admin" });
      }
    }

    await projectsCol.updateOne(
      { _id: req.project._id },
      { $pull: { members: { email: targetEmail } } }
    );
    await logActivity(
      req.project._id,
      req.user.email,
      isSelf ? "MEMBER_LEFT" : "MEMBER_REMOVED",
      { targetEmail }
    );
    res.json({ success: true, message: isSelf ? `You left ${req.project.name}` : `Removed ${targetEmail}` });
  }));

  // Get Project Audit / Activity Logs
  app.get("/api/projects/:projectId/logs", requireUser, requireProjectAccess, ah(async (req, res) => {
    const logs = await logsCol
      .find({ projectId: req.project._id })
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();
    res.json(logs);
  }));

  // ----- Encrypted Variables -----
  app.get("/api/envs", requireUser, requireProjectAccess, requireMinRole("viewer"), ah(async (req, res) => {
    const environment = req.query.environment || "development";
    if (!ENVIRONMENTS.includes(environment)) return res.status(400).json({ error: "Unknown environment" });

    const records = await envsCol.find({ projectId: req.project._id, environment }).toArray();
    const list = records
      .map((r) => ({
        _id: r._id,
        key: decrypt(r.encryptedKey),
        value: decrypt(r.encryptedValue),
        environment: r.environment,
        updatedAt: r.updatedAt || r.createdAt,
        updatedBy: r.updatedBy || null
      }))
      .filter((r) => r.key !== null && r.value !== null)
      .sort((a, b) => a.key.localeCompare(b.key));

    if (req.query.format === "raw") {
      if (req.user.viaApiKey) {
        await logActivity(req.project._id, req.user.email, "CLI_PULLED", {
          environment,
          count: list.length
        });
      }
      res.type("text/plain").set("Cache-Control", "no-store");
      return res.send(list.map((i) => `${i.key}=${dotenvValue(i.value)}`).join("\n") + (list.length ? "\n" : ""));
    }
    res.set("Cache-Control", "no-store").json(list);
  }));

  // Create or Upsert Variable (Requires 'editor' or higher)
  app.post("/api/envs", requireUser, requireProjectAccess, requireMinRole("editor"), ah(async (req, res) => {
    const { environment = "development" } = req.body;
    const key = String(req.body.key || "").trim().toUpperCase();
    const value = req.body.value;

    if (!ENVIRONMENTS.includes(environment)) return res.status(400).json({ error: "Unknown environment" });
    if (!KEY_RE.test(key) || key.length > 128) {
      return res.status(400).json({ error: "Key must contain only A-Z, 0-9 and _, and not start with a digit" });
    }
    if (typeof value !== "string" || value.length > 10000) {
      return res.status(400).json({ error: "Value must be a string up to 10,000 characters" });
    }

    const now = new Date();
    const result = await envsCol.updateOne(
      { projectId: req.project._id, environment, keyHash: blindIndex(key) },
      {
        $set: {
          encryptedKey: encrypt(key),
          encryptedValue: encrypt(value),
          updatedAt: now,
          updatedBy: req.user.email
        },$setOnInsert: { createdAt: now }
      },
      { upsert: true }
    );

    await logActivity(
      req.project._id,
      req.user.email,
      result.upsertedCount ? "VAR_CREATED" : "VAR_UPDATED",
      { key, environment }
    );
    res.json({ success: true });
  }));

  // Bulk Import .env (Requires 'editor' or higher)
  app.post("/api/envs/bulk", requireUser, requireProjectAccess, requireMinRole("editor"), ah(async (req, res) => {
    const { environment = "development", rawEnv = "" } = req.body;
    if (!ENVIRONMENTS.includes(environment)) return res.status(400).json({ error: "Unknown environment" });

    const pairs = parseDotenv(rawEnv);
    if (!pairs.length) {
      return res.status(400).json({ error: "No valid KEY=VALUE pairs found to import" });
    }

    const now = new Date();
    const ops = pairs.map(({ key, value }) => ({
      updateOne: {
        filter: { projectId: req.project._id, environment, keyHash: blindIndex(key) },
        update: {
          $set: {
            encryptedKey: encrypt(key),
            encryptedValue: encrypt(value),
            updatedAt: now,
            updatedBy: req.user.email
          },$setOnInsert: { createdAt: now }
        },
        upsert: true
      }
    }));

    await envsCol.bulkWrite(ops);
    await logActivity(req.project._id, req.user.email, "BULK_IMPORT", {
      environment,
      count: pairs.length
    });
    res.json({ success: true, count: pairs.length });
  }));

  // Inline Edit Variable Value (Requires 'editor' or higher)
  app.put("/api/envs/:id", requireUser, requireProjectAccess, requireMinRole("editor"), ah(async (req, res) => {
    const { id } = req.params;
    const { value, key } = req.body;

    if (!ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid variable id" });
    if (typeof value !== "string" || value.length > 10000) {
      return res.status(400).json({ error: "Value must be a string up to 10,000 characters" });
    }

    const existingDoc = await envsCol.findOne({ _id: new ObjectId(id), projectId: req.project._id });
    if (!existingDoc) return res.status(404).json({ error: "Variable not found" });

    const updateFields = {
      encryptedValue: encrypt(value),
      updatedAt: new Date(),
      updatedBy: req.user.email
    };

    let keyName = decrypt(existingDoc.encryptedKey) || "UNKNOWN";
    if (key !== undefined) {
      const cleanKey = String(key).trim().toUpperCase();
      if (!KEY_RE.test(cleanKey) || cleanKey.length > 128) {
        return res.status(400).json({ error: "Key must contain only A-Z, 0-9 and _, and not start with a digit" });
      }
      updateFields.encryptedKey = encrypt(cleanKey);
      updateFields.keyHash = blindIndex(cleanKey);
      keyName = cleanKey;
    }

    try {
      await envsCol.updateOne({ _id: existingDoc._id }, { $set: updateFields });
      await logActivity(req.project._id, req.user.email, "VAR_UPDATED", {
        key: keyName,
        environment: existingDoc.environment
      });
      res.json({ success: true });
    } catch (err) {
      if (err.code === 11000) return res.status(409).json({ error: "A variable with that key already exists" });
      throw err;
    }
  }));

  // Delete Variable (Requires 'editor' or higher)
  app.delete("/api/envs", requireUser, requireProjectAccess, requireMinRole("editor"), ah(async (req, res) => {
    const { id } = req.body;
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid id" });
    const existingDoc = await envsCol.findOne({ _id: new ObjectId(id), projectId: req.project._id });
    if (!existingDoc) return res.status(404).json({ error: "Variable not found" });

    await envsCol.deleteOne({ _id: existingDoc._id });
    await logActivity(req.project._id, req.user.email, "VAR_DELETED", {
      key: decrypt(existingDoc.encryptedKey) || "REDACTED",
      environment: existingDoc.environment
    });
    res.json({ success: true });
  }));

  // ----- Fallbacks -----
  app.use("/api", (req, res) => res.status(404).json({ error: "API route not found" }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  });
}

// ---------- Startup ----------
async function start() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(DB_NAME);

  const existing = await db.listCollections({ name: "variables" }).toArray();
  if (existing.length) await db.command({ collMod: "variables", validator: {}, validationLevel: "off" });
  else await db.createCollection("variables");

  usersCol = db.collection("users");
  projectsCol = db.collection("projects");
  envsCol = db.collection("variables");
  logsCol = db.collection("audit_logs");

  await usersCol.createIndex({ email: 1 }, { unique: true });
  await usersCol.createIndex(
    { apiKeyHash: 1 },
    { unique: true, partialFilterExpression: { apiKeyHash: { $exists: true } } }
  );
  await projectsCol.createIndex({ "members.email": 1 });
  await projectsCol.createIndex(
    { projectId: 1 },
    { unique: true, partialFilterExpression: { projectId: { $exists: true } } }
  );
  await envsCol.createIndex({ projectId: 1, environment: 1 });
  await envsCol.createIndex(
    { projectId: 1, environment: 1, keyHash: 1 },
    { unique: true, partialFilterExpression: { keyHash: { $exists: true } } }
  );
  await logsCol.createIndex({ projectId: 1, createdAt: -1 });

  registerRoutes();
  const server = app.listen(PORT, () => console.log(`⚡ EnvHub running on http://localhost:${PORT}`));

  const shutdown = async () => {
    server.close();
    await client.close();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

start().catch((err) => {
  console.error("Failed to start:", err);
  process.exit(1);
});
