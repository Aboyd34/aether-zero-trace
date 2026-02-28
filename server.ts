import express, { Request, Response, NextFunction } from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import winston from "winston";
import Joi from "joi";
import crypto from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- Logging Setup ---
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

// Switch to in-memory database for 100% privacy (no data persists on disk)
const db = new Database(":memory:");

// Initialize "Ephemeral Storage"
db.exec(`
  CREATE TABLE IF NOT EXISTS storage (
    key TEXT PRIMARY KEY,
    value TEXT
  );
  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    topic TEXT,
    sender_pubkey TEXT,
    payload TEXT,
    signature TEXT,
    timestamp INTEGER
  );
  CREATE TABLE IF NOT EXISTS peers (
    pubkey TEXT PRIMARY KEY,
    last_seen INTEGER,
    status TEXT,
    connection_type TEXT,
    metadata TEXT
  );
  CREATE TABLE IF NOT EXISTS communities (
    id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    owner_pubkey TEXT,
    created_at INTEGER
  );
`);

// --- Validation Schemas ---
const storageSchema = Joi.object({
  key: Joi.string().max(256).required(),
  value: Joi.any().required(),
});

const communitySchema = Joi.object({
  id: Joi.string().max(128).required(),
  name: Joi.string().max(128).required(),
  description: Joi.string().max(512).allow(""),
  owner_pubkey: Joi.string().max(512).required(),
});

const peerSchema = Joi.object({
  pubkey: Joi.string().max(512).required(),
  lastSeen: Joi.number().integer().min(0),
  status: Joi.string().valid("online", "offline", "away"),
  connectionType: Joi.string().valid("direct", "relay"),
  metadata: Joi.object().max(20),
});

const messageSchema = Joi.object({
  id: Joi.string().max(128).required(),
  topic: Joi.string().max(128).required(),
  sender: Joi.string().max(512).required(),
  content: Joi.string().max(10000).required(),
  signature: Joi.string().max(1024).required(),
  timestamp: Joi.number().integer().required(),
  type: Joi.string().max(32),
});

// --- Helper Functions ---
function verifySignature(payload: string, signatureB64: string, publicKeyB64: string): boolean {
  try {
    const publicKey = `-----BEGIN PUBLIC KEY-----\n${publicKeyB64}\n-----END PUBLIC KEY-----`;
    const signature = Buffer.from(signatureB64, "base64");
    return crypto.verify(
      "sha256",
      Buffer.from(payload),
      {
        key: publicKey,
        format: "pem",
        type: "spki",
      },
      signature
    );
  } catch (e) {
    logger.error("Signature verification failed", { error: e });
    return false;
  }
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // --- Security Middleware ---
  app.use(helmet());
  app.use(cors({
    origin: process.env.APP_URL || true,
    credentials: true,
  }));
  app.use(express.json({ limit: "50kb" }));

  // --- Request Logging ---
  app.use((req, res, next) => {
    const start = Date.now();
    res.on("finish", () => {
      const duration = Date.now() - start;
      logger.info(`${req.method} ${req.path}`, {
        status: res.statusCode,
        duration: `${duration}ms`,
        ip: req.ip,
      });
    });
    next();
  });

  // --- Rate Limiting ---
  const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 200, // limit each IP to 200 requests per windowMs
    message: { error: "Too many requests, please try again later." },
  });
  app.use("/api/", apiLimiter);

  // --- Health Check ---
  app.get("/api/health", (req, res) => {
    res.json({
      status: "ok",
      uptime: process.uptime(),
      timestamp: Date.now(),
      memory: process.memoryUsage(),
    });
  });

  // --- Local Storage API ---
  app.get("/api/storage/:key", (req, res) => {
    try {
      const row = db.prepare("SELECT value FROM storage WHERE key = ?").get(req.params.key) as { value: string } | undefined;
      res.json({ value: row ? JSON.parse(row.value) : null });
    } catch (err) {
      logger.error("Storage fetch error", { key: req.params.key, error: err });
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/storage", (req, res) => {
    const { error, value } = storageSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    try {
      db.prepare("INSERT OR REPLACE INTO storage (key, value) VALUES (?, ?)").run(value.key, JSON.stringify(value.value));
      res.status(201).json({ status: "ok" });
    } catch (err) {
      logger.error("Storage save error", { error: err });
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // --- Community CRUD ---
  app.get("/api/communities", (req, res) => {
    try {
      const rows = db.prepare("SELECT * FROM communities").all();
      res.json(rows);
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/communities", (req, res) => {
    const { error, value } = communitySchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    try {
      db.prepare(`
        INSERT OR REPLACE INTO communities (id, name, description, owner_pubkey, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(value.id, value.name, value.description, value.owner_pubkey, Date.now());
      res.status(201).json({ status: "ok" });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.delete("/api/communities/:id", (req, res) => {
    try {
      const result = db.prepare("DELETE FROM communities WHERE id = ?").run(req.params.id);
      if (result.changes === 0) return res.status(404).json({ error: "Community not found" });
      res.json({ status: "ok" });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // --- Peer Management ---
  app.get("/api/peers", (req, res) => {
    try {
      const rows = db.prepare("SELECT * FROM peers ORDER BY last_seen DESC").all() as any[];
      const peers = rows.map(r => ({
        pubkey: r.pubkey,
        lastSeen: r.last_seen,
        status: r.status || "offline",
        connectionType: r.connection_type || "relay",
        metadata: JSON.parse(r.metadata || "{}")
      }));
      res.json(peers);
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/peers", (req, res) => {
    const { error, value } = peerSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    try {
      db.prepare(`
        INSERT OR REPLACE INTO peers (pubkey, last_seen, status, connection_type, metadata)
        VALUES (?, ?, ?, ?, ?)
      `).run(
        value.pubkey, 
        value.lastSeen || Date.now(), 
        value.status || "offline", 
        value.connectionType || "relay", 
        JSON.stringify(value.metadata || {})
      );
      res.status(201).json({ status: "ok" });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.delete("/api/peers/:pubkey", (req, res) => {
    try {
      db.prepare("DELETE FROM peers WHERE pubkey = ?").run(req.params.pubkey);
      res.json({ status: "ok" });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // --- Relay API ---
  app.post("/api/relay/broadcast", (req, res) => {
    const { error, value } = messageSchema.validate(req.body);
    if (error) return res.status(400).json({ error: error.details[0].message });

    // Verify Signature
    if (!verifySignature(value.content, value.signature, value.sender)) {
      logger.warn("Invalid signature on broadcast", { sender: value.sender });
      return res.status(401).json({ error: "Invalid cryptographic signature" });
    }

    try {
      db.prepare(`
        INSERT INTO messages (id, topic, sender_pubkey, payload, signature, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(value.id, value.topic, value.sender, value.content, value.signature, value.timestamp);
      res.status(201).json({ status: "ok" });
    } catch (e) {
      res.status(409).json({ error: "Duplicate message" });
    }
  });

  app.get("/api/relay/messages/:topic", (req, res) => {
    try {
      const rows = db.prepare("SELECT * FROM messages WHERE topic = ? ORDER BY timestamp DESC LIMIT 100").all(req.params.topic) as any[];
      const messages = rows.map(r => ({
        id: r.id,
        topic: r.topic,
        sender: r.sender_pubkey,
        content: r.payload,
        signature: r.signature,
        timestamp: r.timestamp,
        type: "post"
      }));
      res.json(messages);
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/relay/feed", (req, res) => {
    try {
      const rows = db.prepare("SELECT * FROM messages ORDER BY timestamp DESC LIMIT 200").all() as any[];
      const messages = rows.map(r => ({
        id: r.id,
        topic: r.topic,
        sender: r.sender_pubkey,
        content: r.payload,
        signature: r.signature,
        timestamp: r.timestamp,
        type: "post"
      }));
      res.json(messages);
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // --- Maintenance API ---
  app.post("/api/storage/maintenance/retention", (req, res) => {
    const { maxAgeMs, maxCount } = req.body;
    
    try {
      if (maxAgeMs) {
        const cutoff = Date.now() - maxAgeMs;
        db.prepare("DELETE FROM messages WHERE timestamp < ?").run(cutoff);
      }

      if (maxCount) {
        db.prepare(`
          DELETE FROM messages 
          WHERE id NOT IN (
            SELECT id FROM messages 
            ORDER BY timestamp DESC 
            LIMIT ?
          )
        `).run(maxCount);
      }

      res.json({ status: "ok" });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.post("/api/storage/maintenance/purge", (req, res) => {
    try {
      db.prepare("DELETE FROM messages").run();
      db.prepare("DELETE FROM storage").run();
      db.prepare("DELETE FROM communities").run();
      db.prepare("DELETE FROM peers").run();
      res.json({ status: "ok" });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  app.get("/api/storage/dump", (req, res) => {
    try {
      const messages = db.prepare("SELECT * FROM messages").all();
      const storage = db.prepare("SELECT * FROM storage").all();
      const communities = db.prepare("SELECT * FROM communities").all();
      const peers = db.prepare("SELECT * FROM peers").all();
      res.json({ messages, storage, communities, peers });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // --- Automatic Cleanup Task ---
  setInterval(() => {
    const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
    try {
      const peerResult = db.prepare("DELETE FROM peers WHERE last_seen < ?").run(oneDayAgo);
      const msgResult = db.prepare("DELETE FROM messages WHERE timestamp < ?").run(oneDayAgo);
      if (peerResult.changes > 0 || msgResult.changes > 0) {
        logger.info("Automatic cleanup performed", { 
          peersRemoved: peerResult.changes, 
          messagesRemoved: msgResult.changes 
        });
      }
    } catch (err) {
      logger.error("Cleanup task failed", { error: err });
    }
  }, 60 * 60 * 1000); // Run hourly

  // --- Error Handling Middleware ---
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    logger.error("Unhandled error", { error: err.message, stack: err.stack });
    res.status(500).json({ 
      error: "Internal server error",
      details: process.env.NODE_ENV === "development" ? err.message : undefined
    });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    logger.info(`Aether Node running on http://localhost:${PORT}`);
  });
}

startServer();
