import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
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

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // --- Local Storage API (Simulating Device Disk) ---
  app.get("/api/storage/:key", (req, res) => {
    const row = db.prepare("SELECT value FROM storage WHERE key = ?").get(req.params.key) as { value: string } | undefined;
    res.json({ value: row ? JSON.parse(row.value) : null });
  });

  app.post("/api/storage", (req, res) => {
    const { key, value } = req.body;
    db.prepare("INSERT OR REPLACE INTO storage (key, value) VALUES (?, ?)").run(key, JSON.stringify(value));
    res.json({ status: "ok" });
  });

  // --- Community CRUD ---
  app.get("/api/communities", (req, res) => {
    const rows = db.prepare("SELECT * FROM communities").all();
    res.json(rows);
  });

  app.post("/api/communities", (req, res) => {
    const { id, name, description, owner_pubkey } = req.body;
    db.prepare(`
      INSERT OR REPLACE INTO communities (id, name, description, owner_pubkey, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, name, description, owner_pubkey, Date.now());
    res.json({ status: "ok" });
  });

  app.delete("/api/communities/:id", (req, res) => {
    db.prepare("DELETE FROM communities WHERE id = ?").run(req.params.id);
    res.json({ status: "ok" });
  });

  // --- Peer Management ---
  app.get("/api/peers", (req, res) => {
    const rows = db.prepare("SELECT * FROM peers ORDER BY last_seen DESC").all() as any[];
    const peers = rows.map(r => ({
      pubkey: r.pubkey,
      lastSeen: r.last_seen,
      status: r.status || 'offline',
      connectionType: r.connection_type || 'relay',
      metadata: JSON.parse(r.metadata || "{}")
    }));
    res.json(peers);
  });

  app.post("/api/peers", (req, res) => {
    const { pubkey, lastSeen, status, connectionType, metadata } = req.body;
    db.prepare(`
      INSERT OR REPLACE INTO peers (pubkey, last_seen, status, connection_type, metadata)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      pubkey, 
      lastSeen || Date.now(), 
      status || 'offline', 
      connectionType || 'relay', 
      JSON.stringify(metadata || {})
    );
    res.json({ status: "ok" });
  });

  app.delete("/api/peers/:pubkey", (req, res) => {
    db.prepare("DELETE FROM peers WHERE pubkey = ?").run(req.params.pubkey);
    res.json({ status: "ok" });
  });

  // --- Relay API (Simulating P2P Network) ---
  app.post("/api/relay/broadcast", (req, res) => {
    const { id, topic, sender, content, signature, timestamp, type } = req.body;
    try {
      db.prepare(`
        INSERT INTO messages (id, topic, sender_pubkey, payload, signature, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(id, topic, sender, content, signature, timestamp);
      res.json({ status: "ok" });
    } catch (e) {
      res.status(400).json({ error: "Duplicate or invalid message" });
    }
  });

  // --- Retention & Purge ---
  app.post("/api/storage/maintenance/retention", (req, res) => {
    const { maxAgeMs, maxCount } = req.body;
    
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
  });

  app.post("/api/storage/maintenance/purge", (req, res) => {
    db.prepare("DELETE FROM messages").run();
    db.prepare("DELETE FROM storage").run();
    db.prepare("DELETE FROM communities").run();
    db.prepare("DELETE FROM peers").run();
    res.json({ status: "ok" });
  });

  app.get("/api/storage/dump", (req, res) => {
    const messages = db.prepare("SELECT * FROM messages").all();
    const storage = db.prepare("SELECT * FROM storage").all();
    const communities = db.prepare("SELECT * FROM communities").all();
    const peers = db.prepare("SELECT * FROM peers").all();
    res.json({ messages, storage, communities, peers });
  });

  app.get("/api/relay/messages/:topic", (req, res) => {
    const rows = db.prepare("SELECT * FROM messages WHERE topic = ? ORDER BY timestamp DESC LIMIT 100").all(req.params.topic) as any[];
    const messages = rows.map(r => ({
      id: r.id,
      topic: r.topic,
      sender: r.sender_pubkey,
      content: r.payload,
      signature: r.signature,
      timestamp: r.timestamp,
      type: 'post' // Default to post for now
    }));
    res.json(messages);
  });

  app.get("/api/relay/feed", (req, res) => {
    const rows = db.prepare("SELECT * FROM messages ORDER BY timestamp DESC LIMIT 200").all() as any[];
    const messages = rows.map(r => ({
      id: r.id,
      topic: r.topic,
      sender: r.sender_pubkey,
      content: r.payload,
      signature: r.signature,
      timestamp: r.timestamp,
      type: 'post'
    }));
    res.json(messages);
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
    console.log(`Aether Node running on http://localhost:${PORT}`);
  });
}

startServer();
