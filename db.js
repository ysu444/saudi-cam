const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'chat.db');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function initDB() {
  const db = new Database(DB_PATH);

  // Enable WAL mode for better concurrent performance
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');

  // Users table
  db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT,
    role TEXT DEFAULT 'guest',
    badge TEXT DEFAULT '',
    permissions TEXT DEFAULT '[]',
    invite_code TEXT DEFAULT '',
    chat_muted INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at INTEGER,
    last_seen INTEGER
  )`);

  // Rooms table
  db.exec(`CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    marquee TEXT DEFAULT '',
    max_users INTEGER DEFAULT 0,
    is_default INTEGER DEFAULT 0,
    password TEXT DEFAULT '',
    fixed_text TEXT DEFAULT '',
    bg_image TEXT DEFAULT '',
    allowed_roles TEXT DEFAULT 'all',
    perms TEXT DEFAULT '{"micMode":"all","camMode":"all","chatMode":"all"}',
    created_at INTEGER
  )`);

  // Messages table (chat history)
  db.exec(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    username TEXT NOT NULL,
    text TEXT NOT NULL,
    type TEXT DEFAULT 'chat',
    created_at INTEGER,
    FOREIGN KEY (room_id) REFERENCES rooms(id)
  )`);

  // Bans table
  db.exec(`CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    reason TEXT DEFAULT '',
    banned_by TEXT DEFAULT '',
    duration INTEGER,
    created_at INTEGER
  )`);

  // Mod accounts table
  db.exec(`CREATE TABLE IF NOT EXISTS mod_accounts (
    code TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    pin_hash TEXT NOT NULL,
    role TEXT DEFAULT 'mod',
    badge TEXT DEFAULT '',
    permissions TEXT DEFAULT '[]',
    enabled INTEGER DEFAULT 1,
    created_at INTEGER
  )`);

  // Invite codes table
  db.exec(`CREATE TABLE IF NOT EXISTS invite_codes (
    code TEXT PRIMARY KEY,
    created_by TEXT DEFAULT 'admin',
    role TEXT DEFAULT 'member',
    max_uses INTEGER DEFAULT 0,
    uses INTEGER DEFAULT 0,
    expires_at INTEGER,
    created_at INTEGER
  )`);

  // Logs table
  db.exec(`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    actor TEXT DEFAULT '',
    target TEXT DEFAULT '',
    details TEXT DEFAULT '',
    created_at INTEGER
  )`);

  // Settings table (key-value)
  db.exec(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )`);

  // Create indexes for performance
  db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, created_at)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(username)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_logs_action ON logs(action, created_at)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_bans_username ON bans(username)`);

  // Insert default room if not exists
  const defaultRoom = db.prepare('SELECT id FROM rooms WHERE id = ?').get('general');
  if (!defaultRoom) {
    db.prepare('INSERT INTO rooms (id, name, marquee, is_default, created_at, perms) VALUES (?, ?, ?, 1, ?, ?)').run(
      'general', 'الغرفة العامة', 'مرحباً بكم في الغرفة العامة', Date.now(),
      '{"micMode":"all","camMode":"all","chatMode":"all"}'
    );
  }

  // Insert default settings
  const defaults = {
    admin_password: sha256('admin123'),
    theme: JSON.stringify({primary:'#3a76f0',bg:'#1a1a2e',sidebar:'#141e30',accent:'#e0a93a',text:'#e0e0e0',headerGrad:['#2a1a3e','#1a2a4e'],marqueeColor:'#ffcc00',font:'Segoe UI, Tahoma, Arial, sans-serif'}),
    guest_allowed: 'true',
    require_password: 'false',
    require_invite_code: 'false',
    features: JSON.stringify({camera:true,microphone:true,privateMessages:true,marquee:true}),
    word_filter: '[]'
  };

  const insertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
  for (const [k, v] of Object.entries(defaults)) {
    insertSetting.run(k, v);
  }

  // Migrate from data.json if exists
  const jsonPath = path.join(__dirname, 'data.json');
  if (fs.existsSync(jsonPath)) {
    try {
      const data = JSON.parse(fs.readFileSync(jsonPath, 'utf-8'));
      console.log('Migrating from data.json...');

      // Migrate users
      const insertUser = db.prepare('INSERT OR IGNORE INTO users (username, display_name, password_hash, role, badge, permissions, invite_code, enabled, created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
      for (const [key, u] of Object.entries(data.users || {})) {
        insertUser.run(key, u.displayName, u.passwordHash || null, u.role, u.badge || '', JSON.stringify(u.permissions || []), u.inviteCode || '', u.enabled !== false ? 1 : 0, u.registeredAt || Date.now(), u.lastSeen || Date.now());
      }

      // Migrate rooms
      const insertRoom = db.prepare('INSERT OR REPLACE INTO rooms (id, name, marquee, max_users, is_default, password, fixed_text, bg_image, allowed_roles, perms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
      for (const [id, r] of Object.entries(data.rooms || {})) {
        insertRoom.run(id, r.name, r.marquee || '', r.maxUsers || 0, r.isDefault ? 1 : 0, r.password || '', r.fixedText || '', r.bgImage || '', r.allowedRoles || 'all', JSON.stringify(r.perms || {}), r.createdAt || Date.now());
      }

      // Migrate mod accounts
      const insertMod = db.prepare('INSERT OR IGNORE INTO mod_accounts (code, display_name, pin_hash, role, badge, permissions, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
      for (const [code, m] of Object.entries(data.modAccounts || {})) {
        insertMod.run(code, m.displayName, m.pinHash, m.role, m.badge || '', JSON.stringify(m.permissions || []), m.enabled !== false ? 1 : 0, m.createdAt || Date.now());
      }

      // Migrate invite codes
      const insertInvite = db.prepare('INSERT OR IGNORE INTO invite_codes (code, created_by, role, max_uses, uses, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)');
      for (const [code, c] of Object.entries(data.inviteCodes || {})) {
        insertInvite.run(code, c.createdBy || 'admin', c.role, c.maxUses || 0, c.uses || 0, c.expiresAt || null, c.createdAt || Date.now());
      }

      // Migrate bans
      const insertBan = db.prepare('INSERT INTO bans (username, reason, banned_by, duration, created_at) VALUES (?, ?, ?, ?, ?)');
      if (Array.isArray(data.bans)) {
        for (const b of data.bans) {
          insertBan.run(b.username, b.reason || '', b.by || '', b.duration || null, b.time || Date.now());
        }
      }

      // Migrate settings
      if (data.adminPassword) db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(data.adminPassword, 'admin_password');
      if (data.theme) db.prepare('UPDATE settings SET value = ? WHERE key = ?').run(JSON.stringify(data.theme), 'theme');

      // Rename old file
      fs.renameSync(jsonPath, jsonPath + '.bak');
      console.log('Migration complete! data.json renamed to data.json.bak');
    } catch(e) {
      console.error('Migration error:', e.message);
    }
  }

  console.log('Database ready: ' + DB_PATH);
  return db;
}

module.exports = { initDB, DB_PATH };
