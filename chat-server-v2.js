
// Word Filter
async function getFilteredWords() {
  const row = await getSetting('filtered_words');
  if (!row) return [];
  try { return JSON.parse(row); } catch(e) { return []; }
}

function checkFilter(text, words) {
  if (!words.length) return false;
  const lower = text.toLowerCase();
  for (const w of words) {
    if (w && lower.includes(w.toLowerCase())) return w;
  }
  return false;
}

// XSS Protection - sanitize all user input
function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
}
/**
 * Saudi Cam Server v2
 *
 * A production-ready chat server using Node.js HTTP, PostgreSQL, and Redis.
 * Supports guest and mod logins, room-based chat with long polling,
 * admin panel, bans, signals (mic/cam), and static file serving.
 *
 * Dependencies: pg, ioredis (plus built-in http, crypto, fs, path, os)
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const bcrypt = (() => { try { return require('bcryptjs'); } catch(e) { return null; } })();
const fs = require('fs');
const path = require('path');
const os = require('os');
const { Pool } = require('pg');
const Redis = require('ioredis');
const { Server: SocketServer } = require('socket.io');

// ---------------------------------------------------------------------------
//  Configuration
// ---------------------------------------------------------------------------

const PORT = 8089;
const LONG_POLL_TIMEOUT = 25000; // 25 seconds
const SESSION_TTL = 3600;      // 1 hour in seconds
const ADMIN_PASSWORD_DEFAULT_HASH =
  '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9';

const STATIC_DIR = __dirname;

// ---------------------------------------------------------------------------
//  PostgreSQL pool
// ---------------------------------------------------------------------------

const pgPool = new Pool({
  host: 'localhost',
  user: 'chatadmin',
  password: process.env.DB_PASSWORD || 'chatpass123',
  database: 'saudicam',
  max: 20,
  idleTimeoutMillis: 30000,
});

// ---------------------------------------------------------------------------
//  Redis clients
//  - redis       : general commands (GET, SET, SADD, etc.)
//  - redisSub    : dedicated subscriber (cannot issue normal commands once subscribed)
// ---------------------------------------------------------------------------

const redis = new Redis({ host: '127.0.0.1', port: 6379, lazyConnect: true });
const redisSub = new Redis({ host: '127.0.0.1', port: 6379, lazyConnect: true });

// ---------------------------------------------------------------------------
//  Utility helpers
// ---------------------------------------------------------------------------

/** Timestamped console log */
function log(msg) {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${msg}`);
}

/** SHA-256 hex digest of a string */
// Secure password hashing - bcrypt with fallback to sha256
async function secureHash(str) {
  if (bcrypt) return await bcrypt.hash(str, 10);
  return sha256(str);
}
async function secureCompare(plain, hash) {
  if (bcrypt && hash.startsWith('$2')) return await bcrypt.compare(plain, hash);
  return sha256(plain) === hash;
}
// Rate limiting
const _rateLimits = {};
function rateLimit(key, maxReqs, windowSec) {
  const now = Date.now();
  if (!_rateLimits[key]) _rateLimits[key] = [];
  _rateLimits[key] = _rateLimits[key].filter(t => now - t < windowSec * 1000);
  if (_rateLimits[key].length >= maxReqs) return false;
  _rateLimits[key].push(now);
  return true;
}
// Clean rate limits every 5 min
setInterval(() => {
  const now = Date.now();
  for (const k in _rateLimits) {
    _rateLimits[k] = _rateLimits[k].filter(t => now - t < 300000);
    if (!_rateLimits[k].length) delete _rateLimits[k];
  }
}, 300000);

function sha256(str) {
  return crypto.createHash('sha256').update(str).digest('hex');
}

/** Generate a random hex id (32 hex chars = 16 bytes) */
function genId() {
  return crypto.randomBytes(16).toString('hex');
}

/** Parse JSON body from an IncomingMessage */
function parseBody(req) {
  const MAX_BODY = 1024 * 512; // 512KB max
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; if (data.length > MAX_BODY) { req.destroy(); reject(new Error('Body too large')); } });
    req.on('end', () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

/** Send a JSON response with CORS headers */
function sendJson(res, statusCode, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
  });
  res.end(body);
}

/** Attach CORS headers (used for OPTIONS pre-flight and static responses) */
function setCors(res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

/** Map file extension to MIME type */
function mimeType(ext) {
  const map = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
    '.mp3': 'audio/mpeg',
    '.mp4': 'video/mp4',
    '.webm': 'video/webm',
    '.m3u8': 'application/vnd.apple.mpegurl',
    '.ts': 'video/mp2t',
  };
  return map[ext] || 'application/octet-stream';
}

// ---------------------------------------------------------------------------
//  Redis session helpers
// ---------------------------------------------------------------------------

/** Create a session in Redis. Returns the session id. */
async function createSession(username, role, badge, permissions, roomId, displayName) {
  const sessionId = genId();
  const data = JSON.stringify({
    username,
    displayName: displayName || username,
    role,
    badge: badge || '',
    permissions: permissions || [],
    roomId: roomId || null,
  });
  await redis.set(`session:${sessionId}`, typeof data === 'string' ? data : JSON.stringify(data), 'EX', SESSION_TTL);
  return sessionId;
}

/** Retrieve a session. Returns parsed object or null. */
async function getSession(sessionId) {
  if (!sessionId) return null;
  const raw = await redis.get(`session:${sessionId}`);
  if (!raw) return null;
  const sess = JSON.parse(raw);
  sess.sessionId = sessionId;
  // Refresh TTL on access
  await redis.expire(`session:${sessionId}`, SESSION_TTL);
  return sess;
}

/** Update fields on a session */
async function updateSession(sessionId, fields) {
  const sess = await getSession(sessionId);
  if (!sess) return null;
  Object.assign(sess, fields);
  delete sess.sessionId; // don't store the id inside the value
  await redis.set(`session:${sessionId}`, JSON.stringify(sess), 'EX', SESSION_TTL);
  return sess;
}

/** Destroy a session */
async function destroySession(sessionId) {
  await redis.del(`session:${sessionId}`);
}

// ---------------------------------------------------------------------------
//  Redis online-user tracking  (sets per room)
// ---------------------------------------------------------------------------

async function addOnlineUser(roomId, username, role, badge) {
  if (roomId) await redis.sadd('room:' + roomId + ':online', username);
  if (role) await redis.set('user:role:' + username, JSON.stringify({role: role || 'guest', badge: badge || ''}), 'EX', 3600);
}

async function removeOnlineUser(roomId, username) {
  if (roomId) await redis.srem('room:' + roomId + ':online', username);
  await redis.del('user:role:' + username);
}

async function getOnlineUsers(roomId) {
  const names = await redis.smembers('room:' + roomId + ':online');
  if (!names.length) return [];
  const cams = await redis.smembers('room:' + roomId + ':cams');
  const mics = await redis.smembers('room:' + roomId + ':mics');
  const pipeline = redis.pipeline();
  names.forEach(n => { pipeline.get('stream:cam:' + n); pipeline.get('stream:mic:' + n); });
  const streams = await pipeline.exec();
  const users = [];
  for (let i = 0; i < names.length; i++) {
    const name = names[i];
    const camStream = streams[i*2] ? streams[i*2][1] : null;
    const micStream = streams[i*2+1] ? streams[i*2+1][1] : null;
    // Get role from session cache or default
    const sessData = await redis.get('user:role:' + name);
    const info = sessData ? JSON.parse(sessData) : {role:'guest',badge:''};
    users.push({
      name,
      role: info.role || 'guest',
      badge: info.badge || '',
      cam: cams.includes(name),
      mic: mics.includes(name),
      camStream, micStream
    });
  }
  return users;
}

async function getOnlineCount(roomId) {
  return redis.scard('room:' + roomId + ':online');
}

/** Remove user from ALL room online sets (used on logout / kick) */
async function removeFromAllRooms(username) {
  const rooms = await pgPool.query('SELECT id FROM rooms');
  for (const r of rooms.rows) {
    await redis.srem('room:' + r.id + ':online', username);
    await redis.srem('room:' + r.id + ':cams', username);
    await redis.srem('room:' + r.id + ':mics', username);
  }
  await redis.del('stream:cam:' + username);
  await redis.del('stream:mic:' + username);
  await redis.del('user:role:' + username);
}

// ---------------------------------------------------------------------------
//  Redis pub/sub message broadcasting
// ---------------------------------------------------------------------------

// In-memory map: roomId -> Set of {resolve, timer} waiting poll clients
const pollWaiters = new Map();

/** Initialise subscriber – called once at startup */
function initPubSub() {
  redisSub.on('message', (channel, message) => {
    // channel = "room:<roomId>"
    const roomId = channel.replace('room:', '');
    const waiters = pollWaiters.get(roomId);
    if (waiters && waiters.size > 0) {
      const parsed = JSON.parse(message);
      for (const w of waiters) {
        clearTimeout(w.timer);
        w.resolve([parsed]);
      }
      waiters.clear();
    }
  });
}

/** Subscribe to a room channel (idempotent at Redis level) */
async function subscribeRoom(roomId) {
  await redisSub.subscribe(`room:${roomId}`);
}

/** Publish a message object to a room channel via Socket.IO */
async function publishToRoom(roomId, msgObj) {
  if (io) {
    io.to("room:" + roomId).emit("room-message", msgObj);
  }
}



// ---------------------------------------------------------------------------
//  Mic multi-speaker state management (in-memory, per room)
// ---------------------------------------------------------------------------

const roomMicState = new Map();
let io;
const userSockets = new Map(); // roomId -> { activeSpeakers: Map, queue: [] }

function getMicState(roomId) {
  if (!roomMicState.has(roomId)) {
    roomMicState.set(roomId, {
      activeSpeakers: new Map(), // sessionId -> { username, streamName, startedAt, warningTimer, timeoutTimer }
      queue: [] // [{ sessionId, username, requestedAt }]
    });
  }
  return roomMicState.get(roomId);
}

/** Get room mic settings from DB */
async function getRoomMicSettings(roomId) {
  const r = await pgPool.query('SELECT max_speakers, mic_queue_mode, mic_auto_release, mic_mode FROM rooms WHERE id = $1', [roomId]);
  if (!r.rows.length) return { maxSpeakers: 1, micQueueMode: 'fifo', micAutoRelease: 0, micMode: 'all' };
  const row = r.rows[0];
  return {
    maxSpeakers: row.max_speakers || 1,
    micQueueMode: row.mic_queue_mode || 'fifo',
    micAutoRelease: row.mic_auto_release || 0,
    micMode: row.mic_mode || 'all'
  };
}

/** Check if user role is allowed to speak based on micMode */
function canSpeak(role, micMode) {
  if (micMode === 'none') return false;
  if (micMode === 'all') return true;
  if (micMode === 'mods') return ['mod', 'admin', 'owner'].includes(role);
  if (micMode === 'admin') return ['admin', 'owner'].includes(role);
  return false;
}

/** Start auto-release timer for a speaker */
function startMicTimer(roomId, sessionId, minutes) {
  if (!minutes || minutes <= 0) return;
  const state = getMicState(roomId);
  const speaker = state.activeSpeakers.get(sessionId);
  if (!speaker) return;

  const ms = minutes * 60000;
  const warningMs = Math.max(0, ms - 30000);

  // Warning 30s before
  speaker.warningTimer = setTimeout(async () => {
    try {
      // Send warning to the speaker via their room
      await publishToRoom(roomId, {
        type: 'mic-timeout-warning',
        target: speaker.username,
        secondsLeft: 30,
        ts: Date.now()
      });
    } catch(e) { log('Mic warning error: ' + e.message); }
  }, warningMs);

  // Auto-release
  speaker.timeoutTimer = setTimeout(async () => {
    try {
      await doMicRelease(roomId, sessionId, 'timeout');
    } catch(e) { log('Mic auto-release error: ' + e.message); }
  }, ms);
}

/** Clear timers for a speaker */
function clearMicTimers(speaker) {
  if (speaker.warningTimer) { clearTimeout(speaker.warningTimer); speaker.warningTimer = null; }
  if (speaker.timeoutTimer) { clearTimeout(speaker.timeoutTimer); speaker.timeoutTimer = null; }
}

/** Release a mic - core logic used by all release paths */
async function doMicRelease(roomId, sessionId, reason) {
  const state = getMicState(roomId);
  const speaker = state.activeSpeakers.get(sessionId);
  if (!speaker) return false;

  clearMicTimers(speaker);
  state.activeSpeakers.delete(sessionId);

  // Clean up Redis
  await redis.srem('room:' + roomId + ':mics', speaker.username);
  await redis.del('stream:mic:' + speaker.username);

  // Notify room
  await publishToRoom(roomId, {
    type: 'mic-off',
    from: speaker.username,
    username: speaker.username,
    text: speaker.username + (reason === 'timeout' ? ' انتهى وقت المايك' : reason === 'force' ? ' تم إسكاته' : ' أغلق المايك'),
    roomId: roomId,
    ts: Date.now(),
    timestamp: Date.now()
  });

  // Send force-off to the specific user if forced/timeout
  if (reason === 'force' || reason === 'timeout') {
    await publishToRoom(roomId, {
      type: 'mic-force-off',
      target: speaker.username,
      reason: reason,
      ts: Date.now()
    });
  }

  // Broadcast updated speaker list
  await broadcastSpeakerList(roomId);

  // Auto-promote from queue
  await autoPromoteFromQueue(roomId);

  return true;
}

/** Auto-promote users from queue when slots are available */
async function autoPromoteFromQueue(roomId) {
  const state = getMicState(roomId);
  const settings = await getRoomMicSettings(roomId);

  while (state.activeSpeakers.size < settings.maxSpeakers && state.queue.length > 0) {
    const next = state.queue.shift();

    // Verify user is still in room
    const isOnline = await redis.sismember('room:' + roomId + ':online', next.username);
    if (!isOnline) continue;

    const streamName = roomId + '_mic_' + next.sessionId.substring(0, 8);
    state.activeSpeakers.set(next.sessionId, {
      username: next.username,
      streamName: streamName,
      startedAt: Date.now(),
      warningTimer: null,
      timeoutTimer: null
    });

    // Save to Redis
    await redis.sadd('room:' + roomId + ':mics', next.username);
    await redis.set('stream:mic:' + next.username, streamName, 'EX', 3600);

    // Start timer
    startMicTimer(roomId, next.sessionId, settings.micAutoRelease);

    // Notify the promoted user
    await publishToRoom(roomId, {
      type: 'mic-approved',
      target: next.username,
      streamName: streamName,
      roomId: roomId,
      ts: Date.now()
    });

    // Notify room
    await publishToRoom(roomId, {
      type: 'mic-on',
      from: next.username,
      username: next.username,
      streamName: streamName,
      roomId: roomId,
      text: next.username + ' فتح المايك',
      ts: Date.now(),
      timestamp: Date.now()
    });

    await broadcastSpeakerList(roomId);
  }
}

/** Broadcast updated speaker list to all room members */
async function broadcastSpeakerList(roomId) {
  const state = getMicState(roomId);
  const speakers = [];
  for (const [sid, info] of state.activeSpeakers) {
    speakers.push({
      sessionId: sid,
      username: info.username,
      streamName: info.streamName,
      startedAt: info.startedAt
    });
  }
  await publishToRoom(roomId, {
    type: 'speaker-list-update',
    speakers: speakers,
    queue: state.queue.map((q, i) => ({ sessionId: q.sessionId, username: q.username, position: i + 1 })),
    roomId: roomId,
    ts: Date.now()
  });
}

/** Clean up mic state when user leaves room */
async function cleanupMicOnLeave(roomId, username, sessionId) {
  const state = getMicState(roomId);

  // Remove from active speakers
  for (const [sid, info] of state.activeSpeakers) {
    if (info.username === username || sid === sessionId) {
      clearMicTimers(info);
      state.activeSpeakers.delete(sid);
      await redis.srem('room:' + roomId + ':mics', info.username);
      await redis.del('stream:mic:' + info.username);
      await broadcastSpeakerList(roomId);
      await autoPromoteFromQueue(roomId);
      break;
    }
  }

  // Remove from queue
  state.queue = state.queue.filter(q => q.username !== username && q.sessionId !== sessionId);
}

// ---------------------------------------------------------------------------
//  Mic API handlers
// ---------------------------------------------------------------------------

/** POST /api/mic/request - User requests to speak */
async function handleMicRequest(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };
  if (!sess.roomId) return { status: 400, body: { error: 'Not in a room' } };

  const roomId = sess.roomId;
  const displayName = sess.displayName || sess.username;
  const settings = await getRoomMicSettings(roomId);

  // Check permission
  if (!canSpeak(sess.role, settings.micMode)) {
    return { status: 403, body: { error: 'غير مسموح بالتحدث', denied: true } };
  }

  const state = getMicState(roomId);

  // Already speaking?
  for (const [sid, info] of state.activeSpeakers) {
    if (info.username === displayName || sid === body.sessionId) {
      return { status: 200, body: { ok: true, approved: true, streamName: info.streamName, alreadySpeaking: true } };
    }
  }

  // Already in queue?
  const qIdx = state.queue.findIndex(q => q.username === displayName || q.sessionId === body.sessionId);
  if (qIdx >= 0) {
    return { status: 200, body: { ok: true, queued: true, position: qIdx + 1 } };
  }

  // Priority: admins/mods bypass queue
  const isPriority = ['admin', 'owner', 'mod'].includes(sess.role);

  // Check if slots available
  if (state.activeSpeakers.size < settings.maxSpeakers) {
    // Approve immediately
    const streamName = roomId + '_mic_' + body.sessionId.substring(0, 8);
    state.activeSpeakers.set(body.sessionId, {
      username: displayName,
      streamName: streamName,
      startedAt: Date.now(),
      warningTimer: null,
      timeoutTimer: null
    });

    // Save to Redis
    await redis.sadd('room:' + roomId + ':mics', displayName);
    await redis.set('stream:mic:' + displayName, streamName, 'EX', 3600);

    // Start timer
    startMicTimer(roomId, body.sessionId, settings.micAutoRelease);

    // Notify room
    await publishToRoom(roomId, {
      type: 'mic-on',
      from: displayName,
      username: displayName,
      streamName: streamName,
      roomId: roomId,
      text: displayName + ' فتح المايك',
      ts: Date.now(),
      timestamp: Date.now()
    });

    await broadcastSpeakerList(roomId);
    return { status: 200, body: { ok: true, approved: true, streamName: streamName } };
  }

  // Slots full - priority user can bump (but not other admins)
  // For now, add to queue (priority users go to front)
  if (isPriority) {
    state.queue.unshift({ sessionId: body.sessionId, username: displayName, requestedAt: Date.now() });
  } else {
    state.queue.push({ sessionId: body.sessionId, username: displayName, requestedAt: Date.now() });
  }

  const position = state.queue.findIndex(q => q.sessionId === body.sessionId) + 1;

  // Notify user
  await publishToRoom(roomId, {
    type: 'mic-queued',
    target: displayName,
    position: position,
    roomId: roomId,
    ts: Date.now()
  });

  return { status: 200, body: { ok: true, queued: true, position: position } };
}

/** POST /api/mic/release - User releases mic */
async function handleMicRelease(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };

  const roomId = body.roomId || sess.roomId;
  if (!roomId) return { status: 400, body: { error: 'No room' } };

  const released = await doMicRelease(roomId, body.sessionId, 'voluntary');

  // Also remove from queue if queued
  const state = getMicState(roomId);
  const displayName = sess.displayName || sess.username;
  state.queue = state.queue.filter(q => q.sessionId !== body.sessionId && q.username !== displayName);

  return { status: 200, body: { ok: true, released: released } };
}

/** POST /api/mic/force-off - Admin/mod forces speaker off */
async function handleMicForceOff(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };

  // Check permission: must be admin/owner/mod with canAllowMic
  const isAdmin = ['admin', 'owner'].includes(sess.role);
  const hasPerm = sess.permissions && (sess.permissions.includes('canAllowMic') || sess.permissions.includes('canMuteAll'));
  if (!isAdmin && !hasPerm) return { status: 403, body: { error: 'Unauthorized' } };

  const roomId = body.roomId || sess.roomId;
  const targetSession = body.targetSessionId;
  const targetUsername = body.targetUsername;

  const state = getMicState(roomId);

  // Find by session or username
  let foundSid = null;
  for (const [sid, info] of state.activeSpeakers) {
    if (sid === targetSession || info.username === targetUsername) {
      foundSid = sid;
      break;
    }
  }

  if (!foundSid) return { status: 404, body: { error: 'Speaker not found' } };

  await doMicRelease(roomId, foundSid, 'force');
  await writeLog('mic_force_off', { by: sess.displayName || sess.username, target: targetUsername, roomId });
  return { status: 200, body: { ok: true } };
}

/** POST /api/mic/queue/approve - Approve user from queue */
async function handleMicQueueApprove(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };

  const isAdmin = ['admin', 'owner'].includes(sess.role);
  const hasPerm = sess.permissions && sess.permissions.includes('canAllowMic');
  if (!isAdmin && !hasPerm) return { status: 403, body: { error: 'Unauthorized' } };

  const roomId = body.roomId || sess.roomId;
  const state = getMicState(roomId);
  const settings = await getRoomMicSettings(roomId);

  // Find in queue
  const idx = state.queue.findIndex(q => q.sessionId === body.targetSessionId || q.username === body.targetUsername);
  if (idx < 0) return { status: 404, body: { error: 'Not in queue' } };

  // Check if there's space
  if (state.activeSpeakers.size >= settings.maxSpeakers) {
    return { status: 400, body: { error: 'المتحدثون ممتلئون - أسكت متحدث أولاً' } };
  }

  const user = state.queue.splice(idx, 1)[0];
  const streamName = roomId + '_mic_' + user.sessionId.substring(0, 8);

  state.activeSpeakers.set(user.sessionId, {
    username: user.username,
    streamName: streamName,
    startedAt: Date.now(),
    warningTimer: null,
    timeoutTimer: null
  });

  await redis.sadd('room:' + roomId + ':mics', user.username);
  await redis.set('stream:mic:' + user.username, streamName, 'EX', 3600);
  startMicTimer(roomId, user.sessionId, settings.micAutoRelease);

  await publishToRoom(roomId, {
    type: 'mic-approved',
    target: user.username,
    streamName: streamName,
    roomId: roomId,
    ts: Date.now()
  });

  await publishToRoom(roomId, {
    type: 'mic-on',
    from: user.username,
    username: user.username,
    streamName: streamName,
    roomId: roomId,
    text: user.username + ' فتح المايك',
    ts: Date.now(),
    timestamp: Date.now()
  });

  await broadcastSpeakerList(roomId);
  return { status: 200, body: { ok: true } };
}

/** POST /api/mic/queue/deny - Deny user from queue */
async function handleMicQueueDeny(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };

  const isAdmin = ['admin', 'owner'].includes(sess.role);
  const hasPerm = sess.permissions && sess.permissions.includes('canAllowMic');
  if (!isAdmin && !hasPerm) return { status: 403, body: { error: 'Unauthorized' } };

  const roomId = body.roomId || sess.roomId;
  const state = getMicState(roomId);

  const idx = state.queue.findIndex(q => q.sessionId === body.targetSessionId || q.username === body.targetUsername);
  if (idx < 0) return { status: 404, body: { error: 'Not in queue' } };

  const user = state.queue.splice(idx, 1)[0];

  await publishToRoom(roomId, {
    type: 'mic-denied',
    target: user.username,
    roomId: roomId,
    ts: Date.now()
  });

  await broadcastSpeakerList(roomId);
  return { status: 200, body: { ok: true } };
}

/** POST /api/mic/queue/remove - User removes self from queue */
async function handleMicQueueRemove(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };

  const roomId = body.roomId || sess.roomId;
  const state = getMicState(roomId);
  const displayName = sess.displayName || sess.username;

  state.queue = state.queue.filter(q => q.sessionId !== body.sessionId && q.username !== displayName);
  return { status: 200, body: { ok: true } };
}

/** GET-style /api/mic/speakers - Get active speakers and queue */
async function handleMicSpeakers(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Auth required' } };
  const roomId = body.roomId;
  if (!roomId) return { status: 400, body: { error: 'roomId required' } };

  const state = getMicState(roomId);
  const settings = await getRoomMicSettings(roomId);
  const now = Date.now();

  const speakers = [];
  for (const [sid, info] of state.activeSpeakers) {
    speakers.push({
      sessionId: sid,
      username: info.username,
      streamName: info.streamName,
      startedAt: info.startedAt,
      duration: Math.floor((now - info.startedAt) / 1000)
    });
  }

  const queue = state.queue.map((q, i) => ({
    sessionId: q.sessionId,
    username: q.username,
    position: i + 1,
    waitTime: Math.floor((now - q.requestedAt) / 1000)
  }));

  return { status: 200, body: { speakers, queue, settings } };
}

/** POST /api/admin/room/mic-settings - Update room mic settings */
async function handleAdminMicSettings(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.roomId) return { status: 400, body: { error: 'roomId required' } };

  const sets = [];
  const vals = [];
  let idx = 1;

  if (body.maxSpeakers !== undefined) {
    const ms = Math.max(1, Math.min(10, parseInt(body.maxSpeakers) || 1));
    sets.push('max_speakers = $' + idx++);
    vals.push(ms);
  }
  if (body.micQueueMode !== undefined) {
    sets.push('mic_queue_mode = $' + idx++);
    vals.push(body.micQueueMode === 'manual' ? 'manual' : 'fifo');
  }
  if (body.micAutoRelease !== undefined) {
    const ar = Math.max(0, Math.min(60, parseInt(body.micAutoRelease) || 0));
    sets.push('mic_auto_release = $' + idx++);
    vals.push(ar);
  }
  if (body.micMode !== undefined) {
    sets.push('mic_mode = $' + idx++);
    vals.push(body.micMode);
  }

  if (sets.length === 0) return { status: 400, body: { error: 'No fields to update' } };

  vals.push(body.roomId);
  await pgPool.query('UPDATE rooms SET ' + sets.join(', ') + ' WHERE id = $' + idx, vals);
  await writeLog('mic_settings_update', JSON.stringify({ roomId: body.roomId, ...body }));
  return { status: 200, body: { ok: true } };
}

/** Register a long-poll waiter. Returns a promise that resolves with messages. */
function waitForMessages(roomId, timeoutMs) {
  return new Promise(resolve => {
    if (!pollWaiters.has(roomId)) pollWaiters.set(roomId, new Set());
    const entry = { resolve, timer: null };
    entry.timer = setTimeout(() => {
      // Timeout – resolve with empty array
      pollWaiters.get(roomId)?.delete(entry);
      resolve([]);
    }, timeoutMs);
    pollWaiters.get(roomId).add(entry);
  });
}

// ---------------------------------------------------------------------------
//  PostgreSQL helpers
// ---------------------------------------------------------------------------

/** Write an admin/system log entry */
async function writeLog(action, details) {
  try {
    await pgPool.query(
      'INSERT INTO logs (action, details, created_at) VALUES ($1, $2, NOW())',
      [action, typeof details === 'string' ? details : JSON.stringify(details)]
    );
  } catch (e) {
    log(`Log write error: ${e.message}`);
  }
}

/** Get a setting value from the settings table */
async function getSetting(key) {
  const r = await pgPool.query('SELECT value FROM settings WHERE key = $1', [key]);
  return r.rows.length ? r.rows[0].value : null;
}

/** Upsert a setting value */
async function setSetting(key, value) {
  await pgPool.query(
    `INSERT INTO settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
    [key, value]
  );
}

/** Get the default room (is_default = true, or first room) */
async function getDefaultRoom() {
  let r = await pgPool.query('SELECT * FROM rooms WHERE is_default = true LIMIT 1');
  if (r.rows.length) return r.rows[0];
  r = await pgPool.query('SELECT * FROM rooms ORDER BY created_at ASC LIMIT 1');
  return r.rows.length ? r.rows[0] : null;
}

// ---------------------------------------------------------------------------
//  API: Authentication
// ---------------------------------------------------------------------------

/**
 * POST /api/login
 * Guest: { username }
 * Mod:   { code, password }
 */


// ===== RATE LIMITING =====
const rateLimitMap = new Map();
function rateLimit(key, maxRequests, windowMs) {
  const now = Date.now();
  if (!rateLimitMap.has(key)) rateLimitMap.set(key, []);
  const timestamps = rateLimitMap.get(key).filter(t => now - t < windowMs);
  if (timestamps.length >= maxRequests) return true; // blocked
  timestamps.push(now);
  rateLimitMap.set(key, timestamps);
  return false; // allowed
}
// Clean old entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, times] of rateLimitMap) {
    const valid = times.filter(t => now - t < 300000);
    if (valid.length === 0) rateLimitMap.delete(key);
    else rateLimitMap.set(key, valid);
  }
}, 300000);

// Check if session has a mod permission
function hasModPerm(sess, perm) {
  if (sess.role === 'admin' || sess.role === 'owner') return true;
  if (sess.role === 'mod' && sess.permissions && sess.permissions.indexOf(perm) >= 0) return true;
  return false;
}

async function handleLogin(body) {
  const ip = body._realIp || 'unknown';
  if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1' && rateLimit('login:' + ip, 10, 60000)) return { status: 429, body: { error: 'كثرة محاولات. انتظر دقيقة' } };
  // --- Mod login ---
  if (body.code && (body.password || body.pin)) {
    if (body.pin && !body.password) body.password = body.pin;
    const modRes = await pgPool.query('SELECT * FROM mods WHERE code = $1', [body.code]);
    if (!modRes.rows.length) return { status: 401, body: { error: 'Invalid mod code' } };
    const mod = modRes.rows[0];
    if (sha256(body.password) !== mod.password_hash) {
      return { status: 401, body: { error: 'Invalid password' } };
    }
    const defaultRoom = await getDefaultRoom();
    const roomId = null; // Don't join room until user selects one
    const sessionId = await createSession(
      mod.code, mod.role, mod.badge, mod.permissions, roomId, mod.display_name
    );
    // Update last_seen equivalent (mods table doesn't have last_seen, but we log)
    // Don't add to room yet - wait for room selection
    await writeLog('mod_login', { code: mod.code, displayName: mod.display_name });
  if (body.fingerprint) {
    const ip = (body._reqIp) || 'unknown'; // Set from request headers, not user input
    await pgPool.query(
      'INSERT INTO device_tracks (fingerprint, ip, username, user_agent, screen_size, language, platform) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [body.fingerprint, ip, mod.display_name, body.userAgent||'', body.screenSize||'', body.language||'', body.platform||'']
    );
    const dban = await pgPool.query('SELECT * FROM device_bans WHERE fingerprint = $1', [body.fingerprint]);
    if (dban.rows.length) {
      await destroySession(sessionId);
      return { status: 403, body: { error: 'جهازك محظور' } };
    }
  }
    return {
      status: 200,
      body: {
        sessionId,
        username: mod.code,
        displayName: mod.display_name,
        role: mod.role,
        badge: mod.badge,
        permissions: mod.permissions || [],
        roomId,
        users: [], recentMessages: [], rooms: await getAllRoomsWithCounts(),
      },
    };
  }

  // --- Guest login ---
  if (!body.username || typeof body.username !== 'string' || body.username.trim().length < 1) {
    return { status: 400, body: { error: 'Username required' } };
  }
  const username = body.username.trim().substring(0, 30);

  // Check ban
  const banCheck = await pgPool.query(
    'SELECT * FROM bans WHERE username = $1', [username]
  );
  if (banCheck.rows.length) {
    return { status: 403, body: { error: 'You are banned', reason: banCheck.rows[0].reason } };
  }

  // Determine role: first user ever becomes owner
  const userCount = await pgPool.query('SELECT COUNT(*)::int AS cnt FROM users');
  const isFirstUser = userCount.rows[0].cnt === 0;
  const role = isFirstUser ? 'owner' : 'guest';

  // Upsert user row
  await pgPool.query(
    `INSERT INTO users (username, display_name, role, created_at, last_seen, enabled)
     VALUES ($1, $1, $2, NOW(), NOW(), true)
     ON CONFLICT (username) DO UPDATE SET last_seen = NOW(), enabled = true`,
    [username, role]
  );

  // If user exists and has an upgraded role, fetch it
  const userRow = await pgPool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = userRow.rows[0];
  const effectiveRole = user.role || role;

  const defaultRoom = await getDefaultRoom();
  const roomId = null; // Don't join room until user selects one
  const sessionId = await createSession(
    username, effectiveRole, user.badge || '', user.permissions || [], roomId, user.display_name
  );

  // Don't add to room yet - wait for room selection
  // Track daily stats
    await pgPool.query("INSERT INTO daily_stats (date, visitors) VALUES (CURRENT_DATE, 1) ON CONFLICT (date) DO UPDATE SET visitors = daily_stats.visitors + 1");
    await writeLog('guest_login', { username, role: effectiveRole });
  // Device tracking
  if (body.fingerprint) {
    const ip = (body._reqIp) || 'unknown'; // Set from request headers, not user input
    await pgPool.query(
      'INSERT INTO device_tracks (fingerprint, ip, username, user_agent, screen_size, language, platform) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [body.fingerprint, ip, username, body.userAgent||'', body.screenSize||'', body.language||'', body.platform||'']
    );
    // Check device ban
    const dban = await pgPool.query('SELECT * FROM device_bans WHERE fingerprint = $1', [body.fingerprint]);
    if (dban.rows.length) {
      await destroySession(sessionId);
      return { status: 403, body: { error: 'جهازك محظور' } };
    }
  }

  return {
    status: 200,
    body: {
      sessionId,
      username,
      displayName: user.display_name || username,
      role: effectiveRole,
      badge: user.badge || '',
      permissions: user.permissions || [],
      roomId,
      users: await getOnlineUsers(roomId),
      recentMessages: [],
      rooms: await (async()=>{const rr=await pgPool.query('SELECT id, name, icon FROM rooms ORDER BY name');const result=[];for(const r of rr.rows){const cnt=await getOnlineCount(String(r.id));result.push({id:r.id,name:r.name,icon:r.icon,online:cnt||0})}return result.sort((a,b)=>b.online-a.online)})(),
    },
  };
}

/**
 * POST /api/logout
 */
async function handleLogout(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 200, body: { ok: true } };
  await removeFromAllRooms(sess.displayName || sess.username);
  await destroySession(body.sessionId);

  // Broadcast user-left to the room
  if (sess.roomId && sess.roomId !== 'null' && sess.roomId !== null) {
    const wasInRoom = await redis.sismember('room:' + sess.roomId + ':online', sess.displayName || sess.username);
    if (wasInRoom) {
      await publishToRoom(sess.roomId, {
        type: 'leave',
        from: sess.displayName || sess.username,
        text: (sess.displayName || sess.username) + ' غادر الغرفة',
        ts: Date.now(),
        timestamp: Date.now(),
      });
    }
  }
  await writeLog('logout', { username: sess.username });
  return { status: 200, body: { ok: true } };
}

// ---------------------------------------------------------------------------
//  API: Messaging
// ---------------------------------------------------------------------------

/**
 * POST /api/send
 * body: { sessionId, text, private?, target? }
 */
async function handleSend(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };
  if (!sess.roomId) return { status: 400, body: { error: 'Not in a room' } };
  if (!body.text || !body.text.trim()) return { status: 400, body: { error: 'Empty message' } };

  const text = sanitize(body.text.trim().substring(0, 5000));
  // Chat block check
  const dn = sess.displayName || sess.username;
  const isCB = await redis.get('chatblock:' + dn);
  if (isCB) return { status: 403, body: { error: 'تم منعك من الكتابة' } };
  const isCL = await redis.get('chatlock:' + sess.roomId);
  if (isCL === '1' && sess.role !== 'admin' && sess.role !== 'owner' && sess.role !== 'mod') return { status: 403, body: { error: 'الكتابة مقفلة' } };
  // Rate limit messages: 30 per 10 seconds
        if (rateLimit('msg:' + socket.username, 30, 10000)) { if (ack) ack({error:'أنت ترسل بسرعة. انتظر شوي'}); return; }
        const filteredWords = await getFilteredWords();
  const blocked = checkFilter(text, filteredWords);
  if (blocked) {
    // Save violation as evidence
    await writeLog('violation', JSON.stringify({username: displayName, word: blocked, text: text.substring(0, 100)}));
    return { status: 400, body: { error: 'الرسالة تحتوي على كلمة ممنوعة: ' + blocked } };
  }
  const isPrivate = !!body.private;
  const target = body.target || null;
  const msgType = isPrivate ? 'private' : 'public';
  const displayName = sess.displayName || sess.username;

  // Save to PostgreSQL
  // Only save if it's a violation (blocked by filter)
  // Normal messages are NOT saved - they go direct to users via pub/sub

  const msgObj = {
    type: isPrivate ? 'private' : 'chat',
    from: displayName,
    username: displayName,
    role: sess.role,
    badge: sess.badge,
    text,
    target,
    timestamp: Date.now(),
    ts: Date.now(),
  };

  // Publish to room channel so all pollers receive it
  if (isPrivate && target) {
    if (io) {
      for (var [_sid, _sock] of io.sockets.sockets) {
        if (_sock.username === (sess.displayName || sess.username)) {
          _sock.emit('room-message', Object.assign({}, msgObj, {type: 'private-sent'}));
        } else if (_sock.username === target) {
          _sock.emit('room-message', Object.assign({}, msgObj, {type: 'private'}));
        }
      }
    }
  } else {
    await publishToRoom(sess.roomId, msgObj);
  }

  return { status: 200, body: { ok: true } };
}

/**
 * POST /api/poll
 * Long-poll: waits up to 25s for new messages in the user's current room.
 */
async function handlePoll(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) { return { status: 401, body: { error: 'Not authenticated' } }; }
  if (!sess.roomId) return { status: 200, body: { messages: [] } };

  // Ensure we are subscribed to this room
  await subscribeRoom(sess.roomId);

  const messages = await waitForMessages(sess.roomId, LONG_POLL_TIMEOUT);
  // Get online users AFTER messages arrive (so leave/join are reflected)
  const onlineUsers = await getOnlineUsers(sess.roomId);
  // Build full poll response for frontend compatibility
    const sess2 = await getSession(body.sessionId);
    const roomRow = await pgPool.query('SELECT name FROM rooms WHERE id = $1', [sess.roomId]);
    const roomsAll = await (async()=>{const rr=await pgPool.query('SELECT id, name, icon FROM rooms ORDER BY name');const result=[];for(const r of rr.rows){const cnt=await getOnlineCount(String(r.id));result.push({id:r.id,name:r.name,icon:r.icon,online:cnt||0})}return result.sort((a,b)=>b.online-a.online)})();
    return { status: 200, body: { 
      messages, 
      users: onlineUsers, 
      role: sess2 ? sess2.role : 'guest',
      roomName: roomRow.rows[0]?.name || '',
      rooms: roomsAll
    } };
}

/**
 * POST /api/switch-room
 */
async function handleSwitchRoom(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };

  const newRoomId = String(body.roomId);
  const roomCheck = await pgPool.query('SELECT * FROM rooms WHERE id = $1', [newRoomId]);
  if (!roomCheck.rows.length) return { status: 404, body: { error: 'Room not found' } };

  const displayName = sess.displayName || sess.username;

  // Remove from old room
  if (sess.roomId && sess.roomId !== 'null') {
    await removeOnlineUser(sess.roomId, displayName);
    await redis.srem('room:' + sess.roomId + ':cams', displayName);
    await redis.srem('room:' + sess.roomId + ':mics', displayName);
    await redis.del('stream:cam:' + displayName);
    await redis.del('stream:mic:' + displayName);
    // Clean up mic state on room switch
    await cleanupMicOnLeave(sess.roomId, displayName, body.sessionId);
    await publishToRoom(sess.roomId, {
      type: 'leave',
      from: displayName,
      text: displayName + ' غادر الغرفة',
      ts: Date.now(),
      timestamp: Date.now(),
    });
  }

  // Join new room
  await updateSession(body.sessionId, { roomId: newRoomId });
  await addOnlineUser(newRoomId, displayName, sess.role, sess.badge);
  await redis.set('hb:' + displayName, Date.now().toString(), 'EX', 180);
  await publishToRoom(newRoomId, { type: 'join', from: displayName, text: displayName + ' دخل الغرفة', timestamp: Date.now(), ts: Date.now() });
  await subscribeRoom(newRoomId);
  await publishToRoom(newRoomId, {
    type: 'system',
    text: `${displayName} joined the room`,
    ts: Date.now(),
  });

  // Return recent messages from DB
  const recent = await pgPool.query(
    `SELECT username, text, msg_type, target, created_at
     FROM messages WHERE room_id = $1 ORDER BY created_at DESC LIMIT 0`,
    [newRoomId]
  );

  const room = roomCheck.rows[0];
  const onlineUsers = await getOnlineUsers(newRoomId);

  return {
    status: 200,
    body: {
      ok: true,
      room: { id: room.id, name: room.name, marquee: room.marquee, icon: room.icon, pinned_msg: room.pinned_msg || "" },
      messages: recent.rows.reverse(),
      onlineUsers,
    },
  };
}

/**
 * POST /api/signal
 * For mic/cam WebRTC signalling – relayed to room via pub/sub.
 */
async function handleSignal(body) {
  const sess = await getSession(body.sessionId);
  if (!sess) return { status: 401, body: { error: 'Not authenticated' } };
  if (!sess.roomId) return { status: 400, body: { error: 'Not in a room' } };

  const displayName = sess.displayName || sess.username;

  const sigType = body.type || 'unknown';
  // Include roomId in signal so frontend knows which room this belongs to
  const signalRoomId = sess.roomId;
  
  // Save media state in Redis
  if (sigType === 'cam-on') { await redis.sadd('room:' + sess.roomId + ':cams', displayName); if (body.streamName) await redis.set('stream:cam:' + displayName, body.streamName, 'EX', 3600); }
  if (sigType === 'cam-off') await redis.srem('room:' + sess.roomId + ':cams', displayName);
  // mic-on and mic-off now handled by /api/mic/request and /api/mic/release
  // Keep signal handler for backward compatibility but redirect to new system
  if (sigType === 'mic-on') {
    // Use new mic request system
    const micResult = await handleMicRequest({ sessionId: body.sessionId, roomId: sess.roomId });
    if (micResult.body.approved) {
      // Already handled by handleMicRequest
      return { status: 200, body: { ok: true, approved: true, streamName: micResult.body.streamName } };
    } else if (micResult.body.queued) {
      return { status: 200, body: { ok: true, queued: true, position: micResult.body.position } };
    } else if (micResult.body.denied) {
      return { status: 200, body: { ok: true, denied: true } };
    }
    return { status: 200, body: { ok: true } };
  }
  if (sigType === 'mic-off') {
    await handleMicRelease({ sessionId: body.sessionId, roomId: sess.roomId });
    return { status: 200, body: { ok: true } };
  }
  
  const signalMsg = {
    type: sigType,
    from: displayName,
    username: displayName,
    target: body.target || null,
    data: body.data || null,
    streamName: body.streamName || null,
    roomId: signalRoomId || null,
    ts: Date.now(),
    timestamp: Date.now(),
  };

  await publishToRoom(sess.roomId, signalMsg);
  return { status: 200, body: { ok: true } };
}

// ---------------------------------------------------------------------------
//  API: Admin authentication
// ---------------------------------------------------------------------------

/** Verify admin token (stored in Redis) */
async function verifyAdmin(token) {
  if (!token) return false;
  const val = await redis.get(`admin:${token}`);
  return val === 'valid';
}

/**
 * POST /api/admin/login
 * body: { password }
 */

async function handleAdminUsers(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const r = await pgPool.query('SELECT username, display_name, role, badge, enabled, created_at, last_seen FROM users ORDER BY last_seen DESC NULLS LAST');
  // Get actual connected users from Socket.IO
  const connectedUsers = new Set();
  if (io) {
    for (const [sid, sock] of io.sockets.sockets) {
      if (sock.username) connectedUsers.add(sock.username);
    }
  }
  const users = r.rows.map(u => ({
    ...u,
    online: connectedUsers.has(u.username) || connectedUsers.has(u.display_name)
  }));
  return { status: 200, body: { users } };
}

async function handleAdminLogin(body) {
  const ip = body._realIp || 'unknown';
  if (ip !== '127.0.0.1' && ip !== '::1' && ip !== '::ffff:127.0.0.1' && rateLimit('admin:' + ip, 5, 300000)) return { status: 429, body: { error: 'كثرة محاولات. انتظر 5 دقائق' } };
  if (!body.password) return { status: 400, body: { error: 'Password required' } };

  // Fetch stored hash or use default
  let storedHash = await getSetting('admin_password');
  if (!storedHash) {
    storedHash = ADMIN_PASSWORD_DEFAULT_HASH;
    await setSetting('admin_password', storedHash);
  }

  if (sha256(body.password) !== storedHash) {
    return { status: 401, body: { error: 'Invalid password' } };
  }

  const token = genId();
  await redis.set(`admin:${token}`, 'valid', 'EX', 14400); // 4 hours // 24h
  await writeLog('admin_login', { ip: 'local' });
  return { status: 200, body: { token } };
}

// ---------------------------------------------------------------------------
//  API: Admin endpoints
// ---------------------------------------------------------------------------

async function handleAdminStats(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  
  const os = require('os');
  
  // Basic counts
  const online = io ? io.sockets.sockets.size : 0;
  const registered = (await pgPool.query('SELECT COUNT(*)::int AS c FROM users')).rows[0].c;
  const banned = (await pgPool.query('SELECT COUNT(*)::int AS c FROM bans')).rows[0].c;
  const roomCount = (await pgPool.query('SELECT COUNT(*)::int AS c FROM rooms')).rows[0].c;
  const modsCount = (await pgPool.query('SELECT COUNT(*)::int AS c FROM mods')).rows[0].c;
  
  // Messages
  const messagesTotal = (await pgPool.query("SELECT COUNT(*)::int AS c FROM messages WHERE msg_type = 'violation'")).rows[0].c;
  const messagesToday = (await pgPool.query("SELECT COUNT(*)::int AS c FROM messages WHERE created_at >= CURRENT_DATE")).rows[0].c;
  
  // Top room
  const allRooms = (await pgPool.query('SELECT id, name FROM rooms')).rows;
  let topRoom = { name: '-', online: 0 };
  for (const r of allRooms) {
    const cnt = await redis.scard('room:' + r.id + ':online');
    if (cnt > topRoom.online) topRoom = { name: r.name, online: cnt };
  }
  
  // Top user today
  const topUserRow = await pgPool.query("SELECT username, COUNT(*)::int AS c FROM messages WHERE created_at >= CURRENT_DATE GROUP BY username ORDER BY c DESC LIMIT 1");
  const topUser = topUserRow.rows.length ? { name: topUserRow.rows[0].username, count: topUserRow.rows[0].c } : { name: '-', count: 0 };
  
  // Recent events (last 20 logs)
  const logsRows = await pgPool.query('SELECT action, details, created_at FROM logs ORDER BY id DESC LIMIT 20');
  const recentEvents = logsRows.rows.map(l => ({ time: l.created_at, action: l.action, details: l.details || '' }));
  
  // Server warnings
  const cpuPercent = Math.round((os.loadavg()[0] / os.cpus().length) * 100);
  const memPercent = Math.round(((os.totalmem() - os.freemem()) / os.totalmem()) * 100);
  const warnings = [];
  if (cpuPercent > 80) warnings.push({level:'danger',msg:'CPU ' + cpuPercent + '%'});
  else if (cpuPercent > 50) warnings.push({level:'warning',msg:'CPU ' + cpuPercent + '%'});
  if (memPercent > 85) warnings.push({level:'danger',msg:'RAM ' + memPercent + '%'});
  else if (memPercent > 70) warnings.push({level:'warning',msg:'RAM ' + memPercent + '%'});
  if (!warnings.length) warnings.push({level:'ok',msg:'كل شي تمام'});
  
  return { status: 200, body: {
    online, registered, banned, rooms: roomCount, modsCount,
    messagesTotal, messagesToday,
    topRoom, topUser,
    hourlyOnline: new Array(24).fill(online),
    recentEvents, serverWarnings: warnings,
    recentLogs: recentEvents.map(e => ({time:e.time, action:e.action, actor:'', target:'', details:e.details}))
  }};
}

async function handleAdminServerHealth(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };

  const cpus = os.cpus();
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = totalMem - freeMem;
  const uptime = process.uptime();
  const processMemory = process.memoryUsage();

  // Calculate CPU usage
  const loadAvg = os.loadavg();
  const cpuPercent = Math.min(100, Math.round(loadAvg[0] / cpus.length * 100));
  const memPercent = Math.round(usedMem / totalMem * 100);

  // Count active connections
  let activeConnections = 0;
  let activeMics = 0;
  let activeCams = 0;
  try {
    if (io) activeConnections = io.sockets.sockets.size;
    const micKeys = await redis.keys('room:*:mics');
    for (const k of micKeys) { activeMics += await redis.scard(k); }
    const camKeys = await redis.keys('room:*:cams');
    for (const k of camKeys) { activeCams += await redis.scard(k); }
  } catch(e) {}

  // Estimate capacity
  // Accurate capacity based on actual specs
    const totalMemMB = Math.round(totalMem / 1024 / 1024);
    const freeMemMB = Math.round(freeMem / 1024 / 1024);
    const memPerUser = 0.5; // ~0.5MB per socket connection
    const maxByMem = Math.floor(freeMemMB / memPerUser);
    const maxByCPU = cpus.length * 400;
    const maxUsersEstimate = Math.min(maxByMem, maxByCPU, 2000);
  const maxMicsEstimate = cpus.length * 15; // WebRTC relay uses more CPU

  const warnings = [];
  if (memPercent > 85) warnings.push({level:'danger', msg:'ذاكرة منخفضة ('+memPercent+'%)', fix:'ترقية السيرفر'});
  if (cpuPercent > 80) warnings.push({level:'danger', msg:'معالج مرتفع ('+cpuPercent+'%)', fix:'ترقية أو تقليل الحمل'});
  if (processMemory.heapUsed > 500*1024*1024) warnings.push({level:'warning', msg:'Node.js heap مرتفع', fix:'إعادة تشغيل'});

  return {
    status: 200,
    body: {
      cpu: { model: cpus[0]?.model || 'unknown', cores: cpus.length, percent: cpuPercent, loadAvg },
      memory: { total: totalMem, free: freeMem, used: usedMem, percent: memPercent, totalMB: Math.round(totalMem/1024/1024), usedMB: Math.round(usedMem/1024/1024), freeMB: Math.round(freeMem/1024/1024) },
      process: { uptime: Math.round(uptime), pid: process.pid, heapUsedMB: Math.round(processMemory.heapUsed/1024/1024), rssMB: Math.round(processMemory.rss/1024/1024), nodeVersion: process.version },
      server: { hostname: os.hostname(), platform: os.platform(), uptimeSeconds: Math.round(os.uptime()) },
      connections: { users: activeConnections, mics: activeMics, cams: activeCams },
      capacity: { maxUsers: maxUsersEstimate, maxMics: maxMicsEstimate, usagePercent: Math.round(activeConnections / maxUsersEstimate * 100), maxCams: cpus.length * 10, note: 'شات كتابي: ~' + maxUsersEstimate + ' | مع مايك: ~' + Math.floor(maxUsersEstimate/2) + ' | مع كام: ~' + Math.floor(maxUsersEstimate/4) },
      warnings
    }
  };
}

async function handleAdminUserRole(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.username || !body.role) return { status: 400, body: { error: 'username and role required' } };
  await pgPool.query('UPDATE users SET role = $1 WHERE username = $2', [body.role, body.username]);
  await writeLog('role_change', { username: body.username, role: body.role });
  return { status: 200, body: { ok: true } };
}

async function handleAdminUserBadge(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.username) return { status: 400, body: { error: 'username required' } };
  await pgPool.query('UPDATE users SET badge = $1 WHERE username = $2', [body.badge || '', body.username]);
  await writeLog('badge_change', { username: body.username, badge: body.badge });
  return { status: 200, body: { ok: true } };
}

async function handleAdminUserKick(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.username) return { status: 400, body: { error: 'username required' } };

  // Remove from all rooms
  await removeFromAllRooms(body.username);

  // Find and destroy their session(s) by scanning (small scale is fine)
  const keys = await redis.keys('session:*');
  for (const key of keys) {
    const raw = await redis.get(key);
    if (!raw) continue;
    try {
      const s = JSON.parse(raw);
      if (s.username === body.username || s.displayName === body.username) {
        await redis.del(key);
      }
    } catch (_) { /* ignore parse errors */ }
  }

  await writeLog('kick', { username: body.username });
  return { status: 200, body: { ok: true } };
}

async function handleAdminUserBan(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.username) return { status: 400, body: { error: 'username required' } };

  await pgPool.query(
    'INSERT INTO bans (username, reason, banned_by, created_at) VALUES ($1, $2, $3, NOW())',
    [body.username, body.reason || 'No reason', 'admin']
  );

  // Also kick them
  await handleAdminUserKick(body);
  await writeLog('ban', { username: body.username, reason: body.reason });
  return { status: 200, body: { ok: true } };
}

async function handleAdminUserUnban(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.username) return { status: 400, body: { error: 'username required' } };
  await pgPool.query('DELETE FROM bans WHERE username = $1', [body.username]);
  await writeLog('unban', { username: body.username });
  return { status: 200, body: { ok: true } };
}

async function handleAdminBans(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const r = await pgPool.query('SELECT * FROM bans ORDER BY created_at DESC');
  return { status: 200, body: { bans: r.rows } };
}

async function handleAdminRooms(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const r = await pgPool.query('SELECT * FROM rooms ORDER BY name');
  const rooms = [];
  for (const room of r.rows) {
    const onlineCount = await getOnlineCount(String(room.id));
    const micState = getMicState(String(room.id));
    rooms.push({ ...room, onlineCount, activeSpeakers: micState.activeSpeakers.size, queueSize: micState.queue.length });
  }
  return { status: 200, body: { rooms } };
}

async function handleAdminRoomCreate(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.name) return { status: 400, body: { error: 'Room name required' } };

  const roomId = 'room_' + Date.now().toString(36) + Math.random().toString(36).substr(2, 4);
  const r = await pgPool.query(
    `INSERT INTO rooms (id, name, password, icon, created_at, is_default)
     VALUES ($1, $2, $3, $4, NOW(), false) RETURNING *`,
    [roomId, body.name, body.password || null, body.icon || '🏠']
  );
  await writeLog('room_create', { name: body.name });
  return { status: 200, body: { room: r.rows[0] } };
}

async function handleAdminRoomDelete(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.roomId) return { status: 400, body: { error: 'roomId required' } };
  await pgPool.query('DELETE FROM messages WHERE room_id = $1', [body.roomId]);
  await pgPool.query('DELETE FROM rooms WHERE id = $1', [body.roomId]);
  await redis.del(`room:${body.roomId}:online`);
  await writeLog('room_delete', { roomId: body.roomId });
  return { status: 200, body: { ok: true } };
}

async function handleAdminRoomUpdate(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.roomId) return { status: 400, body: { error: 'roomId required' } };

  const sets = [];
  const vals = [];
  let idx = 1;

  if (body.name !== undefined) { sets.push(`name = $${idx++}`); vals.push(body.name); }
  if (body.password !== undefined) { sets.push(`password = $${idx++}`); vals.push(body.password); }
  if (body.marquee !== undefined) { sets.push(`marquee = $${idx++}`); vals.push(body.marquee); }
  if (body.maxUsers !== undefined) { sets.push(`max_users = $${idx++}`); vals.push(body.maxUsers); }
  if (body.icon !== undefined) { sets.push(`icon = $${idx++}`); vals.push(body.icon); }
  if (body.micMode !== undefined) { sets.push(`mic_mode = $${idx++}`); vals.push(body.micMode); }
  if (body.camMode !== undefined) { sets.push(`cam_mode = $${idx++}`); vals.push(body.camMode); }
  if (body.chatMode !== undefined) { sets.push(`chat_mode = $${idx++}`); vals.push(body.chatMode); }
  if (body.fixedText !== undefined) { body.pinnedMsg = body.fixedText; }
  if (body.pinnedMsg !== undefined) { sets.push(`pinned_msg = $${idx++}`); vals.push(body.pinnedMsg); }
  if (body.maxSpeakers !== undefined) { sets.push(`max_speakers = $${idx++}`); vals.push(Math.max(1, Math.min(10, parseInt(body.maxSpeakers) || 1))); }
  if (body.micQueueMode !== undefined) { sets.push(`mic_queue_mode = $${idx++}`); vals.push(body.micQueueMode); }
  if (body.micAutoRelease !== undefined) { sets.push(`mic_auto_release = $${idx++}`); vals.push(Math.max(0, Math.min(60, parseInt(body.micAutoRelease) || 0))); }

  if (sets.length === 0) return { status: 400, body: { error: 'No fields to update' } };

  vals.push(body.roomId);
  await pgPool.query(`UPDATE rooms SET ${sets.join(', ')} WHERE id = $${idx}`, vals);
  await writeLog('room_update', { roomId: body.roomId });

  // If marquee changed, broadcast it to the room
  if (body.marquee !== undefined) {
    await publishToRoom(String(body.roomId), {
      type: 'marquee',
      text: body.marquee,
      ts: Date.now(),
    });
  }

  return { status: 200, body: { ok: true } };
}

async function handleAdminMods(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const r = await pgPool.query('SELECT id, display_name, code, role, badge, permissions, created_at FROM mods ORDER BY created_at DESC');
  return { status: 200, body: { mods: r.rows } };
}

async function handleAdminModAdd(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.displayName || !body.code || !body.password) {
    return { status: 400, body: { error: 'displayName, code, and password required' } };
  }

  const hash = sha256(body.password);
  await pgPool.query(
    `INSERT INTO mods (display_name, code, password_hash, role, badge, permissions, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
    [
      body.displayName,
      body.code,
      hash,
      body.role || 'mod',
      body.badge || '',
      body.permissions || [],
    ]
  );
  await writeLog('mod_add', { code: body.code, displayName: body.displayName });
  return { status: 200, body: { ok: true } };
}

async function handleAdminModUpdate(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.code) return { status: 400, body: { error: 'code required' } };

  const sets = [];
  const vals = [];
  let idx = 1;

  if (body.displayName !== undefined) { sets.push(`display_name = $${idx++}`); vals.push(body.displayName); }
  if (body.role !== undefined) { sets.push(`role = $${idx++}`); vals.push(body.role); }
  if (body.badge !== undefined) { sets.push(`badge = $${idx++}`); vals.push(body.badge); }
  if (body.password !== undefined) { sets.push(`password_hash = $${idx++}`); vals.push(sha256(body.password)); }
  if (body.permissions !== undefined) { sets.push(`permissions = $${idx++}`); vals.push(body.permissions); }

  if (sets.length === 0) return { status: 400, body: { error: 'No fields to update' } };

  vals.push(body.code);
  await pgPool.query(`UPDATE mods SET ${sets.join(', ')} WHERE code = $${idx}`, vals);
  await writeLog('mod_update', { code: body.code });
  return { status: 200, body: { ok: true } };
}

async function handleAdminModDelete(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.code) return { status: 400, body: { error: 'code required' } };
  await pgPool.query('DELETE FROM mods WHERE code = $1', [body.code]);
  await writeLog('mod_delete', { code: body.code });
  return { status: 200, body: { ok: true } };
}

async function handleAdminLogs(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const limit = body.limit || 100;
  const r = await pgPool.query('SELECT * FROM logs ORDER BY created_at DESC LIMIT $1', [limit]);
  return { status: 200, body: { logs: r.rows } };
}

async function handleAdminSettings(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };

  // If settings are provided, update them
  if (body.settings && typeof body.settings === 'object') {
    for (const [key, value] of Object.entries(body.settings)) {
      // Special case: admin_password should be hashed
      if (key === 'admin_password') {
        await setSetting(key, sha256(value));
      } else {
        await setSetting(key, value);
      }
    }
    await writeLog('settings_update', Object.keys(body.settings));
    return { status: 200, body: { ok: true } };
  }

  // Otherwise return all settings
  const r = await pgPool.query('SELECT key, value FROM settings ORDER BY key');
  const settings = {};
  for (const row of r.rows) {
    settings[row.key] = row.value;
  }
  return { status: 200, body: { settings } };
}

async function handleAdminTheme(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };

  // If theme data is provided, save it
  if (body.theme && typeof body.theme === 'object') {
    await setSetting('theme', JSON.stringify(body.theme));
    await writeLog('theme_update', {});
    // Broadcast theme to ALL connected clients via Socket.IO
    if (io) io.emit('theme-update', body.theme);
    return { status: 200, body: { ok: true } };
  }

  // Otherwise return current theme
  const raw = await getSetting('theme');
  let theme = {};
  if (raw) {
    try { theme = JSON.parse(raw); } catch (_) { /* ignore */ }
  }
  return { status: 200, body: { theme } };
}

async function handleAdminAnnounce(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.text) return { status: 400, body: { error: 'text required' } };

  const announcement = {
    type: 'announcement',
    text: body.text,
    ts: Date.now(),
  };

  if (body.roomId) {
    // Send to specific room
    await publishToRoom(String(body.roomId), announcement);
    // Messages not saved to DB
  } else {
    // Send to ALL rooms
    const rooms = await pgPool.query('SELECT id FROM rooms');
    for (const r of rooms.rows) {
      await publishToRoom(String(r.id), announcement);
      // Messages not saved to DB
    }
  }

  await writeLog('announcement', { text: body.text, roomId: body.roomId || 'all' });
  return { status: 200, body: { ok: true } };
}

// ---------------------------------------------------------------------------
//  HLS proxy (to MediaMTX on port 8888)
// ---------------------------------------------------------------------------

function proxyHls(req, res) {
  const targetPath = req.url; // e.g. /hls/stream/index.m3u8
  // WHIP/WHEP goes to WebRTC port 8889, everything else to HLS port 8888
  const isWebRTC = targetPath.includes('/whip') || targetPath.includes('/whep');
  const targetPort = isWebRTC ? 8889 : 8888;
  const options = {
    hostname: '127.0.0.1',
    port: targetPort,
    path: targetPath,
    method: req.method,
    headers: { ...req.headers, host: '127.0.0.1:' + targetPort },
  };

  const proxyReq = http.request(options, proxyRes => {
    setCors(res);
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res, { end: true });
  });

  proxyReq.on('error', () => {
    sendJson(res, 502, { error: 'HLS proxy error' });
  });

  req.pipe(proxyReq, { end: true });
}

// ---------------------------------------------------------------------------
//  Static file serving
// ---------------------------------------------------------------------------

function serveStaticFile(filePath, res) {
  const safePath = path.normalize(filePath).replace(/^(\.\.[/\\])+/, '');
  const fullPath = path.join(STATIC_DIR, safePath);

  // Prevent directory traversal outside STATIC_DIR
  if (!fullPath.startsWith(STATIC_DIR)) {
    sendJson(res, 403, { error: 'Forbidden' });
    return;
  }

  fs.stat(fullPath, (err, stats) => {
    if (err || !stats.isFile()) {
      sendJson(res, 404, { error: 'Not found' });
      return;
    }

    const ext = path.extname(fullPath).toLowerCase();
    const contentType = mimeType(ext);

    setCors(res);
    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(fullPath).pipe(res);
  });
}


// ---------------------------------------------------------------------------
//  API: Admin Data Management endpoints
// ---------------------------------------------------------------------------

async function handleAdminDataStats(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const usersCount = (await pgPool.query('SELECT COUNT(*)::int AS c FROM users')).rows[0].c;
  const messagesCount = (await pgPool.query("SELECT COUNT(*)::int AS c FROM messages WHERE msg_type = 'violation'")).rows[0].c;
  const logsCount = (await pgPool.query('SELECT COUNT(*)::int AS c FROM logs')).rows[0].c;
  const dbSizeRow = (await pgPool.query("SELECT pg_database_size(current_database()) AS s")).rows[0];
  const dbSizeMB = +(dbSizeRow.s / (1024 * 1024)).toFixed(2);
  const inactiveUsers = (await pgPool.query("SELECT COUNT(*)::int AS c FROM users WHERE last_seen < NOW() - INTERVAL '30 days'")).rows[0].c;
  const oldMessages = (await pgPool.query("SELECT COUNT(*)::int AS c FROM messages WHERE created_at < NOW() - INTERVAL '30 days'")).rows[0].c;
  const oldLogs = (await pgPool.query("SELECT COUNT(*)::int AS c FROM logs WHERE created_at < NOW() - INTERVAL '14 days'")).rows[0].c;
  let settings = { autoCleanEnabled: false, inactiveDays: 30, maxMessagesPerRoom: 10000, maxLogs: 5000, cleanIntervalHours: 24 };
  const cfgRow = await getSetting('cleanup_config');
  if (cfgRow) { try { settings = JSON.parse(cfgRow); } catch(_){} }
  return { status: 200, body: { usersCount, messagesCount, logsCount, dbSizeMB, inactiveUsers, oldMessages, oldLogs, settings } };
}

async function handleAdminDataSettings(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.settings || typeof body.settings !== 'object') return { status: 400, body: { error: 'settings object required' } };
  await setSetting('cleanup_config', JSON.stringify(body.settings));
  await writeLog('cleanup_settings_update', body.settings);
  return { status: 200, body: { ok: true } };
}

async function handleAdminDataInactiveUsers(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const days = parseInt(body.days) || 30;
  const r = await pgPool.query("SELECT username, display_name, last_seen, role FROM users WHERE last_seen < NOW() - INTERVAL '" + days + " days' ORDER BY last_seen ASC");
  return { status: 200, body: { users: r.rows } };
}

async function handleAdminDataDeleteUsers(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  if (!body.usernames || !Array.isArray(body.usernames) || !body.usernames.length) return { status: 400, body: { error: 'usernames array required' } };
  let deleted = 0;
  for (const u of body.usernames) {
    await pgPool.query('DELETE FROM messages WHERE username = $1', [u]);
    await pgPool.query('DELETE FROM device_tracks WHERE username = $1', [u]);
    const dr = await pgPool.query('DELETE FROM users WHERE username = $1', [u]);
    deleted += dr.rowCount;
    await removeFromAllRooms(u);
  }
  await writeLog('data_delete_users', { usernames: body.usernames, deleted });
  return { status: 200, body: { ok: true, deleted } };
}

async function handleAdminDataCleanMessages(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const days = parseInt(body.days) || 30;
  let r;
  if (body.roomId) {
    r = await pgPool.query("DELETE FROM messages WHERE created_at < NOW() - INTERVAL '" + days + " days' AND room_id = $1", [body.roomId]);
  } else {
    r = await pgPool.query('DELETE FROM messages WHERE created_at < NOW() - ($1 || \' days\')::INTERVAL', [days]);
  }
  await writeLog('data_clean_messages', { days, roomId: body.roomId || 'all', deleted: r.rowCount });
  return { status: 200, body: { ok: true, deleted: r.rowCount } };
}

async function handleAdminDataCleanLogs(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  const days = parseInt(body.days) || 14;
  const r = await pgPool.query('DELETE FROM logs WHERE created_at < NOW() - ($1 || \' days\')::INTERVAL', [days]);
  await writeLog('data_clean_logs', { days, deleted: r.rowCount });
  return { status: 200, body: { ok: true, deleted: r.rowCount } };
}

async function handleAdminDataCleanAll(body) {
  if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
  let settings = { autoCleanEnabled: false, inactiveDays: 30, maxMessagesPerRoom: 10000, maxLogs: 5000, cleanIntervalHours: 24 };
  const cfgRow = await getSetting('cleanup_config');
  if (cfgRow) { try { settings = JSON.parse(cfgRow); } catch(_){} }
  const inactiveDays = settings.inactiveDays || 30;
  const msgDays = 30;
  const logDays = 14;
  const delInactive = await pgPool.query("DELETE FROM users WHERE last_seen < NOW() - INTERVAL '" + inactiveDays + " days' AND role = 'guest'");
  const delMessages = await pgPool.query("DELETE FROM messages WHERE created_at < NOW() - INTERVAL '" + msgDays + " days'");
  const delLogs = await pgPool.query("DELETE FROM logs WHERE created_at < NOW() - INTERVAL '" + logDays + " days'");
  await writeLog('data_clean_all', { inactiveDeleted: delInactive.rowCount, messagesDeleted: delMessages.rowCount, logsDeleted: delLogs.rowCount });
  return { status: 200, body: { ok: true, inactiveDeleted: delInactive.rowCount, messagesDeleted: delMessages.rowCount, logsDeleted: delLogs.rowCount } };
}

// ---------------------------------------------------------------------------
//  Route dispatcher
// ---------------------------------------------------------------------------

const apiRoutes = {
  // Public
  '/api/mod-login': handleLogin,
  '/api/login': handleLogin,
  '/api/logout': handleLogout,
  '/api/send': handleSend,
  // heartbeat removed - Socket.IO handles connection state
  // poll removed - Socket.IO handles real-time messaging
  '/api/join-room': handleSwitchRoom,
  '/api/switch-room': handleSwitchRoom,
  '/api/rename-room': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Not authenticated' } };
    if (!hasModPerm(sess, 'canRenameRoom')) return { status: 403, body: { error: 'No permission' } };
    if (body.name) {
      await pgPool.query('UPDATE rooms SET name = $1 WHERE id = $2', [body.name, sess.roomId]);
      await publishToRoom(sess.roomId, { type: 'room-renamed', text: body.name, ts: Date.now() });
    }
    if (body.marquee !== undefined) {
      await pgPool.query('UPDATE rooms SET marquee = $1 WHERE id = $2', [body.marquee, sess.roomId]);
      await publishToRoom(sess.roomId, { type: 'marquee-update', text: body.marquee, ts: Date.now() });
    }
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/action': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Not authenticated' } };
    // Permission check
    if (body.action === 'kick' && !hasModPerm(sess, 'canKick')) return { status: 403, body: { error: 'No permission' } };
    if (body.action === 'ban' && !hasModPerm(sess, 'canBan')) return { status: 403, body: { error: 'No permission' } };
    if (body.action === 'mute' && !hasModPerm(sess, 'canMute')) return { status: 403, body: { error: 'No permission' } };
    const target = body.target;
    if (body.action === 'kick') {
      const keys = await redis.keys('session:*');
      for (const k of keys) { const s = JSON.parse(await redis.get(k)); if (s && s.username === target) { await redis.del(k); } }
      await removeOnlineUser(sess.roomId, target);
      await publishToRoom(sess.roomId, { type: 'system', text: target + ' تم طرده', ts: Date.now() });
      await writeLog('kick', sess.username + ' kicked ' + target);
    } else if (body.action === 'ban') {
      await pgPool.query('INSERT INTO bans (username, reason, banned_by) VALUES ($1, $2, $3)', [target, body.reason || '', sess.username]);
      await removeOnlineUser(sess.roomId, target);
      await publishToRoom(sess.roomId, { type: 'system', text: target + ' تم حظره', ts: Date.now() });
      await writeLog('ban', sess.username + ' banned ' + target);
    } else if (body.action === 'mute') {
      await publishToRoom(sess.roomId, { type: 'system', text: target + ' تم كتمه', ts: Date.now() });
    }
    return { status: 200, body: { ok: true } };
  },
  '/api/rules': async (body) => {
    const rules = await getSetting('chat_rules');
    return { status: 200, body: { rules: rules || '' } };
  },
  '/api/theme': async (body) => {
    const raw = await getSetting('theme');
    let theme = {};
    if (raw) { try { theme = JSON.parse(raw); } catch(_) {} }
    return { status: 200, body: { theme } };
  },
  '/api/signal': handleSignal,
  // Admin
  '/api/admin/login': handleAdminLogin,
  '/api/admin/stats': handleAdminStats,
  '/api/admin/server-health': handleAdminServerHealth,
  '/api/admin/users': handleAdminUsers,
  '/api/admin/user/role': handleAdminUserRole,
  '/api/admin/user/badge': handleAdminUserBadge,
  '/api/admin/user/kick': handleAdminUserKick,
  '/api/admin/user/note': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query("UPDATE users SET avatar_url = COALESCE(avatar_url,'') || $1 WHERE username = $2", [String.fromCharCode(10) + '[' + new Date().toLocaleDateString('ar') + '] ' + body.note, body.username]);
    await writeLog('user_note', JSON.stringify({username: body.username, note: body.note}));
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/user/delete': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query('DELETE FROM messages WHERE username = $1', [body.username]);
    await pgPool.query('DELETE FROM device_tracks WHERE username = $1', [body.username]);
    await pgPool.query('DELETE FROM users WHERE username = $1', [body.username]);
    await writeLog('user_delete', JSON.stringify({username: body.username}));
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/user/ban': handleAdminUserBan,
  '/api/admin/user/unban': handleAdminUserUnban,
  '/api/admin/bans': handleAdminBans,
  '/api/admin/rooms': handleAdminRooms,
  '/api/admin/room/create': handleAdminRoomCreate,
  '/api/admin/room/delete': handleAdminRoomDelete,
  '/api/admin/room/update': handleAdminRoomUpdate,
  '/api/admin/filter': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (body.action === 'get') {
      const words = await getFilteredWords();
      return { status: 200, body: { words } };
    }
    if (body.action === 'set') {
      await setSetting('filtered_words', JSON.stringify(body.words || []));
      return { status: 200, body: { ok: true } };
    }
    return { status: 400, body: { error: 'invalid action' } };
  },
  '/api/admin/device/lookup': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const username = body.username;
    // Find all fingerprints this user used
    const fps = await pgPool.query('SELECT DISTINCT fingerprint FROM device_tracks WHERE username = $1', [username]);
    const allNames = [];
    for (const fp of fps.rows) {
      const names = await pgPool.query('SELECT DISTINCT username FROM device_tracks WHERE fingerprint = $1 ORDER BY username', [fp.fingerprint]);
      names.rows.forEach(n => { if (!allNames.find(a => a.name === n.username)) allNames.push({name: n.username, fingerprint: fp.fingerprint}); });
    }
    // Get device info
    const devices = await pgPool.query('SELECT fingerprint, ip, user_agent, screen_size, platform, language, created_at FROM device_tracks WHERE username = $1 ORDER BY created_at DESC LIMIT 10', [username]);
    return { status: 200, body: { username, aliases: allNames, devices: devices.rows } };
  },
  '/api/admin/device/ban': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query('INSERT INTO device_bans (fingerprint, reason, banned_by) VALUES ($1, $2, $3) ON CONFLICT (fingerprint) DO NOTHING', [body.fingerprint, body.reason || '', 'admin']);
    await writeLog('device_ban', JSON.stringify({fingerprint: body.fingerprint, reason: body.reason}));
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/device/unban': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query('DELETE FROM device_bans WHERE fingerprint = $1', [body.fingerprint]);
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/device/bans': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const r = await pgPool.query('SELECT * FROM device_bans ORDER BY created_at DESC');
    return { status: 200, body: { bans: r.rows } };
  },
  '/api/admin/daily-stats': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const r = await pgPool.query("SELECT date, visitors, peak_online FROM daily_stats ORDER BY date DESC LIMIT 30");
    const today = await pgPool.query("SELECT COUNT(*)::int AS c FROM users WHERE last_seen >= CURRENT_DATE");
    const yesterday = await pgPool.query("SELECT COUNT(*)::int AS c FROM users WHERE last_seen >= CURRENT_DATE - 1 AND last_seen < CURRENT_DATE");
    const week = await pgPool.query("SELECT COUNT(*)::int AS c FROM users WHERE last_seen >= CURRENT_DATE - 7");
    const month = await pgPool.query("SELECT COUNT(*)::int AS c FROM users WHERE last_seen >= CURRENT_DATE - 30");
    return { status: 200, body: { days: r.rows, today: today.rows[0].c, yesterday: yesterday.rows[0].c, week: week.rows[0].c, month: month.rows[0].c } };
  },
  '/api/admin/mods': handleAdminMods,
  '/api/admin/mod/add': handleAdminModAdd,
  '/api/admin/mod/update': handleAdminModUpdate,
  '/api/admin/mod/delete': handleAdminModDelete,
  '/api/admin/logs': handleAdminLogs,
  '/api/admin/settings': handleAdminSettings,
  '/api/admin/theme': handleAdminTheme,
  '/api/admin/announce': handleAdminAnnounce,
  '/api/admin/data/stats': handleAdminDataStats,
  '/api/admin/data/settings': handleAdminDataSettings,
  '/api/admin/data/inactive-users': handleAdminDataInactiveUsers,
  '/api/admin/data/delete-users': handleAdminDataDeleteUsers,
  '/api/admin/data/clean-messages': handleAdminDataCleanMessages,
  '/api/admin/data/delete-all-logs': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const r = await pgPool.query('DELETE FROM logs');
    await writeLog('data_delete_all_logs', { deleted: r.rowCount });
    return { status: 200, body: { ok: true, deleted: r.rowCount } };
  },
  '/api/admin/data/clean-logs': handleAdminDataCleanLogs,
  '/api/admin/data/cleanup-config': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (body.config) {
      await setSetting('cleanup_config', JSON.stringify(body.config));
      return { status: 200, body: { ok: true } };
    }
    const raw = await getSetting('cleanup_config');
    return { status: 200, body: { config: raw ? JSON.parse(raw) : {} } };
  },
  '/api/admin/data/clean-all': handleAdminDataCleanAll,

  // === MODERATOR PERMISSIONS ===
  '/api/admin/mod/perms': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.username) return { status: 400, body: { error: 'username required' } };
    const perms = body.permissions || [];
    await pgPool.query('UPDATE mods SET permissions = $1 WHERE display_name = $2 OR code = $2', [perms, body.username]);
    await writeLog('mod_perms_update', { username: body.username, permissions: perms });
    return { status: 200, body: { ok: true } };
  },

  // === INVITE CODES ===
  '/api/admin/invite-codes': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const r = await pgPool.query('SELECT * FROM invite_codes ORDER BY created_at DESC');
    return { status: 200, body: { codes: r.rows } };
  },
  '/api/admin/invite-code/create': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const code = body.code || genId().substring(0, 8).toUpperCase();
    const maxUses = body.maxUses || 0;
    const expiresAt = body.expiresAt || null;
    await pgPool.query(
      'INSERT INTO invite_codes (code, max_uses, expires_at, created_by) VALUES ($1, $2, $3, $4)',
      [code, maxUses, expiresAt, 'admin']
    );
    await writeLog('invite_create', { code });
    return { status: 200, body: { ok: true, code } };
  },
  '/api/admin/invite-code/delete': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.code) return { status: 400, body: { error: 'code required' } };
    await pgPool.query('DELETE FROM invite_codes WHERE code = $1', [body.code]);
    await writeLog('invite_delete', { code: body.code });
    return { status: 200, body: { ok: true } };
  },

  // === RESET THEME ===
  '/api/admin/reset-theme': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await setSetting('theme', JSON.stringify({}));
    await writeLog('theme_reset', {});
    return { status: 200, body: { ok: true } };
  },

  // === ROOM PERMISSIONS ===
  '/api/admin/room/perms': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.roomId) return { status: 400, body: { error: 'roomId required' } };
    const sets = [];
    const vals = [];
    let idx = 1;
    if (body.mic_mode !== undefined) { sets.push('mic_mode = $' + idx++); vals.push(body.mic_mode); }
    if (body.cam_mode !== undefined) { sets.push('cam_mode = $' + idx++); vals.push(body.cam_mode); }
    if (body.chat_mode !== undefined) { sets.push('chat_mode = $' + idx++); vals.push(body.chat_mode); }
    if (body.password !== undefined) { sets.push('password = $' + idx++); vals.push(body.password || null); }
    if (body.max_users !== undefined) { sets.push('max_users = $' + idx++); vals.push(body.max_users); }
    if (sets.length === 0) return { status: 400, body: { error: 'No fields to update' } };
    vals.push(body.roomId);
    await pgPool.query('UPDATE rooms SET ' + sets.join(', ') + ' WHERE id = $' + idx, vals);
    await writeLog('room_perms_update', { roomId: body.roomId });
    return { status: 200, body: { ok: true } };
  },

  // === USER RESET PASSWORD ===
  '/api/admin/user/reset-password': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.username || !body.newPassword) return { status: 400, body: { error: 'username and newPassword required' } };
    const hash = sha256(body.newPassword);
    await pgPool.query('UPDATE users SET password_hash = $1 WHERE username = $2', [hash, body.username]);
    await writeLog('user_reset_password', { username: body.username });
    return { status: 200, body: { ok: true } };
  },

  // === USER TOGGLE (enable/disable) ===
  '/api/admin/user/toggle': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.username) return { status: 400, body: { error: 'username required' } };
    const r = await pgPool.query('SELECT enabled FROM users WHERE username = $1', [body.username]);
    if (!r.rows.length) return { status: 404, body: { error: 'User not found' } };
    const newState = !r.rows[0].enabled;
    await pgPool.query('UPDATE users SET enabled = $1 WHERE username = $2', [newState, body.username]);
    if (!newState) {
      // If disabling, kick them off
      const keys = await redis.keys('session:*');
      for (const k of keys) {
        try { const s = JSON.parse(await redis.get(k)); if (s && s.username === body.username) await redis.del(k); } catch(e) {}
      }
    }
    await writeLog('user_toggle', { username: body.username, enabled: newState });
    return { status: 200, body: { ok: true, enabled: newState } };
  },

  
  // ===== UNBLOCK ACTIONS =====
  // ===== UNBLOCK ACTIONS =====
  '/api/mod/chat-unblock': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canChatBlock')) return { status: 403, body: { error: 'No permission' } };
    await redis.del('chatblock:' + body.target);
    await publishToRoom(sess.roomId, { type: 'chat-unblocked', target: body.target, ts: Date.now() });
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' تم فك منع الكتابة عنه', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/mic-unblock': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canMicBlock')) return { status: 403, body: { error: 'No permission' } };
    await redis.del('micblock:' + body.target);
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' تم فك منع المايك عنه', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/cam-unblock': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canCamBlock')) return { status: 403, body: { error: 'No permission' } };
    await redis.del('camblock:' + body.target);
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' تم فك منع الكام عنه', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },

  // ===== EXTENDED MOD ACTIONS =====
  '/api/mod/warn': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canWarn')) return { status: 403, body: { error: 'No permission' } };
    const warnType = body.warnType || 'normal';
    const msg = body.message || '\u062a\u062d\u0630\u064a\u0631 \u0645\u0646 \u0627\u0644\u0645\u0634\u0631\u0641';
    const by = sess.displayName || sess.username;
    // Save to database
    await pgPool.query('INSERT INTO warnings (username, message, warn_type, warned_by) VALUES ($1, $2, $3, $4)', [body.target, msg, warnType, by]);
    // Count total warnings
    const countR = await pgPool.query('SELECT COUNT(*) as cnt FROM warnings WHERE username = $1', [body.target]);
    const totalWarnings = parseInt(countR.rows[0].cnt);
    // Send ONLY to the target user via Socket.IO
    if (io) {
      for (const [id, s] of io.sockets.sockets) {
        if (s.username === body.target) {
          s.emit('personal-warning', { message: msg, from: by, warnType: warnType, totalWarnings: totalWarnings, ts: Date.now() });
        }
      }
    }
    // Auto-ban after configurable warnings (default 5)
    if (warnType === 'final' || totalWarnings >= 5) {
      await pgPool.query('INSERT INTO bans (username, reason, banned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [body.target, '\u062a\u062c\u0627\u0648\u0632 \u0639\u062f\u062f \u0627\u0644\u062a\u062d\u0630\u064a\u0631\u0627\u062a (' + totalWarnings + ')', by]);
      // Kick them
      if (io) {
        for (const [id, s] of io.sockets.sockets) {
          if (s.username === body.target) { s.emit('kicked', { reason: '\u062a\u0645 \u062d\u0638\u0631\u0643 \u0628\u0639\u062f ' + totalWarnings + ' \u062a\u062d\u0630\u064a\u0631\u0627\u062a' }); s.disconnect(); }
        }
      }
    }
    // Log it (not broadcast to room)
    await writeLog('warn', { by: by, target: body.target, message: msg, type: warnType, total: totalWarnings });
    return { status: 200, body: { ok: true, totalWarnings: totalWarnings } };
  },
  '/api/mod/rename-user': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canRename')) return { status: 403, body: { error: 'No permission' } };
    const oldName = body.target;
    const newName = body.newName;
    // Update DB
    await pgPool.query('UPDATE users SET display_name = $1 WHERE username = $2 OR display_name = $2', [newName, oldName]);
    // Update all active sessions for this user
    const allKeys = await redis.keys('session:*');
    for (const k of allKeys) {
      try {
        const s = JSON.parse(await redis.get(k));
        if (s && (s.username === oldName || s.displayName === oldName)) {
          s.displayName = newName;
          s.username = newName;
          await redis.set(k, JSON.stringify(s), 'EX', SESSION_TTL);
        }
      } catch(e) {}
    }
    // Update online set
    if (sess.roomId) {
      await redis.srem('room:' + sess.roomId + ':online', oldName);
      await redis.sadd('room:' + sess.roomId + ':online', newName);
    }
    // Update Socket.IO username
    if (io) {
      for (const [id, s] of io.sockets.sockets) {
        if (s.username === oldName) { s.username = newName; s.displayName = newName; }
      }
    }
    // Broadcast name change so clients update their UI
    await publishToRoom(sess.roomId, { type: 'name-change', oldName: oldName, newName: newName, text: oldName + ' تم تغيير اسمه إلى ' + newName, ts: Date.now() });
    await writeLog('rename_user', { by: sess.username, target: oldName, newName: newName });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/badge': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canBadge')) return { status: 403, body: { error: 'No permission' } };
    await pgPool.query('UPDATE users SET badge = $1 WHERE username = $2 OR display_name = $2', [body.badge || '', body.target]);
    await writeLog('badge_change', { by: sess.username, target: body.target, badge: body.badge });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/chat-block': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canChatBlock')) return { status: 403, body: { error: 'No permission' } };
    // Store in Redis with TTL
    const duration = body.duration || 300; // 5 min default
    await redis.set('chatblock:' + body.target, '1', 'EX', duration);
    await publishToRoom(sess.roomId, { type: 'chat-blocked', target: body.target, duration: duration, ts: Date.now() });
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' تم منعه من الكتابة', ts: Date.now() });
    await writeLog('chat_block', { by: sess.username, target: body.target, duration });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/chat-lock': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canChatLock')) return { status: 403, body: { error: 'No permission' } };
    const lock = body.lock !== false;
    await redis.set('chatlock:' + sess.roomId, lock ? '1' : '0');
    await publishToRoom(sess.roomId, { type: 'system', text: lock ? 'تم قفل الكتابة في الغرفة' : 'تم فتح الكتابة في الغرفة', ts: Date.now() });
    await publishToRoom(sess.roomId, { type: 'chat-lock', locked: lock, ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/mic-off': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canMicOff')) return { status: 403, body: { error: 'No permission' } };
    await handleMicForceOff({ sessionId: body.sessionId, roomId: sess.roomId, targetUsername: body.target });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/mic-block': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canMicBlock')) return { status: 403, body: { error: 'No permission' } };
    await redis.set('micblock:' + body.target, '1');
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' تم منعه من المايك', ts: Date.now() });
    await writeLog('mic_block', { by: sess.username, target: body.target });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/cam-off': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canCamOff')) return { status: 403, body: { error: 'No permission' } };
    await redis.srem('room:' + sess.roomId + ':cams', body.target);
    await redis.del('stream:cam:' + body.target);
    await publishToRoom(sess.roomId, { type: 'cam-off', target: body.target, ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/cam-block': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canCamBlock')) return { status: 403, body: { error: 'No permission' } };
    await redis.set('camblock:' + body.target, '1');
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' تم منعه من الكام', ts: Date.now() });
    await writeLog('cam_block', { by: sess.username, target: body.target });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/device-ban': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canDeviceBan')) return { status: 403, body: { error: 'No permission' } };
    const tracks = await pgPool.query('SELECT fingerprint FROM device_tracks WHERE username = $1 ORDER BY created_at DESC LIMIT 1', [body.target]);
    if (!tracks.rows.length) return { status: 404, body: { error: 'No device found' } };
    const fp = tracks.rows[0].fingerprint;
    await pgPool.query('INSERT INTO device_bans (fingerprint, reason, banned_by) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING', [fp, 'Mod ban: ' + body.target, sess.username]);
    await writeLog('device_ban', { by: sess.username, target: body.target, fingerprint: fp });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/clear-chat': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canClearChat')) return { status: 403, body: { error: 'No permission' } };
    await publishToRoom(sess.roomId, { type: 'clear-chat', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/announce': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canAnnounce')) return { status: 403, body: { error: 'No permission' } };
    await publishToRoom(sess.roomId, { type: 'announcement', text: body.text, from: sess.displayName || sess.username, ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/pin-msg': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canPinMsg')) return { status: 403, body: { error: 'No permission' } };
    await pgPool.query('UPDATE rooms SET pinned_msg = $1 WHERE id = $2', [body.text || '', sess.roomId]);
    await publishToRoom(sess.roomId, { type: 'pinned-update', text: body.text || '', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/device-info': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canViewIP')) return { status: 403, body: { error: 'No permission' } };
    const tracks = await pgPool.query('SELECT fingerprint, ip, user_agent, screen_size, language, platform, created_at FROM device_tracks WHERE username = $1 ORDER BY created_at DESC LIMIT 5', [body.target]);
    return { status: 200, body: { devices: tracks.rows } };
  },


  '/api/mod/warnings': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canWarn') && !hasModPerm(sess, 'canViewIP')) return { status: 403, body: { error: 'No permission' } };
    const r = await pgPool.query('SELECT * FROM warnings WHERE username = $1 ORDER BY created_at DESC', [body.target]);
    return { status: 200, body: { warnings: r.rows } };
  },
  '/api/mod/delete-warning': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canWarn')) return { status: 403, body: { error: 'No permission' } };
    await pgPool.query('DELETE FROM warnings WHERE id = $1', [body.warningId]);
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/clear-warnings': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canWarn')) return { status: 403, body: { error: 'No permission' } };
    await pgPool.query('DELETE FROM warnings WHERE username = $1', [body.target]);
    return { status: 200, body: { ok: true } };
  },
  '/api/check-warnings': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth required' } };
    const username = sess.displayName || sess.username;
    const r = await pgPool.query('SELECT id, message, warn_type, warned_by, created_at FROM warnings WHERE username = $1 AND seen = false ORDER BY created_at DESC', [username]);
    if (r.rows.length > 0) {
      await pgPool.query('UPDATE warnings SET seen = true WHERE username = $1 AND seen = false', [username]);
    }
    return { status: 200, body: { warnings: r.rows } };
  },
  '/api/mod/check-blocks': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    const t = body.target;
    const mb = await redis.get('micblock:' + t);
    const cb = await redis.get('camblock:' + t);
    const chb = await redis.get('chatblock:' + t);
    return { status: 200, body: { micBlocked: !!mb, camBlocked: !!cb, chatBlocked: !!chb } };
  },
  '/api/mod/mic-unblock': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canMicBlock')) return { status: 403, body: { error: 'No perm' } };
    await redis.del('micblock:' + body.target);
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' \u062a\u0645 \u0641\u0643 \u0645\u0646\u0639 \u0627\u0644\u0645\u0627\u064a\u0643', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/cam-unblock': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canCamBlock')) return { status: 403, body: { error: 'No perm' } };
    await redis.del('camblock:' + body.target);
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' \u062a\u0645 \u0641\u0643 \u0645\u0646\u0639 \u0627\u0644\u0643\u0627\u0645', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/mod/chat-unblock': async (body) => {
    const sess = await getSession(body.sessionId);
    if (!sess) return { status: 401, body: { error: 'Auth' } };
    if (!hasModPerm(sess, 'canChatBlock')) return { status: 403, body: { error: 'No perm' } };
    await redis.del('chatblock:' + body.target);
    await publishToRoom(sess.roomId, { type: 'system', text: body.target + ' \u062a\u0645 \u0641\u0643 \u0645\u0646\u0639 \u0627\u0644\u0643\u062a\u0627\u0628\u0629', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },

  // ===== SUBSCRIPTION APIs =====
  '/api/admin/sub/plans': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const r = await pgPool.query('SELECT * FROM sub_plans ORDER BY sort_order');
    return { status: 200, body: { plans: r.rows } };
  },
  '/api/admin/sub/plan/create': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query(
      'INSERT INTO sub_plans (name, name_ar, price, currency, duration_days, badge, role, color, features, sort_order, enabled) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [body.name||'', body.nameAr||'', body.price||0, body.currency||'SAR', body.durationDays||30, body.badge||'', body.role||'vip', body.color||'#ffd700', JSON.stringify(body.features||[]), body.sortOrder||0, true]
    );
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/sub/plan/update': async (body) => {
      if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
      if (!body.id) return { status: 400, body: { error: 'id required' } };
      var sets = [], vals = [], idx = 1;
      var m = {name:'name',nameAr:'name_ar',price:'price',currency:'currency',durationDays:'duration_days',badge:'badge',role:'role',color:'color',sortOrder:'sort_order',enabled:'enabled'};
      for (var k in m) { if (body[k] !== undefined) { sets.push(m[k]+'=$'+idx); vals.push(body[k]); idx++; } }
      if (body.features !== undefined) { sets.push('features=$'+idx); vals.push(JSON.stringify(body.features)); idx++; }
      if (!sets.length) return { status: 400, body: { error: 'No fields' } };
      vals.push(body.id);
      await pgPool.query('UPDATE sub_plans SET '+sets.join(',')+' WHERE id=$'+idx, vals);
      return { status: 200, body: { ok: true } };
    },
    '/api/admin/sub/plan/delete': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query('DELETE FROM sub_plans WHERE id=$1', [body.id]);
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/sub/activate': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.username || !body.planId) return { status: 400, body: { error: 'username and planId required' } };
    const plan = await pgPool.query('SELECT * FROM sub_plans WHERE id=$1', [body.planId]);
    if (!plan.rows.length) return { status: 404, body: { error: 'Plan not found' } };
    const p = plan.rows[0];
    const days = body.days || p.duration_days;
    const expires = new Date(); expires.setDate(expires.getDate() + days);
    await pgPool.query(
      'INSERT INTO user_subs (username, plan_id, expires_at, activated_by) VALUES ($1,$2,$3,$4)',
      [body.username, body.planId, expires, 'admin']
    );
    await pgPool.query('UPDATE users SET role=$1, badge=$2 WHERE username=$3 OR display_name=$3', [p.role, p.badge, body.username]);
    await writeLog('sub_activate', { username: body.username, plan: p.name, days });
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/sub/deactivate': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query("UPDATE user_subs SET status='expired' WHERE username=$1 AND status='active'", [body.username]);
    await pgPool.query("UPDATE users SET role='guest', badge='' WHERE username=$1 OR display_name=$1", [body.username]);
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/sub/subscribers': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const r = await pgPool.query("SELECT us.*, sp.name as plan_name, sp.name_ar as plan_name_ar, sp.color as plan_color FROM user_subs us JOIN sub_plans sp ON us.plan_id=sp.id WHERE us.status='active' ORDER BY us.created_at DESC");
    return { status: 200, body: { subscribers: r.rows } };
  },
  '/api/sub/plans': async (body) => {
    const r = await pgPool.query('SELECT id, name, name_ar, price, currency, duration_days, badge, color, features FROM sub_plans WHERE enabled=true ORDER BY sort_order');
    return { status: 200, body: { plans: r.rows } };
  },


  // ===== SITE SETTINGS =====
  '/api/admin/site-settings': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (body.settings) {
      for (const [k, v] of Object.entries(body.settings)) {
        await setSetting('site_' + k, typeof v === 'string' ? v : JSON.stringify(v));
      }
      return { status: 200, body: { ok: true } };
    }
    // Get all site settings
    const keys = ['site_name', 'site_description', 'site_keywords', 'site_topbar_link', 'site_topbar_text', 'site_welcome'];
    const result = {};
    for (const k of keys) {
      const v = await getSetting(k);
      result[k.replace('site_', '')] = v || '';
    }
    return { status: 200, body: result };
  },
  '/api/site-info': async (body) => {
    const name = await getSetting('site_name') || 'سعودي كام';
    const description = await getSetting('site_description') || '';
    const keywords = await getSetting('site_keywords') || '';
    const topbarText = await getSetting('site_topbar_text') || 'ksacam.com';
    const topbarLink = await getSetting('site_topbar_link') || 'https://ksacam.com/';
    const welcome = await getSetting('site_welcome') || '\u0627\u062F\u062E\u0644 \u0627\u0633\u0645\u0643 \u0648\u0627\u0628\u062F\u0623 \u0627\u0644\u0645\u062D\u0627\u062F\u062B\u0629';
    return { status: 200, body: { name, description, keywords, topbarText, topbarLink, welcome } };
  },

  // ===== ROLES MANAGEMENT =====
  '/api/admin/roles': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const r = await pgPool.query('SELECT * FROM roles ORDER BY priority DESC');
    return { status: 200, body: { roles: r.rows } };
  },
  '/api/admin/role/create': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.name) return { status: 400, body: { error: 'name required' } };
    await pgPool.query(
      'INSERT INTO roles (name, name_ar, color, icon, priority) VALUES ($1, $2, $3, $4, $5)',
      [body.name, body.nameAr || body.name, body.color || '#888', body.icon || '', body.priority || 0]
    );
    return { status: 200, body: { ok: true } };
  },
    '/api/admin/role/update': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.id) return { status: 400, body: { error: 'id required' } };
    var updates = [];
    var values = [];
    var i = 1;
    if (body.name !== undefined) { updates.push('name=$' + i); i += 1; values.push(body.name); }
    if (body.nameAr !== undefined) { updates.push('name_ar=$' + i); i += 1; values.push(body.nameAr); }
    if (body.color !== undefined) { updates.push('color=$' + i); i += 1; values.push(body.color); }
    if (body.icon !== undefined) { updates.push('icon=$' + i); i += 1; values.push(body.icon); }
    if (body.priority !== undefined) { updates.push('priority=$' + i); i += 1; values.push(body.priority); }
    if (!updates.length) return { status: 400, body: { error: 'nothing to update' } };
    values.push(body.id);
    await pgPool.query('UPDATE roles SET ' + updates.join(',') + ' WHERE id=$' + i, values);
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/role/delete': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.id) return { status: 400, body: { error: 'id required' } };
    var rr = await pgPool.query('SELECT is_system FROM roles WHERE id=', [body.id]);
    if (rr.rows[0] && rr.rows[0].is_system) return { status: 400, body: { error: 'Cannot delete system role' } };
    await pgPool.query('DELETE FROM roles WHERE id= AND is_system=false', [body.id]);
    return { status: 200, body: { ok: true } };
  },
  '/api/roles': async (body) => {
    var r = await pgPool.query('SELECT name, name_ar, color, icon, priority FROM roles ORDER BY priority DESC');
    return { status: 200, body: { roles: r.rows } };
  },
  '/api/mic/request': handleMicRequest,
  '/api/mic/release': handleMicRelease,
  '/api/mic/force-off': handleMicForceOff,
  '/api/mic/queue/approve': handleMicQueueApprove,
  '/api/mic/queue/deny': handleMicQueueDeny,
  '/api/mic/queue/remove': handleMicQueueRemove,
  '/api/mic/speakers': handleMicSpeakers,
  
  '/api/admin/room/pinned': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (!body.roomId) return { status: 400, body: { error: 'roomId required' } };
    await pgPool.query('UPDATE rooms SET pinned_msg = $1 WHERE id = $2', [body.text || '', body.roomId]);
    if (io) io.to('room:' + body.roomId).emit('room-message', { type: 'pinned-update', text: body.text || '', ts: Date.now() });
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/room/mic-settings': handleAdminMicSettings,
  '/api/admin/rental/add': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query('INSERT INTO room_rentals (username, room_name, price, currency, start_date, end_date, notes) VALUES ($1,$2,$3,$4,$5,$6,$7)', [body.username||'', body.roomName||'', body.price||0, body.currency||'SAR', body.startDate||new Date(), body.endDate||null, body.notes||'']);
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/rentals': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const r = await pgPool.query('SELECT * FROM room_rentals ORDER BY end_date ASC');
    return { status: 200, body: { rentals: r.rows } };
  },
  '/api/admin/rental/update': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    const sets = []; const vals = []; let idx = 1;
    if (body.price !== undefined) { sets.push('price=$'+idx++); vals.push(body.price); }
    if (body.endDate !== undefined) { sets.push('end_date=$'+idx++); vals.push(body.endDate); }
    if (body.notes !== undefined) { sets.push('notes=$'+idx++); vals.push(body.notes); }
    if (body.roomName !== undefined) { sets.push('room_name=$'+idx++); vals.push(body.roomName); }
    if (!sets.length) return { status: 400, body: { error: 'No fields' } };
    vals.push(body.id);
    await pgPool.query('UPDATE room_rentals SET '+sets.join(',')+' WHERE id=$'+idx, vals);
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/rental/delete': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    await pgPool.query('DELETE FROM room_rentals WHERE id=$1', [body.id]);
    return { status: 200, body: { ok: true } };
  },
  '/api/admin/rental/notify': async (body) => {
    if (!(await verifyAdmin(body.token))) return { status: 401, body: { error: 'Unauthorized' } };
    if (io) { for (const [sid, sock] of io.sockets.sockets) { if (sock.username === body.username) { sock.emit('room-message', { type: 'warning', target: body.username, text: body.message || 'تنبيه', ts: Date.now() }); break; } } }
    return { status: 200, body: { ok: true } };
  },
};

async function handleRequest(req, res) {
  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = urlObj.pathname;

  // CORS preflight
  if (req.method === 'OPTIONS') {
    setCors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  // HLS proxy
  if (pathname.startsWith('/hls/')) {
    proxyHls(req, res);
    return;
  }

  // API routes (POST only)
  if (req.method === 'POST' && apiRoutes[pathname]) {
    try {
      const body = await parseBody(req);
      body._realIp = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
      body._reqIp = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
      const result = await apiRoutes[pathname](body);
      sendJson(res, result.status, result.body);
    } catch (err) {
      log(`API error on ${pathname}: ${err.message}`);
      sendJson(res, 500, { error: 'Internal server error' });
    }
    return;
  }

  // Static files (GET)
  if (req.method === 'GET') {
    if (pathname === '/' || pathname === '/index.html') {
      serveStaticFile('web-chat.html', res);
      return;
    }
    if (pathname === '/admin' || pathname === '/admin.html') {
      serveStaticFile('admin.html', res);
      return;
    }
    // Serve any other static file from STATIC_DIR
    serveStaticFile(pathname.substring(1), res);
    return;
  }

  // Fallback 404
  sendJson(res, 404, { error: 'Not found' });
}

// ---------------------------------------------------------------------------
//  Server startup and graceful shutdown
// ---------------------------------------------------------------------------

const server = http.createServer(handleRequest);


// ---------------------------------------------------------------------------
//  Socket.IO Real-time Handler
// ---------------------------------------------------------------------------

function setupSocketIO(sio) {
  sio.on('connection', async (socket) => {
    const sessionId = socket.handshake.auth && socket.handshake.auth.sessionId;
    if (!sessionId) { socket.disconnect(); return; }

    const sess = await getSession(sessionId);
    if (!sess) { socket.emit('auth-error', { error: 'Session expired' }); socket.disconnect(); return; }

    const username = sess.displayName || sess.username;
    socket.username = username;
    socket.sessionId = sessionId;
    socket.userRole = sess.role;
    socket.userBadge = sess.badge || '';
    socket.currentRoomId = sess.roomId;

    if (!userSockets.has(username)) userSockets.set(username, new Set());
    userSockets.get(username).add(socket.id);

    log('Socket connected: ' + username + ' (' + socket.id + ')');

    // Join current room
    if (sess.roomId) {
      socket.join('room:' + sess.roomId);
      await addOnlineUser(sess.roomId, username, sess.role, sess.badge);
      await publishToRoom(sess.roomId, {
        type: 'join', from: username, text: username + ' \u062f\u062e\u0644 \u0627\u0644\u063a\u0631\u0641\u0629',
        ts: Date.now(), timestamp: Date.now()
      });

      const onlineUsers = await getOnlineUsers(sess.roomId);
      const roomRow = await pgPool.query('SELECT name, marquee, icon, pinned_msg FROM rooms WHERE id = $1', [sess.roomId]);
      const roomsAll = await getAllRoomsWithCounts();
      socket.emit('init-data', {
        users: onlineUsers, rooms: roomsAll,
        roomName: roomRow.rows[0] ? roomRow.rows[0].name : '',
        marquee: roomRow.rows[0] ? roomRow.rows[0].marquee : '',
        role: sess.role
      });
    }

    // SEND MESSAGE
    socket.on('send-message', async (data, ack) => {
      try {
        const s = await getSession(socket.sessionId);
        if (!s || !s.roomId) { if (ack) ack({error:'Not in room'}); return; }
        const text = sanitize((data.text || '').trim().substring(0, 5000));
        if (!text) { if (ack) ack({error:'Empty'}); return; }
        // Check chat-block
        const isChatBlocked = await redis.get('chatblock:' + socket.username);
        if (isChatBlocked) { if (ack) ack({error:'تم منعك من الكتابة'}); return; }
        // Check chat-lock
        const isChatLocked = await redis.get('chatlock:' + s.roomId);
        if (isChatLocked === '1' && s.role !== 'admin' && s.role !== 'owner' && s.role !== 'mod') { if (ack) ack({error:'الكتابة مقفلة في الغرفة'}); return; }
        const filteredWords = await getFilteredWords();
        const blocked = checkFilter(text, filteredWords);
        if (blocked) {
          await writeLog('violation', JSON.stringify({username: socket.username, word: blocked}));
          if (ack) ack({error: '\u0627\u0644\u0631\u0633\u0627\u0644\u0629 \u062a\u062d\u062a\u0648\u064a \u0639\u0644\u0649 \u0643\u0644\u0645\u0629 \u0645\u0645\u0646\u0648\u0639\u0629: ' + blocked});
          return;
        }
        const isPrivate = !!data.private;
        const target = data.target || null;
        const replyTo = data.replyTo || null;
        const msgObj = {
          type: isPrivate ? 'private' : 'chat',
          from: socket.username, username: socket.username,
          role: s.role, badge: s.badge, text, target,
          replyTo: replyTo,
          timestamp: Date.now(), ts: Date.now()
        };

        if (isPrivate && target) {
          // PRIVATE: only sender + target see it (in fasl)
          socket.emit('room-message', { ...msgObj, type: 'private-sent' });
          // Find target socket and send
          if (io) {
            for (var [_sid, _sock] of io.sockets.sockets) {
              if (_sock.username === target) {
                _sock.emit('room-message', { ...msgObj, type: 'private' });
                break;
              }
            }
          }
        } else if (target && !isPrivate) {
          // MENTION: public for others, fasl only for sender+target
          // Send to everyone in room EXCEPT sender and target
          if (io) {
            for (var [_sid3, _sock3] of io.sockets.sockets) {
              if (_sock3.username && _sock3.username !== socket.username && _sock3.username !== target) {
                _sock3.emit('room-message', msgObj);
              }
            }
          }
          // Save to DB
          // Messages not saved to DB
          // Send to target's fasl only
          if (io && target !== socket.username) {
            for (var [_sid2, _sock2] of io.sockets.sockets) {
              if (_sock2.username === target) {
                _sock2.emit('room-message', {
                  type: 'mention-notify',
                  from: socket.username,
                  target: target,
                  text: text,
                  ts: Date.now()
                });
                break;
              }
            }
          }
          // Send to sender's fasl only
          socket.emit('room-message', {
            type: 'mention-sent',
            from: socket.username,
            target: target,
            text: text,
            ts: Date.now()
          });
        } else {
          // NORMAL: public message to all
          await publishToRoom(s.roomId, msgObj);
          // Messages not saved to DB
        }
        if (ack) ack({ok:true});
      } catch(e) { log('send-message error: ' + e.message); if (ack) ack({error:e.message}); }
    });

    // JOIN/SWITCH ROOM
    socket.on('join-room', async (data, ack) => {
      try {
        const s = await getSession(socket.sessionId);
        if (!s) { if (ack) ack({error:'Auth'}); return; }
        const newRoomId = String(data.roomId);
        const roomCheck = await pgPool.query('SELECT * FROM rooms WHERE id = $1', [newRoomId]);
        if (!roomCheck.rows.length) { if (ack) ack({error:'Room not found'}); return; }

        if (socket.currentRoomId) {
          socket.leave('room:' + socket.currentRoomId);
          await removeOnlineUser(socket.currentRoomId, socket.username);
          await redis.srem('room:' + socket.currentRoomId + ':cams', socket.username);
          await redis.srem('room:' + socket.currentRoomId + ':mics', socket.username);
          await redis.del('stream:cam:' + socket.username);
          await redis.del('stream:mic:' + socket.username);
          await cleanupMicOnLeave(socket.currentRoomId, socket.username, socket.sessionId);
          await publishToRoom(socket.currentRoomId, {
            type: 'leave', from: socket.username,
            text: socket.username + ' \u063a\u0627\u062f\u0631 \u0627\u0644\u063a\u0631\u0641\u0629',
            ts: Date.now(), timestamp: Date.now()
          });
          const oldOnline = await getOnlineUsers(socket.currentRoomId);
          sio.to('room:' + socket.currentRoomId).emit('users-update', oldOnline);
        }

        socket.currentRoomId = newRoomId;
        socket.join('room:' + newRoomId);
        await updateSession(socket.sessionId, { roomId: newRoomId });
        await addOnlineUser(newRoomId, socket.username, s.role, s.badge);
        await publishToRoom(newRoomId, {
          type: 'join', from: socket.username,
          text: socket.username + ' \u062f\u062e\u0644 \u0627\u0644\u063a\u0631\u0641\u0629',
          ts: Date.now(), timestamp: Date.now()
        });

        const room = roomCheck.rows[0];
        const onlineUsers = await getOnlineUsers(newRoomId);
        const roomsAll = await getAllRoomsWithCounts();
        sio.emit('rooms-update', roomsAll);

        if (ack) ack({
          ok: true,
          room: { id: room.id, name: room.name, marquee: room.marquee, icon: room.icon, pinned_msg: room.pinned_msg || "" },
          onlineUsers, rooms: roomsAll
        });
      } catch(e) { log('join-room error: ' + e.message); if (ack) ack({error:e.message}); }
    });

    // MIC REQUEST
    socket.on('mic-request', async (data, ack) => {
      try {
        const result = await handleMicRequest({ sessionId: socket.sessionId, roomId: socket.currentRoomId });
        if (ack) ack(result.body);
      } catch(e) { if (ack) ack({error:e.message}); }
    });

    // MIC RELEASE
    socket.on('mic-release', async (data, ack) => {
      try {
        const result = await handleMicRelease({ sessionId: socket.sessionId, roomId: socket.currentRoomId });
        if (ack) ack(result.body);
      } catch(e) { if (ack) ack({error:e.message}); }
    });

    // SIGNAL (WebRTC)
    socket.on('signal', async (data) => {
      try {
        const result = await handleSignal({ sessionId: socket.sessionId, ...data });
        if (result.body && (result.body.approved || result.body.queued || result.body.denied)) {
          socket.emit('signal-response', result.body);
        }
      } catch(e) { log('signal error: ' + e.message); }
    });

    // HAND RAISE/LOWER
    socket.on('hand-raise', async () => {
      if (socket.currentRoomId) {
        await publishToRoom(socket.currentRoomId, {
          type: 'hand-raise', from: socket.username, ts: Date.now(), timestamp: Date.now()
        });
      }
    });
    socket.on('hand-lower', async () => {
      if (socket.currentRoomId) {
        await publishToRoom(socket.currentRoomId, {
          type: 'hand-lower', from: socket.username, ts: Date.now(), timestamp: Date.now()
        });
      }
    });

    // MOD ACTIONS
    socket.on('mod-action', async (data, ack) => {
      try {
        const s = await getSession(socket.sessionId);
        if (!s) return;
        const target = data.target;
        if (data.action === 'kick') {
          const ts2 = userSockets.get(target);
          if (ts2) { for (const sid of ts2) { const sk = sio.sockets.sockets.get(sid); if (sk) { sk.emit('kicked'); sk.disconnect(); } } }
          await removeOnlineUser(s.roomId, target);
          await publishToRoom(s.roomId, { type: 'system', text: target + ' \u062a\u0645 \u0637\u0631\u062f\u0647', ts: Date.now() });
          await writeLog('kick', s.username + ' kicked ' + target);
        } else if (data.action === 'ban') {
          await pgPool.query('INSERT INTO bans (username, reason, banned_by) VALUES ($1, $2, $3)', [target, data.reason || '', s.username]);
          const ts2 = userSockets.get(target);
          if (ts2) { for (const sid of ts2) { const sk = sio.sockets.sockets.get(sid); if (sk) { sk.emit('banned'); sk.disconnect(); } } }
          await removeOnlineUser(s.roomId, target);
          await publishToRoom(s.roomId, { type: 'system', text: target + ' \u062a\u0645 \u062d\u0638\u0631\u0647', ts: Date.now() });
          await writeLog('ban', s.username + ' banned ' + target);
        } else if (data.action === 'mute') {
          await publishToRoom(s.roomId, { type: 'system', text: target + ' \u062a\u0645 \u0643\u062a\u0645\u0647', ts: Date.now() });
        }
        if (ack) ack({ok:true});
      } catch(e) { if (ack) ack({error:e.message}); }
    });

    // RENAME ROOM
    socket.on('rename-room', async (data) => {
      const s = await getSession(socket.sessionId);
      if (!s) return;
      if (data.name) {
        await pgPool.query('UPDATE rooms SET name = $1 WHERE id = $2', [data.name, s.roomId]);
        await publishToRoom(s.roomId, { type: 'room-renamed', text: data.name, ts: Date.now() });
      }
      if (data.marquee !== undefined) {
        await pgPool.query('UPDATE rooms SET marquee = $1 WHERE id = $2', [data.marquee, s.roomId]);
        await publishToRoom(s.roomId, { type: 'marquee-update', text: data.marquee, ts: Date.now() });
      }
    });

    // DISCONNECT
    socket.on('disconnect', async (reason) => {
      log('Socket disconnected: ' + socket.username + ' (' + reason + ')');
      const sockets = userSockets.get(socket.username);
      if (sockets) {
        sockets.delete(socket.id);
        if (sockets.size === 0) {
          userSockets.delete(socket.username);
          if (socket.currentRoomId) {
            await removeOnlineUser(socket.currentRoomId, socket.username);
            await redis.srem('room:' + socket.currentRoomId + ':cams', socket.username);
            await redis.srem('room:' + socket.currentRoomId + ':mics', socket.username);
            await redis.del('stream:cam:' + socket.username);
            await redis.del('stream:mic:' + socket.username);
            await cleanupMicOnLeave(socket.currentRoomId, socket.username, socket.sessionId);
            await publishToRoom(socket.currentRoomId, {
              type: 'leave', from: socket.username,
              text: socket.username + ' \u063a\u0627\u062f\u0631 \u0627\u0644\u063a\u0631\u0641\u0629',
              ts: Date.now(), timestamp: Date.now()
            });
            const onlineUsers = await getOnlineUsers(socket.currentRoomId);
            sio.to('room:' + socket.currentRoomId).emit('users-update', onlineUsers);
            const roomsAll = await getAllRoomsWithCounts();
            sio.emit('rooms-update', roomsAll);
          }
        }
      }
    });
  });
}

// Helper: get all rooms with online counts
async function getAllRoomsWithCounts() {
  const rr = await pgPool.query('SELECT id, name, icon FROM rooms ORDER BY name');
  const result = [];
  for (const r of rr.rows) {
    const cnt = await getOnlineCount(String(r.id));
    result.push({ id: r.id, name: r.name, icon: r.icon, online: cnt || 0 });
  }
  return result.sort((a, b) => b.online - a.online);
}


async function start() {
  try {
    // Connect Redis clients
    await redis.connect();
    log('Redis command client connected');
    await redisSub.connect();
    log('Redis subscriber client connected');

    // Test PostgreSQL
    const pgTest = await pgPool.query('SELECT NOW()');
    log(`PostgreSQL connected – server time: ${pgTest.rows[0].now}`);

    // Ensure default admin password setting exists
    const existingPw = await getSetting('admin_password');
    if (!existingPw) {
      await setSetting('admin_password', ADMIN_PASSWORD_DEFAULT_HASH);
      log('Default admin password set');
    }

    // Initialise pub/sub listener
    initPubSub();

    // Subscribe to all existing rooms
    const rooms = await pgPool.query('SELECT id FROM rooms');
    for (const r of rooms.rows) {
      await subscribeRoom(String(r.id));
    }
    log(`Subscribed to ${rooms.rows.length} room channel(s)`);

    // Setup Socket.IO
    io = new SocketServer(server, {
      cors: { origin: '*', methods: ['GET', 'POST'] },
      pingTimeout: 30000,
      pingInterval: 15000,
      transports: ['websocket', 'polling']
    });
    setupSocketIO(io);

    // Start HTTP server
    server.listen(PORT, '127.0.0.1', () => {
      log(`Chat server v2 listening on http://localhost:${PORT}`);
      log(`Admin panel: http://localhost:${PORT}/admin`);
      log('Socket.IO enabled');

    });
  } catch (err) {
    log(`Startup error: ${err.message}`);
    process.exit(1);
  }
}

async function shutdown(signal) {
  log(`Received ${signal}, shutting down gracefully...`);

  // Close HTTP server (stop accepting new connections)
  server.close(() => {
    log('HTTP server closed');
  });

  // Close Socket.IO connections
  if (io) { io.close(); log('Socket.IO closed'); }

  try {
    // Disconnect Redis
    redisSub.disconnect();
    redis.disconnect();
    log('Redis clients disconnected');
  } catch (_) { /* ignore */ }

  try {
    // Close PostgreSQL pool
    await pgPool.end();
    log('PostgreSQL pool closed');
  } catch (_) { /* ignore */ }

  log('Shutdown complete');
  process.exit(0);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// Catch unhandled errors so the server stays up
process.on('uncaughtException', err => {
  log(`Uncaught exception: ${err.message}\n${err.stack}`);
});
process.on('unhandledRejection', reason => {
  log(`Unhandled rejection: ${reason}`);
});

// Sync mic state with actual online users every 15 seconds
setInterval(async () => {
  try {
    for (const [roomId, state] of roomMicState) {
      // Check each active speaker is still online
      for (const [sid, info] of state.activeSpeakers) {
        const isOnline = await redis.sismember('room:' + roomId + ':online', info.username);
        if (!isOnline) {
          // Speaker left without releasing mic - clean up
          log('Mic cleanup: removing ghost speaker ' + info.username + ' from room ' + roomId);
          clearMicTimers(info);
          state.activeSpeakers.delete(sid);
          await redis.srem('room:' + roomId + ':mics', info.username);
          await redis.del('stream:mic:' + info.username);
          await broadcastSpeakerList(roomId);
          await autoPromoteFromQueue(roomId);
        }
      }
      // Check queue members too
      var validQueue = [];
      for (var qi = 0; qi < state.queue.length; qi++) {
        var q = state.queue[qi];
        var qOnline = await redis.sismember('room:' + roomId + ':online', q.username);
        if (qOnline) validQueue.push(q);
      }
      state.queue = validQueue;
    }
  } catch(e) { log('Mic sync error: ' + e.message); }
}, 15000);

// Socket.IO handles connection state - cleanup stale Redis entries every 60s
setInterval(async () => {
  try {
    if (!io) return;
    const roomKeys = await redis.keys('room:*:online');
    for (const key of roomKeys) {
      const members = await redis.smembers(key);
      const roomId = key.replace(':online', '').replace('room:', '');
      for (const member of members) {
        const sockets = userSockets.get(member);
        if (!sockets || sockets.size === 0) {
          await redis.srem(key, member);
          await redis.srem('room:' + roomId + ':cams', member);
          await redis.srem('room:' + roomId + ':mics', member);
          await redis.del('stream:cam:' + member);
          await redis.del('stream:mic:' + member);
          await redis.del('user:role:' + member);
          await cleanupMicOnLeave(roomId, member, null);
          await publishToRoom(roomId, { type: 'leave', from: member, text: member + ' \u063a\u0627\u062f\u0631 \u0627\u0644\u063a\u0631\u0641\u0629', ts: Date.now(), timestamp: Date.now() });
        }
      }
    }
  } catch(e) { log('Ghost cleanup error: ' + e.message); }
}, 60000);


// AUTO_CLEANUP - runs every 6 hours
setInterval(async () => {
  try {
    const cfg = await getSetting('cleanup_config');
    const settings = cfg ? JSON.parse(cfg) : {};
    if (!settings.autoEnabled) return;
    const logDays = settings.logDays || 14;
    const msgDays = settings.msgDays || 30;
    const inactiveDays = settings.inactiveDays || 60;
    // Clean old logs
    await pgPool.query("DELETE FROM logs WHERE created_at < NOW() - INTERVAL '" + logDays + " days'");
    // Clean old messages
    await pgPool.query("DELETE FROM messages WHERE created_at < NOW() - INTERVAL '" + msgDays + " days'");
    // Clean inactive users
    if (settings.cleanInactive) {
      await pgPool.query("DELETE FROM users WHERE last_seen < NOW() - INTERVAL '" + inactiveDays + " days' AND role = 'guest'");
    }
    log('Auto-cleanup completed: logs>' + logDays + 'd, msgs>' + msgDays + 'd');
  } catch(e) { log('Auto-cleanup error: ' + e.message); }
}, 6 * 60 * 60 * 1000); // Every 6 hours

// Launch
start();
