/**
 * NKP Ludo Pro — Server v5.7 PROTECTED (Render.com) — app v1.27 के लिए
 * सुविधाएँ: ऑनलाइन 2-4 खिलाड़ी रूम, नाम/नाम बदलना, चैट+रिपोर्ट, emoji reactions,
 * stickers, anti-cheat जाँच, /health, /api/version, /privacy
 * Zero external dependencies — raw Node.js + hand-rolled WebSocket.
 *
 * APIs:
 *   GET  /health                       — health check (+ razorpay config status)
 *   GET  /api/razorpay/status          — ★ LIVE Razorpay keys check (browser में खोलें)
 *   GET  /api/razorpay/log             — ★ last 100 payment events (debug)
 *   POST /api/razorpay/webhook         — ★ Razorpay Dashboard webhook receiver (payment.captured)
 *   GET  /api/wake                     — wake-up ping
 *   POST /api/register                 — {username, password} → {ok, token}
 *   POST /api/login                    — {username, password} → {ok, token}
 *   GET  /api/profile                  — (Bearer) → {ok, profile}
 *   PUT  /api/profile                  — (Bearer) save profile (anti-cheat clamped)
 *   GET  /api/leaderboard             — top players
 *   POST /api/razorpay/create-order    — create Razorpay order
 *   POST /api/razorpay/verify-payment  — verify payment signature (+credit account)
 *
 * WS /ws message types:
 *   auth, createRoom, joinRoom, rejoin, quickMatch, gameMove, gameState,
 *   diceRoll, tokenMove, turnChange, chat, friendAdd, friendInvite
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// === CONFIG ===
const PORT = process.env.PORT || 3000;
// v5.7 सुरक्षा: भुगतान (Razorpay) पूरी तरह बंद — ऐप अब payment नहीं लेता।
// ★ कोई भी key/पासवर्ड कोड में नहीं रखा जाता — सब सिर्फ़ Render Environment से पढ़े जाते हैं।
const RAZORPAY_KEYS_FROM_ENV = false;
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const RAZORPAY_WEBHOOK_SECRET = process.env.RAZORPAY_WEBHOOK_SECRET || '';

// ★★ आपकी अपनी key — Render → Environment → ADMIN_KEY में डालें (कोड में कभी नहीं) ★★
// इससे आपका निजी admin पेज खुलेगा: /api/admin/stats?key=आपकी-key
const ADMIN_KEY = process.env.ADMIN_KEY || '';
function adminOk(req, url) {
  try {
    const k = (url && url.searchParams.get('key')) || req.headers['x-admin-key'] || '';
    return !!(ADMIN_KEY && k && k === ADMIN_KEY);
  } catch (e) { return false; }
}
// chat सफ़ाई (लिंक/नंबर/ईमेल हटाना) — client के साथ मिलता-जुलता
function safeChat(t) {
  try {
    let x = String(t || '');
    x = x.replace(/(https?:\/\/|www\.)[^\s]+/gi, '🚫(लिंक हटाया)');
    x = x.replace(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi, '🚫(ईमेल हटाया)');
    x = x.replace(/(\+?\d[\d\s-]{8,}\d)/g, '🚫(नंबर हटाया)');
    return x.slice(0, 60);
  } catch (e) { return String(t || '').slice(0, 60); }
}
function maskKey(k) { return k ? k.slice(0, 8) + '****' + k.slice(-4) : '(empty)'; }
function rzpMode() { return /live/i.test(RAZORPAY_KEY_ID) ? 'LIVE' : 'TEST'; }

// In-memory payment event log (last 100) — GET /api/razorpay/log
const PAY_LOG = [];
function payLog(entry) {
  entry.at = new Date().toISOString();
  PAY_LOG.unshift(entry);
  if (PAY_LOG.length > 100) PAY_LOG.pop();
  console.log('[PAY]', JSON.stringify(entry));
  // restart/sleep के बाद भी log बचा रहे (best-effort)
  try { if (DB) { DB.payLog = PAY_LOG.slice(0, 100); saveDB(); } } catch (e) {}
}
// Idempotency: webhook में एक ही payment दो बार credit न हो
const PROCESSED_PAYMENTS = new Set();

// === PERSISTENCE (best-effort disk; Render free tier is ephemeral) ===
const DATA_FILE = path.join('/tmp', 'nkp_data.json');
let DB = { users: {}, friends: {}, purchases: [] };

function loadDB() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      DB = JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
      if (!DB.users) DB.users = {};
      if (!DB.friends) DB.friends = {};
      if (!DB.purchases) DB.purchases = [];
    }
  } catch (e) { console.log('DB load failed, starting fresh:', e.message); }
}
let dbSaveTimer = null;
function saveDB() {
  if (dbSaveTimer) return;
  dbSaveTimer = setTimeout(() => {
    dbSaveTimer = null;
    try { fs.writeFileSync(DATA_FILE, JSON.stringify(DB)); } catch (e) {}
  }, 2000);
}
loadDB();
try { if (Array.isArray(DB.payLog)) PAY_LOG.push(...DB.payLog); } catch (e) {}

// === AUTH HELPERS ===
const tokens = new Map(); // token → username
function hashPassword(pw, salt) {
  return crypto.scryptSync(pw, salt, 32).toString('hex');
}
function makeToken() {
  return crypto.randomBytes(32).toString('hex');
}
function userFromToken(token) {
  if (!token) return null;
  return tokens.get(token) || null;
}
function publicUser(u) {
  return {
    username: u.username,
    coins: u.coins, gems: u.gems, totalEarned: u.totalEarned,
    gamesWon: u.gamesWon, gamesLost: u.gamesLost, gamesPlayed: u.gamesPlayed,
    playerLevel: u.playerLevel, playerXP: u.playerXP,
    friends: DB.friends[u.username] || []
  };
}

// === HTTP HELPERS ===
function readBody(req, raw) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => { body += chunk; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => {
      if (raw) { resolve(body); return; }
      try { resolve(JSON.parse(body)); } catch (e) { resolve({}); }
    });
  });
}
function sendJSON(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  });
  res.end(JSON.stringify(data));
}

function razorpayRequest(endpoint, method, body) {
  return new Promise((resolve, reject) => {
    const auth = Buffer.from(RAZORPAY_KEY_ID + ':' + RAZORPAY_KEY_SECRET).toString('base64');
    const isGet = (method || 'GET').toUpperCase() === 'GET';
    const postData = isGet ? '' : JSON.stringify(body || {});
    const options = {
      hostname: 'api.razorpay.com',
      path: '/v1/' + endpoint,
      method: method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + auth,
      },
    };
    if (!isGet) options.headers['Content-Length'] = Buffer.byteLength(postData);
    const rq = https.request(options, (rs) => {
      let data = '';
      rs.on('data', chunk => { data += chunk; });
      rs.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (typeof parsed === 'object' && parsed !== null) parsed._httpStatus = rs.statusCode;
          resolve(parsed);
        } catch (e) { resolve({ error: { description: 'parse error', raw: data }, _httpStatus: rs.statusCode }); }
      });
    });
    rq.on('error', (e) => { reject(e); });
    if (!isGet) rq.write(postData);
    rq.end();
  });
}

// === PURCHASE COVER — sync के वक़्त Razorpay से पूछकर असली खरीद पकड़ो ===
// verify-payment छूट जाए / DB wipe हो जाए — तब भी खरीदे coins कटने न पाएँ।
// सिर्फ़ UNPAID order कभी cover नहीं होगा (Razorpay से status देखकर)।
async function purchaseCoverFor(uname) {
  const out = { coins: 0, gems: 0 };
  const now = Date.now();
  for (const p of DB.purchases) {
    if (!p || p.username !== uname || p.covered || !p.orderId) continue;
    if (now - (p.at || 0) > 48 * 3600 * 1000) { p.covered = true; continue; } // बासी record — दोबारा न देखो
    try {
      const pays = await razorpayRequest('orders/' + p.orderId + '/payments', 'GET', null);
      const items = Array.isArray(pays) ? pays : (pays && pays.items) || [];
      const paid = items.some(function (x) { return x && (x.status === 'captured' || x.status === 'authorized'); });
      if (paid) { out.coins += (p.coins || 0); out.gems += (p.gems || 0); payLog({ type: 'purchase_covered', orderId: p.orderId, coins: p.coins || 0, gems: p.gems || 0, username: uname }); }
      p.covered = true; // एक बार check — अगली बार skip
    } catch (e) { /* नेटवर्क issue — अगली sync में फिर try होगा */ }
  }
  if (out.coins || out.gems) saveDB();
  return out;
}

// === HTTP SERVER ===
const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') { sendJSON(res, 200, { ok: true }); return; }

  const url = new URL(req.url, 'http://localhost:' + PORT);
  const reqPath = url.pathname;
  const method = req.method;

  // v5.7: भुगतान से जुड़े सारे पुराने रास्ते बंद (ऐप अब payment नहीं लेता)
  if (reqPath.indexOf('/api/razorpay') === 0) {
    sendJSON(res, 410, { ok: false, message: 'भुगतान बंद कर दिया गया है — ऐप अब पैसे नहीं लेता।' });
    return;
  }

  // v5.7: आपका निजी admin पेज (सिर्फ़ आपकी ADMIN_KEY से खुलेगा)
  if (reqPath === '/api/admin/stats' && method === 'GET') {
    if (!ADMIN_KEY) { sendJSON(res, 403, { ok: false, message: 'Render → Environment में ADMIN_KEY डालें (अपनी key)' }); return; }
    if (!adminOk(req, url)) { sendJSON(res, 403, { ok: false, message: 'गलत key' }); return; }
    let roomsCount = 0;
    try { roomsCount = rooms.size; } catch (e) {}
    sendJSON(res, 200, {
      ok: true, serverVersion: '5.13', uptime: Math.round(process.uptime()),
      users: Object.keys(DB.users || {}).length,
      rooms: roomsCount,
      onlineClients: wsClients ? wsClients.size : 0,
      reports: Array.isArray(DB.reports) ? DB.reports.length : 0
    });
    return;
  }
  if (reqPath === '/api/admin/reports' && method === 'GET') {
    if (!ADMIN_KEY) { sendJSON(res, 403, { ok: false, message: 'Render → Environment में ADMIN_KEY डालें (अपनी key)' }); return; }
    if (!adminOk(req, url)) { sendJSON(res, 403, { ok: false, message: 'गलत key' }); return; }
    const list = Array.isArray(DB.reports) ? DB.reports.slice(-100) : [];
    sendJSON(res, 200, { ok: true, count: list.length, reports: list });
    return;
  }

  // --- HEALTH ---
  if (reqPath === '/health' && method === 'GET') {
    sendJSON(res, 200, {
      ok: true, uptime: process.uptime(), users: Object.keys(DB.users).length,
      serverVersion: '5.13',
      payments: 'disabled',
      protections: {
        adminKey: ADMIN_KEY ? 'set' : 'not_set',
        rateLimit: 'on',
        chatFilter: 'on',
        turnValidation: 'on'
      },
      admin: ADMIN_KEY ? 'ready — /api/admin/stats?key=...' : 'Render Environment में ADMIN_KEY डालें (अपनी key)'
    });
    return;
  }

  // --- ★ LIVE RAZORPAY KEYS CHECK (browser में खोलें) ---
  if (reqPath === '/api/razorpay/status' && method === 'GET') {
    if (!RAZORPAY_KEYS_FROM_ENV) {
      sendJSON(res, 200, {
        ok: false, problem: 'ENV_NOT_SET',
        keyId: maskKey(RAZORPAY_KEY_ID), mode: rzpMode(),
        message: 'Render Environment में RAZORPAY_KEY_ID और RAZORPAY_KEY_SECRET set नहीं हैं। Server पुरानी expired TEST keys use कर रहा है — Razorpay हर request reject कर रहा है। Render → Environment में दोनों keys (कोई space/quote नहीं) डालें, Save करें और redeploy होने दें।'
      });
      return;
    }
    try {
      const test = await razorpayRequest('orders?count=1', 'GET', null);
      if (test.error) {
        sendJSON(res, 200, {
          ok: false, problem: test._httpStatus === 401 || /auth/i.test(test.error.description || '') ? 'KEYS_INVALID' : 'RAZORPAY_ERROR',
          keyId: maskKey(RAZORPAY_KEY_ID), mode: rzpMode(), httpStatus: test._httpStatus,
          razorpayError: test.error.description || test.error.code,
          message: (test._httpStatus === 401 || /auth/i.test(test.error.description || '')) ? 'Keys पहचानी नहीं गईं (Authentication failed)। Razorpay Dashboard → Settings → API Keys से Live Key ID + Secret दोबारा copy करें (Secret सिर्फ़ एक बार दिखता है) और Render Environment में बिल्कुल वैसे ही paste करें।' : ('Razorpay ने error दिया: ' + (test.error.description || test.error.code))
        });
        return;
      }
      sendJSON(res, 200, {
        ok: true, problem: null,
        keyId: maskKey(RAZORPAY_KEY_ID), mode: rzpMode(), httpStatus: test._httpStatus,
        webhookSecretSet: !!RAZORPAY_WEBHOOK_SECRET,
        message: '✅ Razorpay keys VALID हैं — payment बनना चाहिए। अगर अब भी checkout न खुले तो: (1) LIVE mode में Razorpay account का KYC complete होना चाहिए (Dashboard → Home देखें)। (2) app में coin pack दबाने पर /api/razorpay/create-order बुलाया जाता है — वो log में दिखेगा। (3) जाँच के लिए /api/razorpay/log खोलें।'
      });
    } catch (e) {
      sendJSON(res, 200, { ok: false, problem: 'NETWORK', message: 'api.razorpay.com से server connect नहीं कर पाया: ' + e.message });
    }
    return;
  }

  // --- ★ PAYMENT EVENT LOG ---
  if (reqPath === '/api/razorpay/log' && method === 'GET') {
    sendJSON(res, 200, { ok: true, count: PAY_LOG.length, events: PAY_LOG });
    return;
  }

  // --- ★ RAZORPAY WEBHOOK (Dashboard → Settings → Webhooks) ---
  if (reqPath === '/api/razorpay/webhook' && method === 'POST') {
    try {
      const raw = await readBody(req, true);
      if (!RAZORPAY_WEBHOOK_SECRET) {
        payLog({ type: 'webhook_rejected', reason: 'RAZORPAY_WEBHOOK_SECRET not set in Render Environment' });
        sendJSON(res, 200, { ok: true, note: 'webhook received but RAZORPAY_WEBHOOK_SECRET not set — credit नहीं हुआ' });
        return;
      }
      const sig = crypto.createHmac('sha256', RAZORPAY_WEBHOOK_SECRET).update(raw).digest('hex');
      if (sig !== (req.headers['x-razorpay-signature'] || '')) {
        payLog({ type: 'webhook_rejected', reason: 'signature mismatch' });
        sendJSON(res, 401, { ok: false, error: 'Invalid webhook signature' });
        return;
      }
      const evt = JSON.parse(raw);
      payLog({ type: 'webhook', event: evt.event });
      if (evt.event === 'payment.captured') {
        const p = evt.payload && evt.payload.payment && evt.payload.payment.entity;
        if (p && p.id && !PROCESSED_PAYMENTS.has(p.id)) {
          PROCESSED_PAYMENTS.add(p.id);
          // order के notes से username + coins निकालो
          try {
            const ord = await razorpayRequest('orders/' + p.order_id, 'GET', null);
            const uname = ord.notes && String(ord.notes.username || '').toLowerCase();
            const coins = parseInt(String((ord.notes && ord.notes.coins) || '0'), 10) || 0;
            const gems = parseInt(String((ord.notes && ord.notes.gems) || '0'), 10) || 0;
            if (uname && DB.users[uname] && (coins > 0 || gems > 0) && coins <= 100000 && gems <= 100000) {
              if (coins > 0) {
                DB.users[uname].coins += coins;
                DB.users[uname].purchaseCredit = (DB.users[uname].purchaseCredit || 0) + coins;
              }
              if (gems > 0) {
                DB.users[uname].gems = (DB.users[uname].gems || 0) + gems;
                DB.users[uname].purchaseGemsCredit = (DB.users[uname].purchaseGemsCredit || 0) + gems;
              }
              saveDB();
              payLog({ type: 'webhook_credit', paymentId: p.id, username: uname, coins, gems, amount: p.amount / 100 });
            } else {
              payLog({ type: 'webhook_nocredit', paymentId: p.id, reason: uname ? 'user not found / coins+gems = 0' : 'order notes missing username' });
            }
          } catch (e) {
            payLog({ type: 'webhook_order_fetch_failed', paymentId: p.id, error: e.message });
          }
        }
      }
      sendJSON(res, 200, { ok: true });
    } catch (e) {
      payLog({ type: 'webhook_error', error: e.message });
      sendJSON(res, 200, { ok: true }); // webhook को हमेशा 200 दें वरना Razorpay बार-बार retry करता है
    }
    return;
  }

  if (reqPath === '/api/version' && method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, versionCode: 53, versionName: '1.38' }));
    return;
  }
  if (reqPath === '/api/wake' && method === 'GET') {
    sendJSON(res, 200, { ok: true, awake: true, ts: Date.now() });
    return;
  }

  // --- REGISTER ---
  if (reqPath === '/api/register' && method === 'POST') {
    const b = await readBody(req);
    const username = String(b.username || '').trim().toLowerCase();
    const password = String(b.password || '');
    if (username.length < 3 || username.length > 20 || !/^[a-z0-9_]+$/.test(username)) {
      sendJSON(res, 400, { ok: false, error: 'Invalid username (3-20 chars, a-z 0-9 _)' }); return;
    }
    if (password.length < 4) { sendJSON(res, 400, { ok: false, error: 'Password too short (min 4)' }); return; }
    if (DB.users[username]) { sendJSON(res, 409, { ok: false, error: 'Username already taken' }); return; }
    const salt = crypto.randomBytes(16).toString('hex');
    DB.users[username] = {
      username, salt, hash: hashPassword(password, salt),
      coins: 0, gems: 0, totalEarned: 0,
      gamesWon: 0, gamesLost: 0, gamesPlayed: 0,
      playerLevel: 1, playerXP: 0, createdAt: Date.now()
    };
    DB.friends[username] = [];
    const token = makeToken();
    tokens.set(token, username);
    saveDB();
    sendJSON(res, 200, { ok: true, token, username });
    return;
  }

  // --- LOGIN ---
  if (reqPath === '/api/login' && method === 'POST') {
    const b = await readBody(req);
    const username = String(b.username || '').trim().toLowerCase();
    const password = String(b.password || '');
    const u = DB.users[username];
    if (!u || hashPassword(password, u.salt) !== u.hash) {
      sendJSON(res, 401, { ok: false, error: 'Wrong username/password' }); return;
    }
    const token = makeToken();
    tokens.set(token, username);
    sendJSON(res, 200, { ok: true, token, username });
    return;
  }

  // --- PROFILE (GET) ---
  if (reqPath === '/api/profile' && method === 'GET') {
    const uname = userFromToken((req.headers.authorization || '').replace('Bearer ', '').trim());
    if (!uname) { sendJSON(res, 401, { ok: false, error: 'Not authenticated' }); return; }
    sendJSON(res, 200, { ok: true, profile: publicUser(DB.users[uname]) });
    return;
  }

  // --- PROFILE (PUT) — anti-cheat clamped sync (purchase-safe) ---
  if (reqPath === '/api/profile' && method === 'PUT') {
    const uname = userFromToken((req.headers.authorization || '').replace('Bearer ', '').trim());
    if (!uname) { sendJSON(res, 401, { ok: false, error: 'Not authenticated' }); return; }
    const u = DB.users[uname];
    const b = await readBody(req);
    // Anti-cheat: coins/gems may only grow by 5000/200 per sync — पर verified purchase कभी नहीं कटेगा
    const growth = (Number(b.coins) || 0) - (u.coins || 0);
    if (growth <= 5000 && growth >= -100000) u.coins = Math.max(0, Math.floor(Number(b.coins) || 0));
    else if (growth > 5000) {
      let covered = (u.purchaseCredit || 0);
      if (growth > 5000 + covered) covered += (await purchaseCoverFor(uname)).coins; // ★ Razorpay से पूछकर असली खरीद cover करो
      if (growth <= 5000 + covered) { u.coins = Math.max(0, Math.floor(Number(b.coins) || 0)); u.purchaseCredit = Math.max(0, covered - growth); }
      else {
        u.coins = (u.coins || 0) + 5000; // reject suspicious jump
        payLog({ type: 'sync_cut', username: uname, sentCoins: b.coins, keptCoins: u.coins, reason: 'growth > 5000 + purchase cover' });
      }
    }
    const gGem = (Number(b.gems) || 0) - (u.gems || 0);
    if (gGem <= 200) u.gems = Math.max(0, Math.floor(Number(b.gems) || 0));
    else {
      let coveredG = (u.purchaseGemsCredit || 0);
      if (gGem > 200 + coveredG) coveredG += (await purchaseCoverFor(uname)).gems;
      if (gGem <= 200 + coveredG) { u.gems = Math.max(0, Math.floor(Number(b.gems) || 0)); u.purchaseGemsCredit = Math.max(0, coveredG - gGem + 200); }
      else {
        u.gems = (u.gems || 0) + 200; // reject suspicious jump
        payLog({ type: 'sync_cut_gems', username: uname, sentGems: b.gems, keptGems: u.gems });
      }
    }
    // stats: monotonic (can only increase)
    u.gamesWon = Math.max(u.gamesWon || 0, Math.floor(Number(b.gamesWon) || 0));
    u.gamesLost = Math.max(u.gamesLost || 0, Math.floor(Number(b.gamesLost) || 0));
    u.gamesPlayed = Math.max(u.gamesPlayed || 0, Math.floor(Number(b.gamesPlayed) || 0));
    u.totalEarned = Math.max(u.totalEarned || 0, Math.floor(Number(b.totalEarned) || 0));
    u.playerLevel = Math.max(u.playerLevel || 1, Math.floor(Number(b.playerLevel) || 1));
    u.playerXP = Math.max(u.playerXP || 0, Math.floor(Number(b.playerXP) || 0));
    u.lastSync = Date.now();
    saveDB();
    sendJSON(res, 200, { ok: true, profile: publicUser(u) });
    return;
  }

  // --- LEADERBOARD ---
  if (reqPath === '/api/leaderboard' && method === 'GET') {
    const limit = Math.min(50, parseInt(url.searchParams.get('limit') || '20', 10) || 20);
    const top = Object.values(DB.users)
      .sort((a, b) => (b.gamesWon || 0) - (a.gamesWon || 0) || (b.totalEarned || 0) - (a.totalEarned || 0))
      .slice(0, limit)
      .map(u => ({ username: u.username, gamesWon: u.gamesWon || 0, totalEarned: u.totalEarned || 0, level: u.playerLevel || 1 }));
    sendJSON(res, 200, { ok: true, leaderboard: top });
    return;
  }

  // --- RAZORPAY: CREATE ORDER ---
  if (reqPath === '/api/razorpay/create-order' && method === 'POST') {
    try {
      const b = await readBody(req);
      const amount = Math.floor(Number(b.amount) || 0); // rupees
      if (amount < 10) { payLog({ type: 'create_order_rejected', reason: 'amount < 10', amount }); sendJSON(res, 400, { ok: false, error: 'Invalid amount' }); return; }
      if (!RAZORPAY_KEYS_FROM_ENV) payLog({ type: 'create_order_warning', reason: 'ENV_NOT_SET — payment नहीं बनेगा' });
      const order = await razorpayRequest('orders', 'POST', {
        amount: amount * 100, currency: 'INR',
        receipt: 'nkp_' + Date.now(),
        notes: { coins: String(b.coins || 0), gems: String(b.gems || 0), username: String(b.username || '') }
      });
      if (order.error) {
        payLog({ type: 'create_order_failed', httpStatus: order._httpStatus, razorpayError: order.error.description || order.error.code });
        sendJSON(res, 500, {
          ok: false,
          error: order.error.description || 'Order failed',
          problem: /auth/i.test(order.error.description || '') ? 'KEYS_INVALID' : 'RAZORPAY_ERROR',
          solution: /auth/i.test(order.error.description || '') ? 'Render Environment में Razorpay keys गलत/पुरानी हैं — /api/razorpay/status खोलकर देखें।' : 'Razorpay Dashboard देखें या /api/razorpay/status खोलें।'
        });
        return;
      }
      payLog({ type: 'create_order_ok', orderId: order.id, amount, coins: b.coins || 0, gems: b.gems || 0 });
      // ★ purchase record — ताकि sync के वक़्त खरीद cover हो सके (verify छूट जाए तब भी)
      DB.purchases.push({ username: String(b.username || '').toLowerCase(), coins: Math.floor(Number(b.coins) || 0), gems: Math.floor(Number(b.gems) || 0), amount, orderId: order.id, at: Date.now(), covered: false });
      if (DB.purchases.length > 300) DB.purchases = DB.purchases.slice(-300);
      saveDB();
      sendJSON(res, 200, { ok: true, orderId: order.id, amount: order.amount, keyId: RAZORPAY_KEY_ID });
    } catch (e) {
      sendJSON(res, 500, { ok: false, error: 'Order creation failed: ' + e.message });
    }
    return;
  }

  // --- RAZORPAY: VERIFY PAYMENT ---
  if (reqPath === '/api/razorpay/verify-payment' && method === 'POST') {
    try {
      const b = await readBody(req);
      const body = b.order_id + '|' + b.payment_id;
      const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(body).digest('hex');
      if (expected === b.signature) {
        payLog({ type: 'verify_ok', orderId: b.order_id, paymentId: b.payment_id, coins: b.coins, gems: b.gems, username: b.username });
        // credit server-side account if authenticated
        const uname = userFromToken((req.headers.authorization || '').replace('Bearer ', '').trim()) ||
          (b.username ? String(b.username).toLowerCase() : null);
        const coins = parseInt(String(b.coins || '0'), 10) || 0;
        const gems = parseInt(String(b.gems || '0'), 10) || 0;
        if (uname && DB.users[uname] && (coins > 0 || gems > 0) && coins <= 100000 && gems <= 100000) {
          if (coins > 0) {
            DB.users[uname].coins += coins;
            DB.users[uname].purchaseCredit = (DB.users[uname].purchaseCredit || 0) + coins;
          }
          if (gems > 0) {
            DB.users[uname].gems = (DB.users[uname].gems || 0) + gems;
            DB.users[uname].purchaseGemsCredit = (DB.users[uname].purchaseGemsCredit || 0) + gems;
          }
          saveDB();
        }
        DB.purchases.push({ username: uname, coins, gems, amount: b.amount || 0, paymentId: b.payment_id, orderId: b.order_id, at: Date.now(), covered: true });
        saveDB();
        sendJSON(res, 200, { ok: true, verified: true, credited: !!(uname && (coins > 0 || gems > 0)) });
      } else {
        payLog({ type: 'verify_failed', reason: 'signature mismatch', orderId: b.order_id });
        sendJSON(res, 400, { ok: false, error: 'Invalid signature' });
      }
    } catch (e) {
      sendJSON(res, 500, { ok: false, error: 'Verification failed' });
    }
    return;
  }

  // --- STATIC (public folder if present) ---
  if (method === 'GET' && !reqPath.startsWith('/api/')) {
    try {
      let filePath = path.join(__dirname, 'public', reqPath === '/' ? 'index.html' : reqPath);
      if (!path.extname(filePath)) filePath += '.html'; // /privacy -> privacy.html
      if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
        const ext = path.extname(filePath).toLowerCase();
        const mimes = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.png': 'image/png', '.wav': 'audio/wav', '.json': 'application/json' };
        res.writeHead(200, { 'Content-Type': mimes[ext] || 'application/octet-stream' });
        fs.createReadStream(filePath).pipe(res);
        return;
      }
    } catch (e) {}
  }

  sendJSON(res, 404, { error: 'Not found', path: reqPath });
});

// ============================================================
// WEBSOCKET SERVER (raw upgrade — no external deps)
// ============================================================
const wsClients = new Map();   // socket → { roomId, playerNumber, name, username }
const rooms = new Map();
// v5.11: हर seat का default रंग (खिलाड़ी बदल भी सकता है)
const SEAT_DEFAULT_COLORS = ['RED', 'YELLOW', 'GREEN', 'BLUE'];
function nkpColorFor(pn) { return SEAT_DEFAULT_COLORS[((Number(pn) || 1) - 1 + 4) % 4]; }       // roomId → { players: [ {playerNumber, name, socket, seatToken} ], password, currentTurn, started }
const matchQueue = [];         // quick match queue

// ---- v3: online players list broadcast ----
function broadcastOnlineList() {
  try {
    const list = [];
    wsClients.forEach((info, sock) => {
      if (!info.roomId && info.name && !sock._closed) list.push({ id: sock._nkpId, name: info.name });
    });
    wsClients.forEach((info, sock) => {
      if (!info.roomId && !sock._closed) wsSendSafe(sock, { type: 'onlinePlayers', players: list, me: sock._nkpId });
    });
  } catch (e) {}
}
setInterval(broadcastOnlineList, 8000);

function roomBroadcast(room, msg, exceptSocket) {
  if (!room) return;
  room.players.forEach(p => {
    if (p.socket && p.socket !== exceptSocket && !p.socket._closed) {
      wsSendSafe(p.socket, msg);
    }
  });
}
function makeRoomId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let id = '';
  for (let i = 0; i < 5; i++) id += chars[Math.floor(Math.random() * chars.length)];
  return rooms.has(id) ? makeRoomId() : id;
}

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url, 'http://localhost:' + PORT);
  if (url.pathname !== '/ws') { socket.destroy(); return; }
  const key = req.headers['sec-websocket-key'];
  if (!key) { socket.destroy(); return; }

  const acceptKey = crypto.createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    'Sec-WebSocket-Accept: ' + acceptKey + '\r\n\r\n'
  );

  let buffer = Buffer.alloc(0);
  socket._closed = false;
  socket._nkpId = crypto.randomBytes(4).toString('hex'); // v3: lobby invite के लिए unique ID

  function wsSend(wsSocket, msg) {
    try {
      const payloadBuf = Buffer.from(JSON.stringify(msg), 'utf-8');
      let header;
      if (payloadBuf.length < 126) {
        header = Buffer.alloc(2);
        header[0] = 0x81; header[1] = payloadBuf.length;
      } else if (payloadBuf.length < 65536) {
        header = Buffer.alloc(4);
        header[0] = 0x81; header[1] = 126;
        header.writeUInt16BE(payloadBuf.length, 2);
      } else {
        header = Buffer.alloc(10);
        header[0] = 0x81; header[1] = 127;
        header.writeBigUInt64BE(BigInt(payloadBuf.length), 2);
      }
      wsSocket.write(Buffer.concat([header, payloadBuf]));
    } catch (e) { /* client gone */ }
  }

  function parseFrames() {
    while (buffer.length >= 2) {
      const op = buffer[0] & 0x0f;
      const masked = (buffer[1] & 0x80) !== 0;
      let len = buffer[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (buffer.length < 4) return; len = buffer.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buffer.length < 10) return; len = Number(buffer.readBigUInt64BE(2)); off = 10; }
      let maskKey = null;
      if (masked) { if (buffer.length < off + 4) return; maskKey = buffer.slice(off, off + 4); off += 4; }
      if (buffer.length < off + len) return;
      let payload = buffer.slice(off, off + len);
      if (maskKey) {
        for (let i = 0; i < payload.length; i++) payload[i] ^= maskKey[i % 4];
      }
      buffer = buffer.slice(off + len);
      if (op === 0x8) { // close
        socket._closed = true;
        try { socket.end(); } catch (e) {}
        handleDisconnect(socket);
        return;
      }
      if (op === 0x9) { // ping → pong
        const pong = Buffer.from([0x8A, 0x00]);
        try { socket.write(pong); } catch (e) {}
        continue;
      }
      if (op === 0x1) { // text
        let text = payload.toString('utf-8');
        try {
          const msg = JSON.parse(text);
          handleMessage(socket, msg, wsSend);
        } catch (e) {}
      }
    }
  }

  socket.on('data', (chunk) => {
    buffer = Buffer.concat([buffer, chunk]);
    parseFrames();
  });
  socket.on('close', () => { socket._closed = true; handleDisconnect(socket); });
  socket.on('end', () => { socket._closed = true; handleDisconnect(socket); try { socket.end(); } catch (e) {} });
  socket.on('error', () => { socket._closed = true; handleDisconnect(socket); });
});

function handleDisconnect(socket) {
  const info = wsClients.get(socket);
  if (!info) return;
  wsClients.delete(socket);
  const qIdx = matchQueue.findIndex(e => e.socket === socket);
  if (qIdx >= 0) matchQueue.splice(qIdx, 1);
  const room = rooms.get(info.roomId);
  if (room) {
    // keep the seat for 5 minutes for reconnect
    const seat = room.players.find(p => p.playerNumber === info.playerNumber);
    if (seat) { seat.socket = null; seat.disconnectedAt = Date.now(); }
    roomBroadcast(room, { type: 'playerLeft', player: info.playerNumber, name: info.name });
  }
  broadcastOnlineList();
}

function handleMessage(socket, msg, wsSend) {
  const type = msg.type;
  const clientInfo = wsClients.get(socket);

  // ---- v5.7: flood-protection (बहुत तेज़ी से संदेश भेजने पर रोक) ----
  try {
    const now = Date.now();
    const rl = socket._nkpRL || (socket._nkpRL = { t: now, n: 0, warned: false });
    if (now - rl.t > 10000) { rl.t = now; rl.n = 0; rl.warned = false; }
    rl.n++;
    if (rl.n > 200) {
      if (!rl.warned) { rl.warned = true; try { wsSendSafe(socket, { type: 'rateLimited', message: 'थोड़ा धीरे — बहुत ज़्यादा संदेश' }); } catch (e) {} }
      return;
    }
  } catch (e) {}

  // ---- v3: identify (lobby में नाम बताओ, online list में दिखो) ----
  if (type === 'identify') {
    if (!clientInfo) wsClients.set(socket, { roomId: null, playerNumber: 0, name: msg.name || 'Player' });
    else if (!clientInfo.name || clientInfo.name === 'Player') clientInfo.name = msg.name || 'Player';
    broadcastOnlineList();
    return;
  }

  // ---- v3: lobby invite — किसी online खिलाड़ी को न्योता ----
  if (type === 'nkpInvite') {
    if (!clientInfo || clientInfo.roomId) return;
    let target = null;
    wsClients.forEach((info, sock) => { if (sock._nkpId === msg.to && !info.roomId && !sock._closed) target = sock; });
    if (target) wsSendSafe(target, { type: 'nkpInviteReceived', from: clientInfo.name, fromId: socket._nkpId });
    else wsSendSafe(socket, { type: 'nkpInviteFailed', error: 'खिलाड़ी अभी online नहीं है' });
    return;
  }
  if (type === 'nkpInviteAccept') {
    if (!clientInfo || clientInfo.roomId) return;
    let inviter = null, inviterInfo = null;
    wsClients.forEach((info, sock) => { if (sock._nkpId === msg.to && !info.roomId && !sock._closed) { inviter = sock; inviterInfo = info; } });
    if (!inviter) { wsSendSafe(socket, { type: 'nkpInviteFailed', error: 'खिलाड़ी चला गया' }); return; }
    const rid = makeRoomId();
    rooms.set(rid, {
      players: [
        { playerNumber: 1, name: inviterInfo.name, color: 'RED', socket: inviter, seatToken: crypto.randomBytes(8).toString('hex'), disconnectedAt: 0 },
        { playerNumber: 2, name: clientInfo.name, color: 'YELLOW', socket, seatToken: crypto.randomBytes(8).toString('hex'), disconnectedAt: 0 }
      ],
      password: '', currentTurn: 1, started: false, createdAt: Date.now()
    });
    wsClients.set(inviter, { roomId: rid, playerNumber: 1, name: inviterInfo.name });
    wsClients.set(socket, { roomId: rid, playerNumber: 2, name: clientInfo.name });
    wsSendSafe(inviter, { type: 'matched', roomId: rid, playerNumber: 1 });
    wsSendSafe(socket, { type: 'matched', roomId: rid, playerNumber: 2 });
    broadcastOnlineList();
    return;
  }
  if (type === 'nkpInviteReject') {
    let target = null;
    wsClients.forEach((info, sock) => { if (sock._nkpId === msg.to && !sock._closed) target = sock; });
    if (target && clientInfo) wsSendSafe(target, { type: 'nkpInviteRejected', by: clientInfo.name });
    return;
  }

  // ---- voice chat relay (live voice) ----
  if (type === 'voice') {
    if (!clientInfo || !clientInfo.roomId) return;
    const room = rooms.get(clientInfo.roomId);
    if (!room) return;
    roomBroadcast(room, { type: 'voice', playerNumber: clientInfo.playerNumber, name: clientInfo.name, data: msg.data || '' }, socket);
    return;
  }

  // ---- v5.6: खिलाड़ी का नाम बदलना ----
  // ---- v5.13: खिलाड़ी खेल छोड़ रहा है (जीत/हार के बिना) ----
  if (type === 'leaveRoom') {
    if (!clientInfo || !clientInfo.roomId) return;
    const rid = clientInfo.roomId;
    const room = rooms.get(rid);
    if (room) {
      const seat = room.players.find(pp => Number(pp.playerNumber) === Number(clientInfo.playerNumber));
      // सामने वालों को बताओ — कोई विनर नहीं, बस गेम खत्म
      roomBroadcast(room, { type: 'opponentLeft', playerNumber: clientInfo.playerNumber, name: (seat && seat.name) || clientInfo.name || 'Player' }, socket);
      room.players = room.players.filter(pp => Number(pp.playerNumber) !== Number(clientInfo.playerNumber));
      room.started = false;
      if (room.players.length === 0) rooms.delete(rid);
    }
    clientInfo.roomId = null;
    try { broadcastOnlineList(); } catch (e) {}
    return;
  }

  // ---- v5.11: खिलाड़ी अपनी गोटी का रंग चुन सके ----
  if (type === 'setColor') {
    const col = String(msg.color || '').toUpperCase();
    if (['RED', 'GREEN', 'YELLOW', 'BLUE'].indexOf(col) === -1) return;
    if (!clientInfo || !clientInfo.roomId) return;
    const room = rooms.get(clientInfo.roomId);
    if (!room) return;
    if (room.started) return; // गेम शुरू होने के बाद रंग नहीं बदलेगा
    const taken = room.players.some(pp => Number(pp.playerNumber) !== Number(clientInfo.playerNumber) && pp.color === col);
    if (taken) { try { wsSendSafe(socket, { type: 'colorTaken', color: col }); } catch (e) {} return; }
    const seat = room.players.find(pp => Number(pp.playerNumber) === Number(clientInfo.playerNumber));
    if (seat) seat.color = col;
    roomBroadcast(room, { type: 'roomPlayers', players: room.players.map(pp => ({ playerNumber: pp.playerNumber, name: pp.name, color: pp.color || nkpColorFor(pp.playerNumber) })) });
    return;
  }

  // ---- v5.6: खिलाड़ी का नाम बदलना ----
  if (type === 'setName') {
    const nm = String(msg.name || '').trim().slice(0, 16);
    if (!nm) return;
    if (clientInfo) {
      clientInfo.name = nm;
      if (clientInfo.roomId) {
        const room = rooms.get(clientInfo.roomId);
        if (room) {
          const seat = room.players.find(p => p.playerNumber === clientInfo.playerNumber);
          if (seat) seat.name = nm;
          roomBroadcast(room, { type: 'roomPlayers', players: room.players.map(p => ({ playerNumber: p.playerNumber, name: p.name, color: p.color || nkpColorFor(p.playerNumber) })) });
        }
      }
    }
    return;
  }

  // ---- v5.6: रिपोर्ट (चैट/व्यवहार की शिकायत) ----
  if (type === 'report') {
    try {
      if (!Array.isArray(DB.reports)) DB.reports = [];
      DB.reports.push({ at: Date.now(), by: (clientInfo && clientInfo.name) || 'Player', roomId: (clientInfo && clientInfo.roomId) || null, about: String(msg.about || '').slice(0, 30), reason: String(msg.reason || '').slice(0, 200) });
      if (DB.reports.length > 500) DB.reports = DB.reports.slice(-500);
      try { saveDB(); } catch (e) {}
    } catch (e) {}
    wsSendSafe(socket, { type: 'reportOk' });
    return;
  }

  // ---- v5.4: emoji reactions relay (online game) ----
  if (type === 'reaction') {
    if (!clientInfo || !clientInfo.roomId) return;
    const room = rooms.get(clientInfo.roomId);
    if (!room) return;
    roomBroadcast(room, { type: 'reaction', name: clientInfo.name || 'Player', emoji: String(msg.emoji || '').slice(0, 8) }, socket);
    return;
  }

  // ---- auth: attach account to connection ----
  if (type === 'auth') {
    const uname = userFromToken(msg.token);
    if (uname) {
      if (!clientInfo) wsClients.set(socket, { roomId: null, playerNumber: 0, name: uname, username: uname });
      else clientInfo.username = uname;
      wsSend(socket, { type: 'authOk', username: uname });
    } else {
      wsSend(socket, { type: 'authFailed' });
    }
    return;
  }

  // ---- createRoom ----
  if (type === 'createRoom') {
    const roomId = makeRoomId();
    const name = msg.name || 'Player 1';
    rooms.set(roomId, {
      players: [{ playerNumber: 1, name, color: 'RED', socket, seatToken: crypto.randomBytes(8).toString('hex'), disconnectedAt: 0 }],
      password: msg.password || '',
      currentTurn: 1, started: false, createdAt: Date.now()
    });
    wsClients.set(socket, { roomId, playerNumber: 1, name });
    wsSend(socket, { type: 'roomCreated', roomId });
    return;
  }

  // ---- joinRoom ----
  if (type === 'joinRoom') {
    const room = rooms.get(msg.roomId);
    if (!room) { wsSend(socket, { type: 'roomFull', error: 'Room not found' }); return; }
    if (room.password && room.password !== msg.password) { wsSend(socket, { type: 'roomFull', error: 'Wrong password' }); return; }
    // rejoin a disconnected seat if available
    const emptySeat = room.players.find(p => !p.socket);
    if (emptySeat) {
      emptySeat.socket = socket;
      emptySeat.disconnectedAt = 0;
      wsClients.set(socket, { roomId: msg.roomId, playerNumber: emptySeat.playerNumber, name: msg.name || emptySeat.name });
      wsSend(socket, { type: 'roomJoined', roomId: msg.roomId, playerNumber: emptySeat.playerNumber });
      roomBroadcast(room, { type: 'playerBack', playerNumber: emptySeat.playerNumber, name: emptySeat.name });
      roomBroadcast(room, { type: 'roomPlayers', players: room.players.map(p => ({ playerNumber: p.playerNumber, name: p.name, color: p.color || nkpColorFor(p.playerNumber) })) });
      return;
    }
    if (room.players.length >= 4) { wsSend(socket, { type: 'roomFull', error: 'Room full' }); return; }
    const pn = room.players.length + 1;
    room.players.push({ playerNumber: pn, name: msg.name || ('Player ' + pn), color: nkpColorFor(pn), socket, seatToken: crypto.randomBytes(8).toString('hex'), disconnectedAt: 0 });
    wsClients.set(socket, { roomId: msg.roomId, playerNumber: pn, name: msg.name });
    wsSend(socket, { type: 'roomJoined', roomId: msg.roomId, playerNumber: pn });
    roomBroadcast(room, { type: 'peerJoined', playerNumber: pn, name: msg.name }, socket);
    // v5.5: सबको खिलाड़ियों की ताज़ा list
    roomBroadcast(room, { type: 'roomPlayers', players: room.players.map(p => ({ playerNumber: p.playerNumber, name: p.name, color: p.color || nkpColorFor(p.playerNumber) })) });
    return;
  }

  // ---- rejoin (reconnect to last game) ----
  if (type === 'rejoin') {
    const room = rooms.get(msg.roomId);
    if (!room) { wsSend(socket, { type: 'roomGone' }); return; }
    const seat = room.players.find(p => p.playerNumber === msg.seat);
    if (!seat) { wsSend(socket, { type: 'roomGone' }); return; }
    // if seat occupied and that client is alive, deny
    if (seat.socket && !seat.socket._closed) { wsSend(socket, { type: 'roomGone', error: 'Seat occupied' }); return; }
    seat.socket = socket; seat.disconnectedAt = 0;
    wsClients.set(socket, { roomId: msg.roomId, playerNumber: seat.playerNumber, name: seat.name });
    wsSend(socket, { type: 'rejoined', roomId: msg.roomId, playerNumber: seat.playerNumber });
    roomBroadcast(room, { type: 'playerBack', playerNumber: seat.playerNumber, name: seat.name }, socket);
    return;
  }

  // ---- quickMatch (matchmaking queue) ----
  if (type === 'quickMatch') {
    // remove stale entries
    for (let i = matchQueue.length - 1; i >= 0; i--) {
      if (matchQueue[i].socket._closed) matchQueue.splice(i, 1);
    }
    if (matchQueue.length > 0) {
      const other = matchQueue.shift();
      const roomId = makeRoomId();
      rooms.set(roomId, {
        players: [
          { playerNumber: 1, name: other.name, color: 'RED', socket: other.socket, seatToken: crypto.randomBytes(8).toString('hex'), disconnectedAt: 0 },
          { playerNumber: 2, name: msg.name || 'Player', color: 'YELLOW', socket, seatToken: crypto.randomBytes(8).toString('hex'), disconnectedAt: 0 }
        ],
        password: '', currentTurn: 1, started: true, createdAt: Date.now()
      });
      wsClients.set(other.socket, { roomId, playerNumber: 1, name: other.name });
      wsClients.set(socket, { roomId, playerNumber: 2, name: msg.name });
      wsSend(other.socket, { type: 'matched', roomId, playerNumber: 1 });
      wsSend(socket, { type: 'matched', roomId, playerNumber: 2 });
    } else {
      matchQueue.push({ socket, name: msg.name || 'Player' });
      wsSend(socket, { type: 'queued' });
    }
    return;
  }

  // ---- friends ----
  if (type === 'friendAdd') {
    const me = (clientInfo && clientInfo.username) || (clientInfo && clientInfo.name) || '';
    const target = String(msg.name || '').toLowerCase();
    if (!DB.users[target]) { wsSend(socket, { type: 'friendNotFound' }); return; }
    if (target === (clientInfo.username || '')) { wsSend(socket, { type: 'friendNotFound' }); return; }
    if (!DB.friends[clientInfo.username]) DB.friends[clientInfo.username] = [];
    if (DB.friends[clientInfo.username].indexOf(target) === -1) DB.friends[clientInfo.username].push(target);
    saveDB();
    wsSend(socket, { type: 'friendAdded', name: target });
    sendFriendsList(socket);
    return;
  }
  if (type === 'friendList') { sendFriendsList(socket); return; }
  if (type === 'friendInvite') {
    const from = (clientInfo && (clientInfo.username || clientInfo.name)) || 'Player';
    const target = String(msg.name || '').toLowerCase();
    // find target among connected clients
    let found = false;
    wsClients.forEach((info, s) => {
      if (info.username === target && !s._closed) {
        wsSend(s, { type: 'friendInvite', from, roomId: msg.roomId });
        found = true;
      }
    });
    if (!found) wsSend(socket, { type: 'friendOffline', name: target });
    return;
  }

  // ---- game relay with server-side validation ----
  if (!clientInfo || !clientInfo.roomId) return;
  const room = rooms.get(clientInfo.roomId);
  if (!room) return;

  if (type === 'startGame') {
    room.started = true;
    room.currentTurn = 1; // v5.5: नई गेम — पहली बारी seat 1
    room.lastActivity = Date.now();
    // सबको भेजो (host भी शुरू हो) — seats की list के साथ
    const seats = room.players.map(p => ({ playerNumber: p.playerNumber, name: p.name, color: p.color || nkpColorFor(p.playerNumber) }));
    roomBroadcast(room, { type: 'startGame', players: seats });
    return;
  }

  if (type === 'diceRoll') {
    // v5.9: बारी की सख़्त जाँच — सिर्फ़ जिस खिलाड़ी की बारी है वही पासा चला सकता है।
    // गलत खिलाड़ी को सही बारी बता दो (resync) — गेम अटकता नहीं, धोखा भी नहीं।
    if (Number(clientInfo.playerNumber) !== Number(room.currentTurn)) {
      try { wsSendSafe(socket, { type: 'notYourTurn', currentTurn: room.currentTurn }); } catch (e) {}
      return;
    }
    room.lastActivity = Date.now();
    roomBroadcast(room, { type: 'diceRoll', player: msg.player, value: msg.value }, socket);
    return;
  }
  if (type === 'tokenMove') {
    const step = Number(msg.step);
    if (isNaN(step) || step < -1 || step > 56) return;
    // v5.9: सिर्फ़ जिसकी बारी है वही गोटी चला सकता है
    if (Number(clientInfo.playerNumber) !== Number(room.currentTurn)) {
      try { wsSendSafe(socket, { type: 'notYourTurn', currentTurn: room.currentTurn }); } catch (e) {}
      return;
    }
    room.lastActivity = Date.now();
    roomBroadcast(room, { type: 'tokenMove', player: msg.player, tokenId: msg.tokenId, step: msg.step }, socket);
    return;
  }
  if (type === 'turnChange') {
    // v5.8: पुराने ऐप "index" भेजते हैं (0,1) और नए "seat" (1,2) — दोनों मान लो
    let np = Number(msg.nextPlayer);
    if (isNaN(np)) return;
    if (np === 0) np = 1;                                  // पुराने ऐप का index 0 → seat 1
    if (np < 1 || np > room.players.length) return;
    room.currentTurn = np;
    room.lastActivity = Date.now();
    roomBroadcast(room, { type: 'turnChange', nextPlayer: np }, socket);
    return;
  }
  if (type === 'gameOver') {
    roomBroadcast(room, { type: 'gameOver', winner: msg.winner }, socket);
    return;
  }
  if (type === 'chat') {
    // v5.7: chat-लिमिट (10 सेकंड में 6 से ज़्यादा नहीं) + लिंक/नंबर/ईमेल की सफ़ाई
    try {
      const now = Date.now();
      const rl = socket._nkpRL || (socket._nkpRL = { t: now, n: 0, chatT: now, chatN: 0 });
      if (!rl.chatT || now - rl.chatT > 10000) { rl.chatT = now; rl.chatN = 0; }
      rl.chatN++;
      if (rl.chatN > 6) { try { wsSendSafe(socket, { type: 'rateLimited', message: 'थोड़ा रुककर भेजें' }); } catch (e) {} return; }
    } catch (e) {}
    const clean = safeChat(msg.msg).slice(0, 50);
    roomBroadcast(room, { type: 'chat', name: clientInfo.name || 'Player', msg: clean }, socket);
    return;
  }
  if (type === 'quickmsg') {
    // v5.5: तैयार छोटे message (sticker) — free typing नहीं, इसलिए सुरक्षित
    const text = String(msg.text || '').slice(0, 60);
    roomBroadcast(room, { type: 'quickmsg', name: clientInfo.name || 'Player', text }, socket);
    return;
  }
  if (type === 'gameState' && msg.state) {
    // v5.12: सिर्फ़ जिसकी बारी है वही बोर्ड भेज सकता है — और सिर्फ़ अपनी गोटियाँ
    if (Number(clientInfo.playerNumber) !== Number(room.currentTurn)) {
      try { wsSendSafe(socket, { type: 'notYourTurn', currentTurn: room.currentTurn }); } catch (e) {}
      return;
    }
    const me = room.players.find(pp => Number(pp.playerNumber) === Number(clientInfo.playerNumber));
    const myColor = me ? (me.color || nkpColorFor(me.playerNumber)) : null;
    if (!myColor) return;
    const safeState = {};
    if (msg.state[myColor]) safeState[myColor] = msg.state[myColor];
    roomBroadcast(room, { type: 'gameState', state: safeState }, socket);
    return;
  }
  if (type === 'captured') {
    // v5.12: गोटी कटने की ख़बर — सिर्फ़ जिसकी बारी है वही भेज सकता है
    if (Number(clientInfo.playerNumber) !== Number(room.currentTurn)) return;
    const vc = String(msg.victimColor || '').toUpperCase();
    if (['RED', 'GREEN', 'YELLOW', 'BLUE'].indexOf(vc) === -1) return;
    roomBroadcast(room, { type: 'captured', victimColor: vc, victimTokenId: Number(msg.victimTokenId) || 0 }, socket);
    return;
  }
  if (type === 'gameMove') {
    roomBroadcast(room, msg, socket);
    return;
  }
}

function sendFriendsList(socket) {
  const info = wsClients.get(socket);
  if (!info || !info.username) { wsSendSafe(socket, { type: 'friendsList', friends: [] }); return; }
  const friends = DB.friends[info.username] || [];
  const online = friends.map(f => {
    let isOnline = false;
    wsClients.forEach((ci) => { if (ci.username === f) isOnline = true; });
    return { name: f, online: isOnline };
  });
  wsSendSafe(socket, { type: 'friendsList', friends: online });
}
function wsSendSafe(socket, msg) {
  try {
    const payloadBuf = Buffer.from(JSON.stringify(msg), 'utf-8');
    let header;
    if (payloadBuf.length < 126) { header = Buffer.alloc(2); header[0] = 0x81; header[1] = payloadBuf.length; }
    else { header = Buffer.alloc(4); header[0] = 0x81; header[1] = 126; header.writeUInt16BE(payloadBuf.length, 2); }
    socket.write(Buffer.concat([header, payloadBuf]));
  } catch (e) {}
}

// ---- v5.9: गेम अटकने से बचाओ — 20 सेकंड तक कोई हरकत न हो तो बारी आगे बढ़ाओ ----
setInterval(() => {
  try {
    const now = Date.now();
    rooms.forEach((room) => {
      if (!room.started) return;
      const n = (room.players && room.players.length) ? room.players.length : 2;
      // v5.10: ज़िंदा (जुड़े हुए) खिलाड़ी को सोचने का पूरा समय दो (60s) — बारी जल्दी न छिने।
      // गया हुआ (disconnected) खिलाड़ी हो तो 20s में ही बारी आगे बढ़ा दो।
      const curSeat = room.players.find(pp => Number(pp.playerNumber) === (Number(room.currentTurn) || 1));
      const curAlive = curSeat && curSeat.socket && !curSeat.socket._closed;
      const _limit = curAlive ? 60000 : 20000;
      if (now - (room.lastActivity || room.createdAt || now) < _limit) return;
      let nt = Number(room.currentTurn) || 1;
      for (let k = 0; k < n; k++) {
        nt = (nt % n) + 1;
        const okSeat = room.players.some(pp => Number(pp.playerNumber) === nt && pp.socket && !pp.socket._closed);
        if (okSeat) break;
      }
      room.currentTurn = nt;
      room.lastActivity = now;
      roomBroadcast(room, { type: 'turnChange', nextPlayer: room.currentTurn, stalled: true });
    });
  } catch (e) {}
}, 5000);

// cleanup dead rooms every 10 minutes
setInterval(() => {
  const now = Date.now();
  rooms.forEach((room, id) => {
    const alive = room.players.some(p => p.socket && !p.socket._closed);
    const anyRecent = room.players.some(p => !p.disconnectedAt || (now - p.disconnectedAt < 300000));
    if (!alive && !anyRecent) rooms.delete(id);
    else if (now - room.createdAt > 6 * 3600000) rooms.delete(id); // 6h max
  });
}, 600000);

server.listen(PORT, () => {
  console.log('NKP Ludo Pro server v5.13 (protected) running on port ' + PORT + (ADMIN_KEY ? ' [admin key set]' : ' [admin key not set]'));
});
