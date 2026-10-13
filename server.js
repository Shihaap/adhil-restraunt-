/* ============================================================================
   Aadil Restaurant — secure automatic backend  (zero third-party dependencies)
   ----------------------------------------------------------------------------
   Run locally:        node server.js
   Deploy to Render:  this file + render.yaml (set ADMIN_PASSWORD + ALLOW_ORIGIN)

   Security model:
   • Admin password is NEVER stored in data.js or any served file.
     Stored scrypt-hashed (per-user random salt) in auth.json (0600).
     On first run it takes ADMIN_PASSWORD from env; otherwise it generates a
     strong one and prints it ONCE to the logs.
   • Sessions: HMAC-signed tokens (random per-install secret in secret.key),
     stored hashed (SHA-256) in sessions.json, 12h sliding expiry.
   • /api/login  : per-IP rate limit + lockout after repeated failures.
   • /api/data POST and /api/orders GET : require a valid session token.
   • /api/orders POST (customers) : public but rate-limited + shape-checked.
   • Body-size caps, JSON validation on every write, CORS allowlist,
     security headers on every response.
   • Published store.json / data.js are scrubbed of secrets (any settings key
     matching "password|secret|token" is dropped).
   ========================================================================= */
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const PORT = process.env.PORT || 3000;
const ADMIN_USER = (process.env.ADMIN_USER || 'admin').toLowerCase();
const ALLOWED_ORIGINS = (process.env.ALLOW_ORIGIN || '').split(',')
  .map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;   /* 12h sliding session */
const BYPASS_ORDER_LIMIT = 60;                 /* items per order */
const BODY_LIMIT = 512 * 1024;                 /* max request body */

/* ------------------------------------------------------------------ state */
const F_AUTH    = path.join(ROOT, 'auth.json');
const F_SECRET  = path.join(ROOT, 'secret.key');
const F_SESS    = path.join(ROOT, 'sessions.json');
const F_STORE   = path.join(ROOT, 'store.json');
const F_ORDERS  = path.join(ROOT, 'orders.json');
const F_DATAJS  = path.join(ROOT, 'data.js');
const F_LOG     = path.join(ROOT, 'security.log');

function readJSON(file, fallback){
  try{ return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch(e){ return fallback; }
}
function writeJSON(file, obj){
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), { mode: 0o600 });
}
function logSec(event, detail){
  const line = new Date().toISOString() + '  ' + event + '  ' + (detail || '');
  try{ fs.appendFileSync(F_LOG, line + '\n'); }catch(e){}
}

/* -------------------------------------------------------- admin credential */
function ensureAdmin(){
  if(fs.existsSync(F_AUTH)) return;
  let pw = process.env.ADMIN_PASSWORD;
  let generated = false;
  if(!pw || pw.length < 8){
    generated = true;
    console.log('=====================================================');
    console.log('  ADMIN_PASSWORD env: ' + (pw ? ('TOO SHORT (' + pw.length + ' chars, need 8+) — ignored') : 'not set') + '.');
    console.log('  Generating a random password instead (printed below ONCE).');
    console.log('=====================================================');
    logSec('ADMIN-ENV-IGNORED', (pw ? ('too-short len=' + pw.length) : 'not-set') + ' -> generated');
    pw = crypto.randomBytes(6).toString('base64url') + '-' + crypto.randomBytes(6).toString('base64url');
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const users = [{ user: ADMIN_USER, salt, hash: hashPassword(pw, salt), createdAt: new Date().toISOString() }];
  writeJSON(F_AUTH, { users });
  logSec('ADMIN-CREATED', 'user=' + ADMIN_USER + (generated ? ' generated-password' : ' from-env'));
  console.log('=====================================================');
  console.log('  ADMIN ACCOUNT CREATED');
  if(generated) console.log('  USERNAME : ' + ADMIN_USER);
  console.log('  PASSWORD : ' + pw + (generated ? '   <-- KEEP SAFE, shown once' : ' (from ADMIN_PASSWORD env)'));
  console.log('=====================================================');
}
function hashPassword(pw, salt){
  return crypto.scryptSync(pw, salt, 64).toString('hex');
}
function verifyPassword(pw, salt, storedHex){
  const a = Buffer.from(hashPassword(pw, salt), 'hex');
  const b = Buffer.from(storedHex, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ----------------------------------------------------------------- tokens */
function ensureSecret(){
  if(!fs.existsSync(F_SECRET)){
    fs.writeFileSync(F_SECRET, crypto.randomBytes(48).toString('hex'), { mode: 0o600 });
  }
  return fs.readFileSync(F_SECRET, 'utf8').trim();
}
const b64u = s => Buffer.from(s).toString('base64url');
function signPayload(obj){
  const secret = ensureSecret();
  const body = b64u(JSON.stringify(obj));
  return body + '.' + crypto.createHmac('sha256', secret).update(body).digest('base64url');
}
function verifyToken(token){
  const secret = ensureSecret();
  const parts = String(token || '').split('.');
  if(parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', secret).update(parts[0]).digest('base64url');
  const a = Buffer.from(parts[1]), b = Buffer.from(expected);
  if(a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try{
    const payload = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const now = Date.now();
    if(payload.exp && payload.exp < now) return null;
    return payload;
  }catch(e){ return null; }
}
function issueSession(user){
  const token = signPayload({ u: user, iat: Date.now(), exp: Date.now() + SESSION_TTL_MS });
  const h = crypto.createHash('sha256').update(token).digest('hex');
  const all = readJSON(F_SESS, []);
  all.push({ h, u: user, exp: Date.now() + SESSION_TTL_MS });
  writeJSON(F_SESS, all.filter(s => s.exp > Date.now()).slice(-50));
  return { token, exp: Date.now() + SESSION_TTL_MS };
}
function validateSession(token){
  const payload = verifyToken(token);
  if(!payload) return null;
  const h = crypto.createHash('sha256').update(token).digest('hex');
  const all = readJSON(F_SESS, []);
  const s = all.find(x => x.h === h && x.exp > Date.now());
  if(!s) return null;
  /* sliding renewal */
  s.exp = Date.now() + SESSION_TTL_MS;
  writeJSON(F_SESS, all.filter(x => x.exp > Date.now()));
  return payload;
}
function revokeSession(token){
  if(!token) return;
  const h = crypto.createHash('sha256').update(token).digest('hex');
  const all = readJSON(F_SESS, []);
  writeJSON(F_SESS, all.filter(x => x.h !== h));
}
function revokeAllFor(user){
  const all = readJSON(F_SESS, []);
  writeJSON(F_SESS, all.filter(x => x.u !== user));
}
function currentUser(req){
  const ah = String(req.headers['authorization'] || '');
  const m = /^Bearer\s+(.+)$/i.exec(ah);
  return m ? validateSession(m[1]) : null;
}
function sessionCount(){
  return readJSON(F_SESS, []).length;
}

/* ------------------------------------------------------------- rate limits */
const hits = new Map();   /* key -> {n, reset} */
function hit(key, limit, windowMs){
  const now = Date.now(), reset = now + windowMs;
  let r = hits.get(key);
  if(!r || now > r.reset){ r = { n: 0, reset }; }
  r.n++;
  hits.set(key, r);
  if(hits.size > 5000){ for(const k of hits.keys()) if(hits.get(k).reset < now) hits.delete(k); }
  return r.n <= limit ? { ok:true } : { ok:false, retry: Math.max(1, Math.ceil((r.reset - now) / 1000)) };
}
const lockouts = new Map(); /* ip -> {n, until}*/
function ipOf(req){
  const f = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return f || req.socket.remoteAddress || '?';
}
function isLocked(ip){
  const l = lockouts.get(ip);
  if(!l) return false;
  if(Date.now() > l.until){ lockouts.delete(ip); return false; }
  return true;
}
function registerFail(ip){
  const l = lockouts.get(ip) || { n: 0, until: 0 };
  l.n++;
  if(l.n >= 5){ l.until = Date.now() + 15 * 60 * 1000; lockouts.set(ip, l); logSec('LOCKOUT', 'ip=' + ip + ' for 15m'); }
  else lockouts.set(ip, l);
}

/* -------------------------------------------------------------- data store */
function loadSeed(){
  if(fs.existsSync(F_STORE)){ return readJSON(F_STORE, null); }
  const sandbox = {};
  try{ new Function('window', fs.readFileSync(F_DATAJS, 'utf8'))(sandbox); return sandbox.AADIL || {}; }
  catch(e){ return { settings:{}, images:{}, menu:{} }; }
}
let store = loadSeed();
let lastWriteTs = Date.now();   /* stable "version" of published data; bumps on every publish */
try{ const rt = readJSON(F_STORE, null); if(rt && typeof rt.ts === 'number') lastWriteTs = rt.ts; }catch(e){}
/* so Render restarts don't bump the version and force visitors to reload */

function scrubSecrets(obj){
  const out = { settings: Object.assign({}, obj.settings), images: Object.assign({}, obj.images || {}), menu: obj.menu || {} };
  for(const k of Object.keys(out.settings)){
    if(/password|secret|token/i.test(k)) delete out.settings[k];
  }
  return out;
}
function saveStore(obj){
  const clean = scrubSecrets(obj);
  lastWriteTs = Date.now();
  writeJSON(F_STORE, Object.assign({}, clean, { ts: lastWriteTs }));
  store = clean;
  const head = '/* Aadil Restaurant — auto-generated by server.js (secrets scrubbed). */\n';
  fs.writeFileSync(F_DATAJS, head + 'window.AADIL = ' + JSON.stringify(clean, null, 2) + ';\n');
  return clean;
}
function readOrders(){ return readJSON(F_ORDERS, []); }
function saveOrders(list){ fs.writeFileSync(F_ORDERS, JSON.stringify(list.slice(-1000), null, 2)); }

/* validate + sanitize a content payload. throws on invalid. */
function sanitizeContent(obj){
  if(!obj || typeof obj !== 'object') throw new Error('payload must be an object');
  const settings = obj.settings || {}, images = obj.images || {}, menu = obj.menu || {};
  if(typeof settings !== 'object' || typeof menu !== 'object') throw new Error('settings and menu must be objects');
  const s = {};
  for(const k of Object.keys(settings)){
    const v = settings[k];
    if(v == null) continue;
    if(typeof v === 'string') s[k] = String(v).slice(0, 5000);
    else if(typeof v === 'number' && isFinite(v)) s[k] = v;
    else if(typeof v === 'boolean') s[k] = v;
    else if(Array.isArray(v)) s[k] = v.map(e => (typeof e === 'string' ? String(e).slice(0, 2000) : e));
    else s[k] = v; /* nested objects (social, hours) left as-is */
  }
  const im = {};
  for(const k of Object.keys(images)){ const v = images[k]; if(typeof v === 'string' || typeof v === 'number') im[k] = String(v).slice(0, 3000); }
  const m = {};
  let itemCount = 0;
  for(const cat of Object.keys(menu)){
    if(!Array.isArray(menu[cat])) continue;
    m[cat] = menu[cat].slice(0, 300).map(it => {
      if(!it || typeof it !== 'object') return null;
      itemCount++;
      return {
        n: String(it.n || '').slice(0, 120),
        p: Math.min(1e7, Math.max(0, Number(it.p) || 0)),
        d: String(it.d || '').slice(0, 300),
        img: String(it.img || '').slice(0, 500),
        v: !!it.v, star: !!it.star, a: it.a === false ? false : true
      };
    }).filter(Boolean);
  }
  if(itemCount > 500) throw new Error('too many items');
  return { settings: s, images: im, menu: m };
}
function sanitizeOrder(o){
  if(!o || !Array.isArray(o.items) || o.items.length === 0 || o.items.length > BYPASS_ORDER_LIMIT) throw new Error('invalid order');
  const items = o.items.map(it => ({
    n: String(it.n || '').slice(0, 120),
    q: Math.max(1, Math.min(99, Number(it.q) || 1)),
    p: Math.min(1e7, Math.max(0, Number(it.p) || 0))
  }));
  return {
    id: String(o.id || '').slice(0, 40),
    ts: Number(o.ts) || Date.now(),
    iso: String(o.iso || new Date().toISOString()).slice(0, 100),
    name: String(o.name || '').slice(0, 80),
    address: String(o.address || '').slice(0, 240),
    phone: String(o.phone || '').slice(0, 24),
    items,
    subtotal: Math.max(0, Number(o.subtotal) || 0),
    delivery: Math.max(0, Number(o.delivery) || 0),
    total: Math.max(0, Number(o.total) || 0)
  };
}
const ORDER_STATUSES = new Set(['new', 'preparing', 'out', 'delivered', 'cancelled']);

/* ------------------------------------------------------- http plumbing */
const MIME = {
  '.html':'text/html; charset=utf-8', '.js':'text/javascript; charset=utf-8',
  '.css':'text/css; charset=utf-8', '.json':'application/json; charset=utf-8',
  '.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp',
  '.gif':'image/gif','.svg':'image/svg+xml','.ico':'image/x-icon','.txt':'text/plain; charset=utf-8'
};
function headers(res, req){
  const o = {
    'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':'DENY',
    'Referrer-Policy':'strict-origin-when-cross-origin',
    'X-XSS-Protection':'0',
    'Permissions-Policy':'camera=(), microphone=(), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; frame-src https://www.google.com; connect-src 'self' https:; font-src 'self' https: data:",
    'Cache-Control':'no-cache'
  };
  if((req.headers['x-forwarded-proto'] || 'http') === 'https'){
    o['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
  }
  const origin = req.headers['origin'];
  if(!origin) return o;
  const host = (req.headers.host || '');
  if(ALLOWED_ORIGINS.includes(origin) || ALLOWED_ORIGINS.includes('*') || new URL(origin).host === host){
    o['Access-Control-Allow-Origin'] = origin;
    o['Vary'] = 'Origin';
    o['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
    o['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
  }
  return o;
}
function json(res, code, obj, extra){
  const h = Object.assign(headers(res, res.req || {}), { 'Content-Type':'application/json; charset=utf-8' }, extra || {});
  res.writeHead(code, h);
  res.end(JSON.stringify(obj));
}
function body(req, cb){
  let raw = '';
  req.on('data', c => {
    raw += c;
    if(raw.length > BODY_LIMIT){ raw = null; req.destroy(); }
  });
  req.on('end', () => cb(raw));
}
function serveStatic(req, res){
  let p;
  try{ p = decodeURIComponent(req.url.split('?')[0]); }
  catch(e){ res.writeHead(400, headers(res, req)); res.end('Bad request'); return; }
  if(p === '/') p = '/index.html';
  const file = path.normalize(path.join(ROOT, p));
  if(!file.startsWith(ROOT)){ res.writeHead(403, headers(res, req)); res.end(); return; }
  fs.readFile(file, (err, data) => {
    if(err){ res.writeHead(404, headers(res, req)); res.end('Not found'); return; }
    const h = headers(res, req);
    h['Content-Type'] = MIME[path.extname(file).toLowerCase()] || 'application/octet-stream';
    h['Cache-Control'] = p.endsWith('.js') || p.endsWith('.html') ? 'no-cache' : 'public, max-age=86400';
    res.writeHead(200, h);
    res.end(data);
  });
}

/* ------------------------------------------------------------------ app */
if(process.env.RESET_ADMIN === '1'){
  try{ if(fs.existsSync(F_AUTH)){ fs.unlinkSync(F_AUTH); console.log('RESET_ADMIN=1 — auth.json removed, will recreate from ADMIN_PASSWORD env (which needs 8+ chars).'); }
       if(fs.existsSync(F_SESS)){ fs.unlinkSync(F_SESS); }
       if(fs.existsSync(F_SECRET)){ fs.unlinkSync(F_SECRET); console.log('RESET_ADMIN=1 — secret.key rotated (old sessions invalidated).'); } }catch(e){}
}
ensureAdmin();
ensureSecret();
const server = http.createServer((req, res) => {
  res.req = req;
  const url = req.url.split('?')[0];
  const method = req.method;

  if(method === 'OPTIONS'){
    res.writeHead(204, headers(res, req)); res.end(); return;
  }

  /* ------------------------------- public: health */
  if(method === 'GET' && url === '/api/health'){
    return json(res, 200, { ok:true, secure:true, name:(store.settings && store.settings.name) || 'Aadil Restaurant', ts:Date.now() });
  }
  /* ------------------------------- public: read data */
  if(method === 'GET' && url === '/api/data'){
    return json(res, 200, { ok:true, ts:lastWriteTs, data: store });
  }
  /* ------------------------------- public: customer places order */
  if(method === 'POST' && url === '/api/orders'){
    const rl = hit('ord:' + ipOf(req), 6, 60000);
    if(!rl.ok) return json(res, 429, { ok:false, error:'Too many orders — try again in ' + rl.retry + 's' });
    return body(req, raw => {
      if(raw == null) return json(res, 413, { ok:false, error:'Request too large' });
      try{
        const order = sanitizeOrder(JSON.parse(raw).order);
        order.status = 'new'; order.statusTs = order.ts;
        const list = readOrders(); list.push(order); saveOrders(list);
        json(res, 200, { ok:true, message:'Order recorded' });
      }catch(e){ json(res, 400, { ok:false, error: String(e.message || e) }); }
    });
  }

  /* ------------------------------- admin login */
  if(method === 'POST' && url === '/api/login'){
    const ip = ipOf(req);
    if(isLocked(ip)) return json(res, 429, { ok:false, error:'Too many attempts — locked for a while' });
    const rl = hit('login:' + ip, 5, 60000);
    if(!rl.ok) return json(res, 429, { ok:false, error:'Rate limited — try again in ' + rl.retry + 's' });
    return body(req, raw => {
      if(raw == null) return json(res, 413, { ok:false, error:'Request too large' });
      try{
        const { user, password } = JSON.parse(raw);
        const u = String(user || '').trim().toLowerCase();
        const auth = readJSON(F_AUTH, { users: [] });
        const rec = auth.users.find(x => x.user === u);
        const ok = !!rec && typeof password === 'string' && verifyPassword(password, rec.salt, rec.hash);
        if(!ok){
          registerFail(ip);
          logSec('LOGIN-FAIL', 'user=' + u + ' ip=' + ip);
          return json(res, 401, { ok:false, error:'Invalid credentials' });
        }
        const s = issueSession(u);
        logSec('LOGIN-OK', 'user=' + u + ' ip=' + ip);
        json(res, 200, { ok:true, token:s.token, expiresIn:s.exp, user: u });
      }catch(e){ json(res, 400, { ok:false, error:'Bad request body' }); }
    });
  }

  /* ------------------------------- admin: requires session from here */
  const session = currentUser(req);
  const publicPost = url === '/api/orders';
  if(!session && method === 'POST' && !publicPost){
    return json(res, 401, { ok:false, error:'Unauthorized — sign in first' });
  }

  if(method === 'POST' && url === '/api/logout'){
    revokeSession(String(req.headers['authorization'] || '').replace(/^Bearer\s+/i, '').trim());
    logSec('LOGOUT', 'user=' + session.u);
    return json(res, 200, { ok:true });
  }

  if(method === 'POST' && url === '/api/change-password'){
    const rl = hit('pw:' + ipOf(req), 5, 60000);
    if(!rl.ok) return json(res, 429, { ok:false, error:'Rate limited' });
    return body(req, raw => {
      if(raw == null) return json(res, 413, { ok:false, error:'Request too large' });
      try{
        const { current, next } = JSON.parse(raw);
        const u = session.u;
        const auth = readJSON(F_AUTH, { users: [] });
        const rec = auth.users.find(x => x.user === u);
        if(!rec || typeof current !== 'string' || typeof next !== 'string' || !verifyPassword(current, rec.salt, rec.hash)){
          logSec('PASSWORD-FAIL', 'user=' + u);
          return json(res, 401, { ok:false, error:'Current password is wrong' });
        }
        if(next.length < 8 || !/[A-Za-z]/.test(next) || !/[0-9]/.test(next)){
          return json(res, 400, { ok:false, error:'New password: min 8 chars with letters and numbers' });
        }
        rec.salt = crypto.randomBytes(16).toString('hex');
        rec.hash = hashPassword(next, rec.salt);
        writeJSON(F_AUTH, auth);
        revokeAllFor(u);
        logSec('PASSWORD-CHANGED', 'user=' + u);
        json(res, 200, { ok:true, message:'Password changed — please sign in again' });
      }catch(e){ json(res, 400, { ok:false, error:'Bad request body' }); }
    });
  }

  /* ------------------------------- admin: publish content */
  if(method === 'POST' && url === '/api/data'){
    const rl = hit('data:' + ipOf(req), 10, 60000);
    if(!rl.ok) return json(res, 429, { ok:false, error:'Rate limited' });
    return body(req, raw => {
      if(raw == null) return json(res, 413, { ok:false, error:'Request too large' });
      try{
        const clean = sanitizeContent(JSON.parse(raw).data);
        const saved = saveStore(clean);
        logSec('PUBLISH', 'user=' + session.u + ' items=' + Object.values(saved.menu).flat().length);
        json(res, 200, { ok:true, ts: Date.now(), message:'Published — live site updated' });
      }catch(e){ json(res, 400, { ok:false, error: String(e.message || e) }); }
    });
  }

  /* ------------------------------- admin: update an order's status */
  if(method === 'POST' && url === '/api/orders/status'){
    return body(req, raw => {
      if(raw == null) return json(res, 413, { ok:false, error:'Request too large' });
      try{
        const { id, status } = JSON.parse(raw);
        if(!ORDER_STATUSES.has(status)) return json(res, 400, { ok:false, error:'Unknown status' });
        const list = readOrders();
        const o = list.find(x => String(x.id) === String(id));
        if(!o) return json(res, 404, { ok:false, error:'Order not found' });
        o.status = status; o.statusTs = Date.now();
        saveOrders(list);
        logSec('ORDER-STATUS', 'user=' + session.u + ' id=' + o.id + ' status=' + status);
        json(res, 200, { ok:true, order:o });
      }catch(e){ json(res, 400, { ok:false, error:'Bad request body' }); }
    });
  }

  /* ------------------------------- admin: read orders */
  if(method === 'GET' && url === '/api/orders'){
    if(!session) return json(res, 401, { ok:false, error:'Unauthorized — sign in first' });
    return json(res, 200, { ok:true, user: session.u, orders: readOrders() });
  }

  serveStatic(req, res);
});

server.listen(PORT, () => {
  console.log('Aadil Restaurant secure backend:');
  console.log('  URL   : http://localhost:' + PORT + '/');
  console.log('  Admin : http://localhost:' + PORT + '/admin.html');
  console.log('  Auth  : scrypt-hashed admin · signed sessions · rate-limited');
});