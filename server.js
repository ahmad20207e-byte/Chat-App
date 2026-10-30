const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) { console.error('Missing DATABASE_URL'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });

async function init() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, hash TEXT NOT NULL, created BIGINT NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT NOT NULL, created BIGINT NOT NULL)`);
  await pool.query(`CREATE TABLE IF NOT EXISTS messages (id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL, text TEXT NOT NULL, ts BIGINT NOT NULL)`);
}

const hash = (p, salt = crypto.randomBytes(16).toString('hex')) =>
  salt + ':' + crypto.scryptSync(p, salt, 64).toString('hex');
const verify = (p, h) => {
  const [s, x] = h.split(':');
  const y = crypto.scryptSync(p, s, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(x), Buffer.from(y));
};

// rate limit auth: 20 tries / minute / IP
const tries = new Map();
setInterval(() => tries.clear(), 60000);
const limited = ip => { const n = (tries.get(ip) || 0) + 1; tries.set(ip, n); return n > 20; };

const readBody = req => new Promise(res => {
  let b = ''; req.on('data', c => { b += c; if (b.length > 5000) req.destroy(); });
  req.on('end', () => { try { res(JSON.parse(b)); } catch { res({}); } });
});
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

const server = http.createServer(async (req, res) => {
  try {
    const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress;
    if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
    }
    if (req.method === 'POST' && (req.url === '/api/register' || req.url === '/api/login')) {
      if (limited(ip)) return send(res, 429, { error: 'محاولات كثيرة، حاول بعد قليل' });
      const { username = '', password = '' } = await readBody(req);
      const u = String(username).trim().toLowerCase();
      if (!/^[a-z0-9_]{3,20}$/.test(u)) return send(res, 400, { error: 'الاسم: 3-20 حرفاً (a-z و 0-9 و _)' });
      if (String(password).length < 6) return send(res, 400, { error: 'كلمة السر 6 أحرف على الأقل' });
      if (req.url === '/api/register') {
        const r = await pool.query('INSERT INTO users(username,hash,created) VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [u, hash(String(password)), Date.now()]);
        if (r.rowCount === 0) return send(res, 400, { error: 'الاسم مستعمل من قبل' });
      } else {
        const r = await pool.query('SELECT hash FROM users WHERE username=$1', [u]);
        if (!r.rows[0] || !verify(String(password), r.rows[0].hash)) return send(res, 401, { error: 'الاسم أو كلمة السر غير صحيحة' });
      }
      const token = crypto.randomBytes(32).toString('hex');
      await pool.query('INSERT INTO sessions(token,username,created) VALUES($1,$2,$3)', [token, u, Date.now()]);
      return send(res, 200, { token, username: u });
    }
    res.writeHead(404); res.end('Not found');
  } catch (e) { console.error(e); send(res, 500, { error: 'خطأ في الخادم' }); }
});

const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 2000 });
wss.on('connection', async (ws, req) => {
  try {
    const token = new URL(req.url, 'http://x').searchParams.get('token') || '';
    const r = await pool.query('SELECT username FROM sessions WHERE token=$1', [token]);
    if (!r.rows[0]) return ws.close(4001, 'unauthorized');
    ws.user = r.rows[0].username; ws.last = 0;
    const h = await pool.query('SELECT username AS u, text, ts FROM messages ORDER BY id DESC LIMIT 100');
    ws.send(JSON.stringify({ type: 'history', messages: h.rows.reverse().map(m => ({ ...m, ts: Number(m.ts) })) }));
    ws.on('message', async raw => {
      let d; try { d = JSON.parse(raw); } catch { return; }
      const text = String(d.text || '').trim().slice(0, 500);
      if (!text || Date.now() - ws.last < 400) return;
      ws.last = Date.now();
      const msg = { u: ws.user, text, ts: Date.now() };
      try { await pool.query('INSERT INTO messages(username,text,ts) VALUES($1,$2,$3)', [msg.u, msg.text, msg.ts]); } catch (e) { return console.error(e); }
      const out = JSON.stringify({ type: 'msg', msg });
      wss.clients.forEach(c => c.readyState === 1 && c.send(out));
    });
  } catch (e) { console.error(e); ws.close(); }
});

init().then(() => {
  server.listen(process.env.PORT || 3000, () => console.log('Chat running'));
}).catch(e => { console.error('DB init failed', e); process.exit(1); });
