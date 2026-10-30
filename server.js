const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');

const FILE = path.join(__dirname, 'data.json');
let db = { users: {}, sessions: {}, messages: [] };
try { db = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch {}
let timer;
const save = () => { clearTimeout(timer); timer = setTimeout(() => fs.writeFile(FILE, JSON.stringify(db), () => {}), 300); };

const hash = (p, salt = crypto.randomBytes(16).toString('hex')) =>
  salt + ':' + crypto.scryptSync(p, salt, 64).toString('hex');
const verify = (p, h) => {
  const [s, x] = h.split(':');
  const y = crypto.scryptSync(p, s, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(x), Buffer.from(y));
};

// simple rate limit for auth endpoints: 20 tries / minute / IP
const tries = new Map();
setInterval(() => tries.clear(), 60000);
const limited = ip => { const n = (tries.get(ip) || 0) + 1; tries.set(ip, n); return n > 20; };

const readBody = req => new Promise(res => {
  let b = ''; req.on('data', c => { b += c; if (b.length > 5000) req.destroy(); });
  req.on('end', () => { try { res(JSON.parse(b)); } catch { res({}); } });
});
const send = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };

const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress;
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(path.join(__dirname, 'index.html')));
  }
  if (req.method === 'POST' && (req.url === '/api/register' || req.url === '/api/login')) {
    if (limited(ip)) return send(res, 429, { error: 'Bezzaf mouhawalat, 3awed ba3d chwiya' });
    const { username = '', password = '' } = await readBody(req);
    const u = String(username).trim().toLowerCase();
    if (!/^[a-z0-9_]{3,20}$/.test(u)) return send(res, 400, { error: 'Smiya: 3-20 7arf (a-z, 0-9, _)' });
    if (String(password).length < 6) return send(res, 400, { error: 'Password lazem 6 7rouf 3la l a9al' });
    if (req.url === '/api/register') {
      if (db.users[u]) return send(res, 400, { error: 'Smiya mat9ouda deja' });
      db.users[u] = { hash: hash(String(password)), created: Date.now() };
    } else if (!db.users[u] || !verify(String(password), db.users[u].hash)) {
      return send(res, 401, { error: 'Smiya wela password ghalet' });
    }
    const token = crypto.randomBytes(32).toString('hex');
    db.sessions[token] = u; save();
    return send(res, 200, { token, username: u });
  }
  res.writeHead(404); res.end('Not found');
});

const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 2000 });
wss.on('connection', (ws, req) => {
  const token = new URL(req.url, 'http://x').searchParams.get('token');
  const user = db.sessions[token];
  if (!user) return ws.close(4001, 'unauthorized');
  ws.user = user; ws.last = 0;
  ws.send(JSON.stringify({ type: 'history', messages: db.messages.slice(-100) }));
  ws.on('message', raw => {
    let d; try { d = JSON.parse(raw); } catch { return; }
    const text = String(d.text || '').trim().slice(0, 500);
    if (!text || Date.now() - ws.last < 400) return;
    ws.last = Date.now();
    const msg = { u: user, text, ts: Date.now() };
    db.messages.push(msg); if (db.messages.length > 500) db.messages.shift(); save();
    const out = JSON.stringify({ type: 'msg', msg });
    wss.clients.forEach(c => c.readyState === 1 && c.send(out));
  });
});

server.listen(process.env.PORT || 3000, () => console.log('Chat running on port ' + (process.env.PORT || 3000)));
