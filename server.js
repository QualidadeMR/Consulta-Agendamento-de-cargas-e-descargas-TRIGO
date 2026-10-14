'use strict';
const express = require('express');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3');
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const USERNAME = process.env.PANEL_USERNAME;
const PASSWORD = process.env.PANEL_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'moinho-regio.sqlite');
const DB_DIR = path.dirname(DB_PATH);
if (!USERNAME || !PASSWORD || !SESSION_SECRET) {
  console.error('ERRO: configure PANEL_USERNAME, PANEL_PASSWORD e SESSION_SECRET nas variáveis de ambiente.');
  process.exit(1);
}
fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS shared_dataset (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  headers_json TEXT NOT NULL,
  rows_json TEXT NOT NULL,
  source TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
)`);

const SQLiteStore = SQLiteStoreFactory(session);
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.use(express.json({ limit: '25mb' }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DB_DIR }),
  name: 'moinho.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000 }
}));

// Small in-memory throttle for login attempts by IP.
const loginAttempts = new Map();
function isAuthenticated(req) { return Boolean(req.session && req.session.authenticated === true); }
function requireAuth(req, res, next) {
  if (isAuthenticated(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Sessão encerrada. Entre novamente.' });
  return res.redirect('/login');
}
const loginPage = (error = '') => `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acesso restrito · Moinho Regio</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f7f1e6;color:#4b2a13;font-family:Arial,sans-serif}.panel{width:min(92vw,410px);background:white;padding:32px;border-radius:18px;box-shadow:0 12px 40px #4b2a131c;border:1px solid #eadbc4}.brand{text-align:center;font-weight:800;font-size:24px;margin-bottom:8px}.sub{text-align:center;color:#73583d;margin-bottom:24px}.error{background:#fff0ed;color:#9b2c17;padding:10px;border-radius:8px;margin-bottom:14px;font-size:14px}label{display:block;font-weight:700;margin:14px 0 6px}input{width:100%;padding:12px;border:1px solid #d6c5ac;border-radius:8px;font-size:16px}button{width:100%;border:0;border-radius:8px;padding:13px;margin-top:20px;background:#7a3f08;color:white;font-size:16px;font-weight:700;cursor:pointer}small{display:block;text-align:center;margin-top:18px;color:#79664f}</style></head><body><main class="panel"><div class="brand">Moinho Regio</div><div class="sub">Painel de Qualidade · acesso restrito</div>${error ? `<div class="error">${error}</div>` : ''}<form method="post" action="/login"><label for="username">Usuário</label><input id="username" name="username" autocomplete="username" required autofocus><label for="password">Senha</label><input id="password" name="password" type="password" autocomplete="current-password" required><button type="submit">Entrar no painel</button></form><small>Acesso exclusivo para funcionários autorizados.</small></main></body></html>`;

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/login', (req, res) => {
  if (isAuthenticated(req)) return res.redirect('/');
  res.status(200).send(loginPage());
});
app.post('/login', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  const attempts = loginAttempts.get(ip) || { count: 0, until: now + 15 * 60 * 1000 };
  if (attempts.until < now) { attempts.count = 0; attempts.until = now + 15 * 60 * 1000; }
  if (attempts.count >= 8) return res.status(429).send(loginPage('Muitas tentativas. Aguarde 15 minutos e tente novamente.'));
  const username = String(req.body.username || '');
  const password = String(req.body.password || '');
  if (username !== USERNAME || password !== PASSWORD) {
    attempts.count += 1; loginAttempts.set(ip, attempts);
    return res.status(401).send(loginPage('Usuário ou senha incorretos.'));
  }
  loginAttempts.delete(ip);
  req.session.regenerate(err => {
    if (err) return res.status(500).send(loginPage('Não foi possível iniciar a sessão. Tente novamente.'));
    req.session.authenticated = true;
    req.session.username = username;
    req.session.save(err2 => err2 ? res.status(500).send(loginPage('Não foi possível salvar a sessão.')) : res.redirect('/'));
  });
});
app.post('/logout', requireAuth, (req, res) => req.session.destroy(() => res.redirect('/login')));

app.get('/api/data', requireAuth, (_req, res) => {
  const item = db.prepare('SELECT headers_json, rows_json, source, updated_at, updated_by FROM shared_dataset WHERE id = 1').get();
  if (!item) return res.json({ headers: [], rows: [], source: 'Aguardando primeira importação', updated_at: null, updated_by: null });
  res.set('Cache-Control', 'no-store');
  res.json({ headers: JSON.parse(item.headers_json), rows: JSON.parse(item.rows_json), source: item.source, updated_at: item.updated_at, updated_by: item.updated_by });
});
app.post('/api/import', requireAuth, (req, res) => {
  const body = req.body || {};
  if (!Array.isArray(body.headers) || !Array.isArray(body.rows)) return res.status(400).json({ error: 'Formato inválido: envie headers e rows.' });
  if (body.headers.length > 250 || body.rows.length > 200000) return res.status(413).json({ error: 'A planilha excede o limite permitido.' });
  if (body.rows.some(row => !Array.isArray(row) || row.length > 250)) return res.status(400).json({ error: 'Há linhas em formato inválido.' });
  const updatedAt = new Date().toISOString();
  const source = String(body.source || 'Planilha importada').slice(0, 200);
  const stmt = db.prepare(`INSERT INTO shared_dataset (id, headers_json, rows_json, source, updated_at, updated_by)
    VALUES (1, @headers, @rows, @source, @updated_at, @updated_by)
    ON CONFLICT(id) DO UPDATE SET headers_json=excluded.headers_json, rows_json=excluded.rows_json, source=excluded.source, updated_at=excluded.updated_at, updated_by=excluded.updated_by`);
  try {
    stmt.run({ headers: JSON.stringify(body.headers), rows: JSON.stringify(body.rows), source, updated_at: updatedAt, updated_by: req.session.username || 'funcionário' });
    res.json({ ok: true, updated_at: updatedAt, record_count: body.rows.length, source });
  } catch (err) {
    console.error('Falha ao salvar importação:', err.message);
    res.status(500).json({ error: 'Não foi possível salvar os dados compartilhados.' });
  }
});
app.use('/', requireAuth, express.static(__dirname, { index: 'index.html', dotfiles: 'deny', etag: false, maxAge: 0, setHeaders: res => res.set('Cache-Control', 'no-store') }));
app.use((err, _req, res, _next) => {
  console.error(err.message);
  res.status(err.status === 413 ? 413 : 500).json({ error: err.status === 413 ? 'Arquivo muito grande.' : 'Erro interno do servidor.' });
});
app.listen(PORT, '0.0.0.0', () => console.log(`Moinho Regio Painel API ativo na porta ${PORT}`));
