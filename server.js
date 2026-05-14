/**
 * DoceGestão Pro — Backend API v2.0
 * ─────────────────────────────────────────────────────────
 * Express + sql.js (SQLite puro JS — sem compilação nativa)
 * Deploy: Render.com (free tier) ✅
 * ─────────────────────────────────────────────────────────
 */
'use strict';

const express   = require('express');
const cors      = require('cors');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path      = require('path');
const fs        = require('fs');
const initSqlJs = require('sql.js');

// ── Config ────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'doce-secret-' + Date.now();
const ADMIN_PASS = process.env.ADMIN_PASS || 'Doce@2025';
const DATA_DIR   = process.env.DATA_DIR || '/tmp';
const DB_PATH    = path.join(DATA_DIR, 'docegestao.db');

// ── Banco de dados ────────────────────────────────────────
let db;

function persistDb() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_PATH, Buffer.from(data));
  } catch(e) { console.error('[DB] persist error:', e.message); }
}

async function initDb() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
    console.log('DB carregado:', DB_PATH);
  } else {
    db = new SQL.Database();
    console.log('DB novo:', DB_PATH);
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL, role TEXT NOT NULL,
      password_hash TEXT NOT NULL, created_at TEXT, active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY, device_name TEXT NOT NULL,
      device_key TEXT UNIQUE NOT NULL, authorized INTEGER DEFAULT 0,
      last_seen TEXT, created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS products (
      id TEXT PRIMARY KEY, name TEXT NOT NULL,
      category TEXT DEFAULT 'Outros', cost REAL DEFAULT 0,
      sell REAL DEFAULT 0, stock INTEGER DEFAULT 0,
      batch_cost REAL DEFAULT NULL, batch_qty INTEGER DEFAULT NULL,
      active INTEGER DEFAULT 1, created_by TEXT,
      updated_at TEXT, created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS movements (
      id TEXT PRIMARY KEY, type TEXT NOT NULL,
      description TEXT NOT NULL, value REAL NOT NULL,
      date TEXT NOT NULL, category TEXT,
      product_id TEXT, created_by TEXT,
      device_id TEXT, created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY, event TEXT NOT NULL,
      message TEXT NOT NULL, username TEXT,
      device_id TEXT, ip_address TEXT, created_at TEXT
    );
  `);
  persistDb();
}

// ── Query helpers ─────────────────────────────────────────
function dbAll(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } catch(e) { console.error('[DB] dbAll:', e.message); return []; }
}
function dbGet(sql, params = []) { return dbAll(sql, params)[0] || null; }
function dbRun(sql, params = []) {
  try { db.run(sql, params); persistDb(); return true; }
  catch(e) { console.error('[DB] dbRun:', e.message); return false; }
}

const now = () => new Date().toISOString();
const getIp = req => req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '?';

function auditLog(event, message, username, deviceId, ip) {
  dbRun('INSERT INTO audit_logs (id,event,message,username,device_id,ip_address,created_at) VALUES (?,?,?,?,?,?,?)',
    [uuidv4(), event, message, username||null, deviceId||null, ip||null, now()]);
}

// ── Rate limit ────────────────────────────────────────────
const loginAttempts = new Map();
function rateLimit(req, res, next) {
  const r = loginAttempts.get(getIp(req)) || { count:0, until:0 };
  if (r.until > Date.now()) return res.status(429).json({ error: `Muitas tentativas. Aguarde ${Math.ceil((r.until-Date.now())/60000)} min.` });
  next();
}

// ── Express ───────────────────────────────────────────────
const app = express();
app.use(cors({ origin:'*', methods:['GET','POST','PUT','DELETE','PATCH'], allowedHeaders:['Content-Type','Authorization','X-Device-Key'] }));
app.use(express.json({ limit:'2mb' }));

// ── Auth middlewares ──────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autenticado.' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Sessão expirada. Faça login novamente.' }); }
}
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Acesso negado.' });
  next();
}
function requireDevice(req, res, next) {
  const key = req.headers['x-device-key'];
  if (!key) return res.status(403).json({ error: 'Dispositivo não identificado.' });

  // Admin: autoriza o dispositivo automaticamente
  if (req.user?.role === 'admin') {
    let device = dbGet('SELECT * FROM devices WHERE device_key = ?', [key]);
    if (!device) {
      dbRun('INSERT INTO devices (id,device_name,device_key,authorized,created_at) VALUES (?,?,?,1,?)',
        [uuidv4(), 'PC Admin (auto-autorizado)', key, now()]);
      device = dbGet('SELECT * FROM devices WHERE device_key = ?', [key]);
    } else if (!device.authorized) {
      dbRun('UPDATE devices SET authorized=1 WHERE device_key = ?', [key]);
      device = dbGet('SELECT * FROM devices WHERE device_key = ?', [key]);
    }
    req.device = device;
    dbRun('UPDATE devices SET last_seen = ? WHERE device_key = ?', [now(), key]);
    return next();
  }

  // Funcionários precisam de autorização manual
  const device = dbGet('SELECT * FROM devices WHERE device_key = ?', [key]);
  if (!device) return res.status(403).json({ error: 'Dispositivo desconhecido. Solicite autorização ao administrador.' });
  if (!device.authorized) return res.status(403).json({ error: 'Dispositivo aguardando autorização do administrador.' });
  req.device = device;
  dbRun('UPDATE devices SET last_seen = ? WHERE device_key = ?', [now(), key]);
  next();
}

// ══════════════════════════════════════════════════════════
//  ROTAS PÚBLICAS
// ══════════════════════════════════════════════════════════
app.get('/health', (req, res) => res.json({ status:'ok', timestamp:now() }));

app.post('/api/devices/register', (req, res) => {
  const { deviceKey, deviceName } = req.body;
  if (!deviceKey || !deviceName) return res.status(400).json({ error: 'deviceKey e deviceName obrigatórios.' });
  const existing = dbGet('SELECT * FROM devices WHERE device_key = ?', [deviceKey]);
  if (existing) return res.json({ authorized: !!existing.authorized, message: existing.authorized ? 'Autorizado.' : 'Aguardando autorização.' });
  dbRun('INSERT INTO devices (id,device_name,device_key,authorized,created_at) VALUES (?,?,?,0,?)', [uuidv4(), deviceName.slice(0,80), deviceKey, now()]);
  auditLog('device_pending', `Novo dispositivo: ${deviceName}`, null, null, getIp(req));
  res.json({ authorized: false, message: 'Registrado. Aguardando autorização.' });
});

app.post('/api/auth/login', rateLimit, async (req, res) => {
  const { username, password, deviceKey } = req.body;
  const ip = getIp(req);
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios.' });
  const user = dbGet('SELECT * FROM users WHERE username = ? AND active = 1', [username.toLowerCase().trim()]);
  const hash = user?.password_hash || '$2a$10$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
  const valid = await bcrypt.compare(password, hash);
  if (!user || !valid) {
    const key = getIp(req);
    const r = loginAttempts.get(key) || { count:0, until:0 };
    r.count++;
    if (r.count >= 3) r.until = Date.now() + [0,0,30000,120000,300000,900000][Math.min(r.count,5)];
    loginAttempts.set(key, r);
    auditLog('login_failed', `Login falhou: ${username}`, username, null, ip);
    return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  }
  if (user.role !== 'admin' && deviceKey) {
    const device = dbGet('SELECT * FROM devices WHERE device_key = ?', [deviceKey]);
    if (!device) return res.status(403).json({ error: 'Dispositivo não registrado.' });
    if (!device.authorized) return res.status(403).json({ error: 'Dispositivo aguardando autorização.' });
  }
  loginAttempts.delete(getIp(req));
  const token = jwt.sign({ id:user.id, username:user.username, displayName:user.display_name, role:user.role }, JWT_SECRET, { expiresIn:'8h' });
  auditLog('login_success', `${user.display_name} entrou no sistema`, user.username, null, ip);
  res.json({ token, user:{ id:user.id, username:user.username, displayName:user.display_name, role:user.role } });
});

// ══════════════════════════════════════════════════════════
//  ROTAS PROTEGIDAS
// ══════════════════════════════════════════════════════════

// Produtos
app.get('/api/products', requireAuth, requireDevice, (req, res) =>
  res.json(dbAll("SELECT * FROM products WHERE active=1 ORDER BY name")));

app.post('/api/products', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const { name, category, cost, sell, stock, batch_cost, batch_qty } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório.' });
  const id = uuidv4();
  dbRun('INSERT INTO products (id,name,category,cost,sell,stock,batch_cost,batch_qty,created_by,updated_at,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [id, name, category||'Outros', cost||0, sell||0, stock||0, batch_cost||null, batch_qty||null, req.user.id, now(), now()]);
  auditLog('product_create', `Produto criado: ${name}`, req.user.username, req.device?.id, getIp(req));
  res.json({ id, name, category, cost, sell, stock, batch_cost, batch_qty });
});

app.put('/api/products/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const { name, category, cost, sell, stock, batch_cost, batch_qty } = req.body;
  if (!dbGet('SELECT id FROM products WHERE id=?', [req.params.id])) return res.status(404).json({ error: 'Produto não encontrado.' });
  dbRun('UPDATE products SET name=?,category=?,cost=?,sell=?,stock=?,batch_cost=?,batch_qty=?,updated_at=? WHERE id=?',
    [name, category, cost, sell, stock, batch_cost||null, batch_qty||null, now(), req.params.id]);
  auditLog('product_update', `Produto editado: ${name}`, req.user.username, req.device?.id, getIp(req));
  res.json({ ok:true });
});

app.delete('/api/products/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const p = dbGet('SELECT name FROM products WHERE id=?', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Produto não encontrado.' });
  dbRun('UPDATE products SET active=0 WHERE id=?', [req.params.id]);
  auditLog('product_delete', `Produto excluído: ${p.name}`, req.user.username, req.device?.id, getIp(req));
  res.json({ ok:true });
});

app.patch('/api/products/:id/stock', requireAuth, requireDevice, (req, res) => {
  const { stock, delta } = req.body;
  const p = dbGet('SELECT * FROM products WHERE id=?', [req.params.id]);
  if (!p) return res.status(404).json({ error: 'Produto não encontrado.' });
  const newStock = typeof delta === 'number' ? Math.max(0,(p.stock||0)+delta) : typeof stock === 'number' ? Math.max(0,stock) : null;
  if (newStock === null) return res.status(400).json({ error: 'Informe stock ou delta.' });
  dbRun('UPDATE products SET stock=?,updated_at=? WHERE id=?', [newStock, now(), req.params.id]);
  auditLog('stock_update', `Estoque "${p.name}": ${p.stock} → ${newStock}`, req.user.username, req.device?.id, getIp(req));
  res.json({ stock: newStock });
});

// Movimentações
app.get('/api/movements', requireAuth, requireDevice, (req, res) => {
  const { type, limit=200 } = req.query;
  const lim = parseInt(limit);
  res.json(type && type !== 'all'
    ? dbAll('SELECT * FROM movements WHERE type=? ORDER BY date DESC, created_at DESC LIMIT ?', [type, lim])
    : dbAll('SELECT * FROM movements ORDER BY date DESC, created_at DESC LIMIT ?', [lim]));
});

app.post('/api/movements', requireAuth, requireDevice, (req, res) => {
  const { type, description, value, date, category, productId, quantity } = req.body;
  if (!type||!description||!value) return res.status(400).json({ error: 'Campos obrigatórios: type, description, value.' });
  if (!['in','out'].includes(type)) return res.status(400).json({ error: 'type deve ser "in" ou "out".' });
  if (req.user.role === 'staff' && type === 'out') return res.status(403).json({ error: 'Funcionários só podem registrar vendas.' });
  const qty = parseInt(quantity)||1;
  const id = uuidv4();
  dbRun('INSERT INTO movements (id,type,description,value,date,category,product_id,created_by,device_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
    [id, type, description, value, date, category||null, productId||null, req.user.id, req.device?.id, now()]);
  // Desconta a quantidade exata do estoque
  if (productId && type === 'in') {
    const p = dbGet('SELECT stock,name FROM products WHERE id=?', [productId]);
    if (p) {
      const newStock = Math.max(0, (p.stock||0) - qty);
      dbRun('UPDATE products SET stock=?,updated_at=? WHERE id=?', [newStock, now(), productId]);
      auditLog('stock_update', `Estoque "${p.name}": ${p.stock} → ${newStock} (venda de ${qty}un)`, req.user.username, req.device?.id, getIp(req));
    }
  }
  auditLog('movement_create', `${type==='in'?'Venda':'Saída'}: ${description} — R$ ${value}`, req.user.username, req.device?.id, getIp(req));
  res.json({ id, type, description, value, date, category });
});

app.delete('/api/movements/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const m = dbGet('SELECT * FROM movements WHERE id=?', [req.params.id]);
  if (!m) return res.status(404).json({ error: 'Movimentação não encontrada.' });
  dbRun('DELETE FROM movements WHERE id=?', [req.params.id]);
  auditLog('movement_delete', `Movimentação excluída: ${m.description}`, req.user.username, req.device?.id, getIp(req));
  res.json({ ok:true });
});

// Usuários
app.get('/api/users', requireAuth, requireDevice, requireAdmin, (req, res) =>
  res.json(dbAll("SELECT id,username,display_name,role,created_at,active FROM users ORDER BY role,display_name")));

app.post('/api/users', requireAuth, requireDevice, requireAdmin, async (req, res) => {
  const { username, displayName, password, role='staff' } = req.body;
  if (!username||!displayName||!password) return res.status(400).json({ error: 'Campos obrigatórios.' });
  if (dbGet('SELECT id FROM users WHERE username=?', [username.toLowerCase()])) return res.status(409).json({ error: 'Usuário já existe.' });
  const hash = await bcrypt.hash(password, 10);
  const id = uuidv4();
  dbRun('INSERT INTO users (id,username,display_name,role,password_hash,created_at) VALUES (?,?,?,?,?,?)',
    [id, username.toLowerCase(), displayName, role, hash, now()]);
  auditLog('user_create', `Funcionário criado: ${displayName} (@${username})`, req.user.username, req.device?.id, getIp(req));
  res.json({ id, username, displayName, role });
});

app.put('/api/users/:id', requireAuth, requireDevice, requireAdmin, async (req, res) => {
  const { displayName, password } = req.body;
  const user = dbGet('SELECT * FROM users WHERE id=?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (displayName) dbRun('UPDATE users SET display_name=? WHERE id=?', [displayName, req.params.id]);
  if (password) { const h = await bcrypt.hash(password, 10); dbRun('UPDATE users SET password_hash=? WHERE id=?', [h, req.params.id]); }
  auditLog('user_update', `Funcionário editado: ${displayName||user.display_name}`, req.user.username, req.device?.id, getIp(req));
  res.json({ ok:true });
});

app.delete('/api/users/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const user = dbGet('SELECT * FROM users WHERE id=?', [req.params.id]);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (user.username === 'admin') return res.status(400).json({ error: 'Não é possível remover o admin.' });
  dbRun('UPDATE users SET active=0 WHERE id=?', [req.params.id]);
  auditLog('user_delete', `Funcionário removido: ${user.display_name}`, req.user.username, req.device?.id, getIp(req));
  res.json({ ok:true });
});

app.post('/api/auth/change-password', requireAuth, requireDevice, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword||!newPassword) return res.status(400).json({ error: 'Campos obrigatórios.' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Nova senha: mínimo 6 caracteres.' });
  const user = dbGet('SELECT * FROM users WHERE id=?', [req.user.id]);
  if (!await bcrypt.compare(currentPassword, user.password_hash)) return res.status(401).json({ error: 'Senha atual incorreta.' });
  const h = await bcrypt.hash(newPassword, 10);
  dbRun('UPDATE users SET password_hash=? WHERE id=?', [h, req.user.id]);
  auditLog('password_change', `Senha alterada por ${req.user.username}`, req.user.username, req.device?.id, getIp(req));
  res.json({ ok:true });
});

// Dispositivos
app.get('/api/devices', requireAuth, requireDevice, requireAdmin, (req, res) =>
  res.json(dbAll('SELECT * FROM devices ORDER BY authorized DESC, created_at DESC')));

app.patch('/api/devices/:id/authorize', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const { authorized } = req.body;
  const device = dbGet('SELECT * FROM devices WHERE id=?', [req.params.id]);
  if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado.' });
  dbRun('UPDATE devices SET authorized=? WHERE id=?', [authorized?1:0, req.params.id]);
  auditLog(authorized?'device_authorized':'device_revoked',
    `Dispositivo "${device.device_name}" ${authorized?'autorizado':'revogado'}`,
    req.user.username, req.device?.id, getIp(req));
  res.json({ ok:true });
});

app.delete('/api/devices/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const device = dbGet('SELECT * FROM devices WHERE id=?', [req.params.id]);
  if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado.' });
  dbRun('DELETE FROM devices WHERE id=?', [req.params.id]);
  auditLog('device_deleted', `Dispositivo removido: ${device.device_name}`, req.user.username, req.device?.id, getIp(req));
  res.json({ ok:true });
});

// Auditoria
app.get('/api/audit', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const { category, limit=200 } = req.query;
  const lim = parseInt(limit);
  res.json(category && category !== 'all'
    ? dbAll('SELECT * FROM audit_logs WHERE event LIKE ? ORDER BY created_at DESC LIMIT ?', [category+'%', lim])
    : dbAll('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?', [lim]));
});

// Dashboard
app.get('/api/dashboard', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const totalIn  = dbGet("SELECT COALESCE(SUM(value),0) as v FROM movements WHERE type='in'")?.v || 0;
  const totalOut = dbGet("SELECT COALESCE(SUM(value),0) as v FROM movements WHERE type='out'")?.v || 0;
  const products = dbGet("SELECT COUNT(*) as v FROM products WHERE active=1")?.v || 0;
  const lowStock = dbGet("SELECT COUNT(*) as v FROM products WHERE active=1 AND stock < 5")?.v || 0;
  const pending  = dbGet("SELECT COUNT(*) as v FROM devices WHERE authorized=0")?.v || 0;
  res.json({ totalIn, totalOut, profit: totalIn-totalOut, products, lowStock, pendingDevices: pending });
});

// ── Iniciar ───────────────────────────────────────────────
async function start() {
  await initDb();

  if (!dbGet('SELECT id FROM users WHERE username=?', ['admin'])) {
    const hash = await bcrypt.hash(ADMIN_PASS, 10);
    dbRun('INSERT INTO users (id,username,display_name,role,password_hash,created_at) VALUES (?,?,?,?,?,?)',
      [uuidv4(), 'admin', 'Administrador', 'admin', hash, now()]);
    console.log('✅ Admin criado');
  }

  app.listen(PORT, () => {
    console.log(`🍬 DoceGestão API porta ${PORT} | DB: ${DB_PATH}`);
  });
}

start().catch(e => { console.error('Erro fatal:', e); process.exit(1); });
