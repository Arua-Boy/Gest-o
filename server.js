/**
 * DoceGestão Pro — Backend API
 * ─────────────────────────────────────────────────────────
 * Express + SQLite (better-sqlite3) + JWT
 * Deploy: Render.com (free tier)
 * ─────────────────────────────────────────────────────────
 */
'use strict';

const express  = require('express');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path     = require('path');
const fs       = require('fs');

// ── Config ────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'doce-gestao-secret-change-in-production';
const ADMIN_PASS = process.env.ADMIN_PASS || 'Doce@2025';

// Render.com usa /tmp para dados persistentes no free tier
// Em produção defina DATA_DIR como variável de ambiente se quiser outro local
const DATA_DIR = process.env.DATA_DIR || '/tmp';
const DB_PATH  = path.join(DATA_DIR, 'docegestao.db');

// ── Database ──────────────────────────────────────────────
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Cria tabelas
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,
    username    TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    role        TEXT NOT NULL CHECK(role IN ('admin','staff')),
    password_hash TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    active      INTEGER DEFAULT 1
  );

  CREATE TABLE IF NOT EXISTS devices (
    id          TEXT PRIMARY KEY,
    device_name TEXT NOT NULL,
    device_key  TEXT UNIQUE NOT NULL,
    user_id     TEXT,
    authorized  INTEGER DEFAULT 0,
    last_seen   TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS products (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    category    TEXT NOT NULL,
    cost        REAL NOT NULL DEFAULT 0,
    sell        REAL NOT NULL DEFAULT 0,
    stock       INTEGER NOT NULL DEFAULT 0,
    active      INTEGER DEFAULT 1,
    created_by  TEXT,
    updated_at  TEXT DEFAULT (datetime('now')),
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS movements (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL CHECK(type IN ('in','out')),
    description TEXT NOT NULL,
    value       REAL NOT NULL,
    date        TEXT NOT NULL,
    category    TEXT,
    product_id  TEXT,
    created_by  TEXT,
    device_id   TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (product_id) REFERENCES products(id)
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT PRIMARY KEY,
    event       TEXT NOT NULL,
    message     TEXT NOT NULL,
    user_id     TEXT,
    username    TEXT,
    device_id   TEXT,
    ip_address  TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT
  );
`);

// ── Seed admin padrão ─────────────────────────────────────
function seedAdmin() {
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (!existing) {
    const hash = bcrypt.hashSync(ADMIN_PASS, 10);
    db.prepare(`
      INSERT INTO users (id, username, display_name, role, password_hash)
      VALUES (?, 'admin', 'Administrador', 'admin', ?)
    `).run(uuidv4(), hash);
    console.log('✅ Admin criado com sucesso');
  }
}
seedAdmin();

// ── Express ───────────────────────────────────────────────
const app = express();

app.use(cors({
  origin: '*', // Em produção, defina o domínio do seu frontend
  methods: ['GET','POST','PUT','DELETE','PATCH'],
  allowedHeaders: ['Content-Type','Authorization','X-Device-Key'],
}));
app.use(express.json({ limit: '2mb' }));

// ── Helpers ───────────────────────────────────────────────
const now = () => new Date().toISOString();

function auditLog(event, message, userId, username, deviceId, ip) {
  try {
    db.prepare(`
      INSERT INTO audit_logs (id, event, message, user_id, username, device_id, ip_address, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(uuidv4(), event, message, userId||null, username||null, deviceId||null, ip||null, now());
  } catch(e) {
    console.error('Audit log error:', e.message);
  }
}

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '?';
}

// ── Middlewares ───────────────────────────────────────────

// Verifica JWT
function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Não autenticado.' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

// Verifica se é admin
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
  next();
}

// Verifica se o dispositivo está autorizado
function requireDevice(req, res, next) {
  const deviceKey = req.headers['x-device-key'];
  if (!deviceKey) return res.status(403).json({ error: 'Dispositivo não identificado.' });

  const device = db.prepare('SELECT * FROM devices WHERE device_key = ?').get(deviceKey);
  if (!device) return res.status(403).json({ error: 'Dispositivo desconhecido. Solicite autorização ao administrador.' });
  if (!device.authorized) return res.status(403).json({ error: 'Dispositivo aguardando autorização do administrador.' });

  req.device = device;

  // Atualiza last_seen
  db.prepare('UPDATE devices SET last_seen = ? WHERE device_key = ?').run(now(), deviceKey);
  next();
}

// Rate limiting simples em memória
const loginAttempts = new Map();
function rateLimit(req, res, next) {
  const key = getClientIp(req);
  const record = loginAttempts.get(key) || { count: 0, until: 0 };
  if (record.until > Date.now()) {
    const mins = Math.ceil((record.until - Date.now()) / 60000);
    return res.status(429).json({ error: `Muitas tentativas. Aguarde ${mins} min.` });
  }
  next();
}

// ═══════════════════════════════════════════════════════════
//  ROTAS PÚBLICAS
// ═══════════════════════════════════════════════════════════

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: now() });
});

// ── Registro de dispositivo (antes do login) ──────────────
app.post('/api/devices/register', (req, res) => {
  const { deviceKey, deviceName } = req.body;
  if (!deviceKey || !deviceName) return res.status(400).json({ error: 'deviceKey e deviceName obrigatórios.' });

  const existing = db.prepare('SELECT * FROM devices WHERE device_key = ?').get(deviceKey);
  if (existing) {
    // Retorna status atual
    return res.json({
      authorized: !!existing.authorized,
      message: existing.authorized ? 'Dispositivo autorizado.' : 'Aguardando autorização do administrador.',
    });
  }

  // Registra novo dispositivo como pendente
  db.prepare(`
    INSERT INTO devices (id, device_name, device_key, authorized, created_at)
    VALUES (?, ?, ?, 0, ?)
  `).run(uuidv4(), deviceName.slice(0,80), deviceKey, now());

  auditLog('device_pending', `Novo dispositivo solicitando acesso: ${deviceName}`, null, null, null, getClientIp(req));

  res.json({ authorized: false, message: 'Dispositivo registrado. Aguardando autorização do administrador.' });
});

// ── Login ─────────────────────────────────────────────────
app.post('/api/auth/login', rateLimit, async (req, res) => {
  const { username, password, deviceKey } = req.body;
  const ip = getClientIp(req);

  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios.' });

  const user = db.prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(username.toLowerCase().trim());

  // Timing-safe: sempre faz o bcrypt mesmo se user não existe
  const hashToCheck = user?.password_hash || '$2a$10$invalidhashtopreventtimingattacks';
  const valid = await bcrypt.compare(password, hashToCheck);

  if (!user || !valid) {
    // Rate limit
    const key = getClientIp(req);
    const record = loginAttempts.get(key) || { count: 0, until: 0 };
    record.count++;
    if (record.count >= 5) record.until = Date.now() + [0,0,30000,120000,300000,900000][Math.min(record.count,5)];
    loginAttempts.set(key, record);

    auditLog('login_failed', `Login falhou: ${username}`, null, username, null, ip);
    return res.status(401).json({ error: 'Usuário ou senha inválidos.' });
  }

  // Verifica dispositivo (admin fica isento da verificação de dispositivo)
  if (user.role !== 'admin' && deviceKey) {
    const device = db.prepare('SELECT * FROM devices WHERE device_key = ?').get(deviceKey);
    if (!device) return res.status(403).json({ error: 'Dispositivo não registrado.' });
    if (!device.authorized) return res.status(403).json({ error: 'Dispositivo aguardando autorização.' });
  }

  // Limpa rate limit
  loginAttempts.delete(getClientIp(req));

  // Gera token JWT (8h)
  const token = jwt.sign(
    { id: user.id, username: user.username, displayName: user.display_name, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  auditLog('login_success', `${user.display_name} entrou no sistema`, user.id, user.username, null, ip);

  res.json({
    token,
    user: { id: user.id, username: user.username, displayName: user.display_name, role: user.role },
  });
});

// ═══════════════════════════════════════════════════════════
//  ROTAS PROTEGIDAS
// ═══════════════════════════════════════════════════════════

// ── Produtos ──────────────────────────────────────────────
app.get('/api/products', requireAuth, requireDevice, (req, res) => {
  const products = db.prepare("SELECT * FROM products WHERE active = 1 ORDER BY name").all();
  res.json(products);
});

app.post('/api/products', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const { name, category, cost, sell, stock } = req.body;
  if (!name) return res.status(400).json({ error: 'Nome obrigatório.' });
  const id = uuidv4();
  db.prepare(`
    INSERT INTO products (id, name, category, cost, sell, stock, created_by, updated_at, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, name, category||'Outros', cost||0, sell||0, stock||0, req.user.id, now(), now());
  auditLog('product_create', `Produto criado: ${name}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ id, name, category, cost, sell, stock });
});

app.put('/api/products/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const { name, category, cost, sell, stock } = req.body;
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).json({ error: 'Produto não encontrado.' });
  db.prepare(`
    UPDATE products SET name=?, category=?, cost=?, sell=?, stock=?, updated_at=? WHERE id=?
  `).run(name, category, cost, sell, stock, now(), req.params.id);
  auditLog('product_update', `Produto editado: ${name}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ ok: true });
});

app.delete('/api/products/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const product = db.prepare('SELECT name FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).json({ error: 'Produto não encontrado.' });
  db.prepare('UPDATE products SET active = 0 WHERE id = ?').run(req.params.id);
  auditLog('product_delete', `Produto excluído: ${product.name}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ ok: true });
});

// Ajuste de estoque
app.patch('/api/products/:id/stock', requireAuth, requireDevice, (req, res) => {
  const { stock, delta } = req.body;
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!product) return res.status(404).json({ error: 'Produto não encontrado.' });

  let newStock;
  if (typeof delta === 'number') {
    newStock = Math.max(0, (product.stock || 0) + delta);
  } else if (typeof stock === 'number') {
    newStock = Math.max(0, stock);
  } else {
    return res.status(400).json({ error: 'Informe stock ou delta.' });
  }

  db.prepare('UPDATE products SET stock=?, updated_at=? WHERE id=?').run(newStock, now(), req.params.id);
  auditLog('stock_update', `Estoque "${product.name}": ${product.stock} → ${newStock}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ stock: newStock });
});

// ── Movimentações ─────────────────────────────────────────
app.get('/api/movements', requireAuth, requireDevice, (req, res) => {
  const { type, limit = 200 } = req.query;
  let q = 'SELECT * FROM movements';
  const params = [];
  if (type && type !== 'all') { q += ' WHERE type = ?'; params.push(type); }
  q += ' ORDER BY date DESC, created_at DESC LIMIT ?';
  params.push(parseInt(limit));
  const movements = db.prepare(q).all(...params);
  res.json(movements);
});

app.post('/api/movements', requireAuth, requireDevice, (req, res) => {
  const { type, description, value, date, category, productId } = req.body;
  if (!type || !description || !value) return res.status(400).json({ error: 'Campos obrigatórios: type, description, value.' });
  if (!['in','out'].includes(type)) return res.status(400).json({ error: 'type deve ser "in" ou "out".' });

  // Funcionário só pode registrar entradas
  if (req.user.role === 'staff' && type === 'out') {
    return res.status(403).json({ error: 'Funcionários só podem registrar vendas (entradas).' });
  }

  const id = uuidv4();
  db.prepare(`
    INSERT INTO movements (id, type, description, value, date, category, product_id, created_by, device_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, type, description, value, date, category||null, productId||null, req.user.id, req.device?.id, now());

  // Desconta estoque se produto vinculado
  if (productId && type === 'in') {
    const p = db.prepare('SELECT stock FROM products WHERE id = ?').get(productId);
    if (p && p.stock > 0) {
      db.prepare('UPDATE products SET stock=?, updated_at=? WHERE id=?')
        .run(Math.max(0, p.stock - 1), now(), productId);
    }
  }

  auditLog('movement_create', `${type==='in'?'Entrada':'Saída'}: ${description} — R$ ${value}`,
    req.user.id, req.user.username, req.device?.id, getClientIp(req));

  res.json({ id, type, description, value, date, category });
});

app.delete('/api/movements/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const mov = db.prepare('SELECT * FROM movements WHERE id = ?').get(req.params.id);
  if (!mov) return res.status(404).json({ error: 'Movimentação não encontrada.' });
  db.prepare('DELETE FROM movements WHERE id = ?').run(req.params.id);
  auditLog('movement_delete', `Movimentação excluída: ${mov.description}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ ok: true });
});

// ── Funcionários (admin only) ─────────────────────────────
app.get('/api/users', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const users = db.prepare("SELECT id, username, display_name, role, created_at, active FROM users ORDER BY role, display_name").all();
  res.json(users);
});

app.post('/api/users', requireAuth, requireDevice, requireAdmin, async (req, res) => {
  const { username, displayName, password, role = 'staff' } = req.body;
  if (!username || !displayName || !password) return res.status(400).json({ error: 'Campos obrigatórios.' });
  if (!['admin','staff'].includes(role)) return res.status(400).json({ error: 'Role inválida.' });
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Usuário já existe.' });
  const id = uuidv4();
  const hash = await bcrypt.hash(password, 10);
  db.prepare(`INSERT INTO users (id, username, display_name, role, password_hash) VALUES (?, ?, ?, ?, ?)`)
    .run(id, username.toLowerCase(), displayName, role, hash);
  auditLog('user_create', `Funcionário criado: ${displayName} (@${username})`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ id, username, displayName, role });
});

app.put('/api/users/:id', requireAuth, requireDevice, requireAdmin, async (req, res) => {
  const { displayName, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (displayName) db.prepare('UPDATE users SET display_name = ? WHERE id = ?').run(displayName, req.params.id);
  if (password) {
    const hash = await bcrypt.hash(password, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.params.id);
  }
  auditLog('user_update', `Funcionário editado: ${displayName || user.display_name}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (user.username === 'admin') return res.status(400).json({ error: 'Não é possível remover o admin.' });
  db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(req.params.id);
  auditLog('user_delete', `Funcionário removido: ${user.display_name}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ ok: true });
});

// Troca de senha (usuário logado)
app.post('/api/auth/change-password', requireAuth, requireDevice, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Campos obrigatórios.' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Nova senha: mínimo 6 caracteres.' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!await bcrypt.compare(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Senha atual incorreta.' });
  }
  const hash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  auditLog('password_change', `Senha alterada por ${req.user.username}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ ok: true });
});

// ── Dispositivos (admin only) ─────────────────────────────
app.get('/api/devices', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const devices = db.prepare('SELECT * FROM devices ORDER BY authorized DESC, created_at DESC').all();
  res.json(devices);
});

app.patch('/api/devices/:id/authorize', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const { authorized } = req.body;
  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.id);
  if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado.' });
  db.prepare('UPDATE devices SET authorized = ? WHERE id = ?').run(authorized ? 1 : 0, req.params.id);
  auditLog(
    authorized ? 'device_authorized' : 'device_revoked',
    `Dispositivo "${device.device_name}" ${authorized ? 'autorizado' : 'revogado'}`,
    req.user.id, req.user.username, req.device?.id, getClientIp(req)
  );
  res.json({ ok: true });
});

app.delete('/api/devices/:id', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(req.params.id);
  if (!device) return res.status(404).json({ error: 'Dispositivo não encontrado.' });
  db.prepare('DELETE FROM devices WHERE id = ?').run(req.params.id);
  auditLog('device_deleted', `Dispositivo removido: ${device.device_name}`, req.user.id, req.user.username, req.device?.id, getClientIp(req));
  res.json({ ok: true });
});

// ── Audit logs (admin only) ───────────────────────────────
app.get('/api/audit', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const { category, limit = 200 } = req.query;
  let q = 'SELECT * FROM audit_logs';
  const params = [];
  if (category && category !== 'all') { q += ' WHERE event LIKE ?'; params.push(category + '%'); }
  q += ' ORDER BY created_at DESC LIMIT ?';
  params.push(parseInt(limit));
  const logs = db.prepare(q).all(...params);
  res.json(logs);
});

// ── Dashboard summary (admin only) ───────────────────────
app.get('/api/dashboard', requireAuth, requireDevice, requireAdmin, (req, res) => {
  const totalIn  = db.prepare("SELECT COALESCE(SUM(value),0) as v FROM movements WHERE type='in'").get().v;
  const totalOut = db.prepare("SELECT COALESCE(SUM(value),0) as v FROM movements WHERE type='out'").get().v;
  const products = db.prepare("SELECT COUNT(*) as v FROM products WHERE active=1").get().v;
  const lowStock = db.prepare("SELECT COUNT(*) as v FROM products WHERE active=1 AND stock < 5").get().v;
  const pending  = db.prepare("SELECT COUNT(*) as v FROM devices WHERE authorized=0").get().v;
  res.json({ totalIn, totalOut, profit: totalIn - totalOut, products, lowStock, pendingDevices: pending });
});

// ── Start ─────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🍬 DoceGestão API rodando na porta ${PORT}`);
  console.log(`   DB: ${DB_PATH}`);
});
