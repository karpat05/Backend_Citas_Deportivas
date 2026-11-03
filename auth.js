// auth.js - usuarios, contraseñas, tokens y permisos por rol
const crypto = require('crypto');
const db = require('./db');

// Clave para firmar los tokens. En producción se define con la variable de entorno TOKEN_SECRET.
const SECRET = process.env.TOKEN_SECRET || 'citas-deportivas-clave-de-desarrollo';
const TOKEN_TTL_MS = 8 * 60 * 60 * 1000; // el token dura 8 horas

// ---------- Tablas ----------
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('ADMIN', 'USER'))
  )
`);

// Cada cita pertenece a un usuario (las creadas por el admin quedan sin dueño)
const appointmentColumns = db.prepare('PRAGMA table_info(appointments)').all();
if (!appointmentColumns.some((c) => c.name === 'user_id')) {
  db.exec('ALTER TABLE appointments ADD COLUMN user_id INTEGER REFERENCES users(id)');
}

// ---------- Contraseñas (scrypt, viene incluido en Node) ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored).split(':');
  if (!salt || !hash) return false;
  const expected = Buffer.from(hash, 'hex');
  const test = crypto.scryptSync(password, salt, 64);
  return expected.length === test.length && crypto.timingSafeEqual(test, expected);
}

// ---------- Tokens firmados (HMAC-SHA256) ----------
function signToken(user) {
  const payload = Buffer.from(
    JSON.stringify({ id: user.id, role: user.role, exp: Date.now() + TOKEN_TTL_MS })
  ).toString('base64url');
  const signature = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function readToken(token) {
  const [payload, signature] = String(token).split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(payload).digest('base64url');
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Date.now() ? data : null;
  } catch (e) {
    return null;
  }
}

const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });

// ---------- Middleware ----------
// 401: no hay sesión o el token no sirve
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const data = readToken(token);
  const user = data ? db.prepare('SELECT * FROM users WHERE id = ?').get(data.id) : null;
  if (!user) return res.status(401).json({ error: 'Debes iniciar sesión' });
  req.user = publicUser(user);
  next();
}

// 403: hay sesión, pero el rol no tiene permiso
function requireRole(role) {
  return (req, res, next) => {
    if (req.user && req.user.role === role) return next();
    res.status(403).json({ error: 'No tienes permiso para realizar esta acción' });
  };
}

// ---------- Cuentas de prueba (solo si no existe ningún usuario) ----------
const total = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (Number(total) === 0) {
  const insert = db.prepare(
    'INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)'
  );
  insert.run('Administrador', 'admin@citas.com', hashPassword('admin123'), 'ADMIN');
  insert.run('Deportista de prueba', 'deportista@citas.com', hashPassword('usuario123'), 'USER');
}

module.exports = { hashPassword, verifyPassword, signToken, requireAuth, requireRole, publicUser };