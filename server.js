const express = require('express');
const db = require('./db');
const auth = require('./auth');

const app = express();
app.use(express.json());

const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const STATUSES = ['PENDIENTE', 'ATENDIDA', 'CANCELADA'];

// ---------- Utilidades ----------
const isText = (v) => typeof v === 'string' && v.trim().length > 0;
const isAdmin = (req) => req.user.role === 'ADMIN';

const isValidDate = (v) => {
  if (typeof v !== 'string' || !DATE_RE.test(v)) return false;
  const d = new Date(v + 'T00:00:00Z');
  return !isNaN(d.getTime()) && d.toISOString().slice(0, 10) === v;
};

const toProfessional = (r) => ({
  id: r.id,
  name: r.name,
  specialty: r.specialty,
  attentionStart: r.attention_start,
  attentionEnd: r.attention_end,
});

const toAppointment = (r) => ({
  id: r.id,
  athleteName: r.athlete_name,
  professionalId: r.professional_id,
  date: r.date,
  startTime: r.start_time,
  endTime: r.end_time,
  status: r.status,
  reason: r.reason,
});

const fail = (res, code, message) => res.status(code).json({ error: message });

// ---------- Validaciones ----------
function checkProfessional(b) {
  if (!isText(b.name)) return 'El nombre es obligatorio';
  if (!isText(b.specialty)) return 'La especialidad es obligatoria';
  if (!TIME_RE.test(b.attentionStart || '') || !TIME_RE.test(b.attentionEnd || ''))
    return 'El horario de atención debe tener formato HH:MM (ejemplo: 08:00)';
  if (b.attentionStart >= b.attentionEnd)
    return 'La hora de fin de atención debe ser posterior a la de inicio';
  return null;
}

// Devuelve null si todo está bien, o { code, error }
function checkAppointment(b, excludeId = 0) {
  if (!isText(b.athleteName)) return { code: 400, error: 'El nombre del deportista es obligatorio' };
  if (!isText(b.reason)) return { code: 400, error: 'El motivo es obligatorio' };
  if (!Number.isInteger(b.professionalId))
    return { code: 400, error: 'professionalId debe ser un número entero' };
  if (!isValidDate(b.date))
    return { code: 400, error: 'La fecha debe tener formato AAAA-MM-DD y ser válida' };
  if (!TIME_RE.test(b.startTime || '') || !TIME_RE.test(b.endTime || ''))
    return { code: 400, error: 'Las horas deben tener formato HH:MM (ejemplo: 09:30)' };
  if (b.startTime >= b.endTime)
    return { code: 400, error: 'La hora de fin debe ser posterior a la hora de inicio' };

  const prof = db.prepare('SELECT * FROM professionals WHERE id = ?').get(b.professionalId);
  if (!prof) return { code: 404, error: 'El profesional no existe' };

  if (b.startTime < prof.attention_start || b.endTime > prof.attention_end)
    return {
      code: 400,
      error: `El profesional atiende de ${prof.attention_start} a ${prof.attention_end}`,
    };

  // REGLA DE NEGOCIO: no permitir cruces de horario
  const clash = db
    .prepare(
      `SELECT id FROM appointments
       WHERE professional_id = ? AND date = ? AND status != 'CANCELADA'
         AND id != ? AND start_time < ? AND end_time > ?`
    )
    .get(b.professionalId, b.date, excludeId, b.endTime, b.startTime);
  if (clash)
    return { code: 409, error: 'El profesional ya tiene una cita que se cruza con ese horario' };

  return null;
}

// ---------- AUTENTICACIÓN (públicas) ----------
app.post('/api/auth/login', (req, res) => {
  const b = req.body || {};
  if (!isText(b.email) || !isText(b.password))
    return fail(res, 400, 'El correo y la contraseña son obligatorios');
  const user = db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(b.email.trim().toLowerCase());
  if (!user || !auth.verifyPassword(b.password, user.password_hash))
    return fail(res, 401, 'Correo o contraseña incorrectos');
  res.json({ token: auth.signToken(user), user: auth.publicUser(user) });
});

// El registro siempre crea usuarios con rol USER; el rol ADMIN no se puede pedir desde la app
app.post('/api/auth/register', (req, res) => {
  const b = req.body || {};
  if (!isText(b.name)) return fail(res, 400, 'El nombre es obligatorio');
  if (!EMAIL_RE.test(b.email || '')) return fail(res, 400, 'El correo no es válido');
  if (typeof b.password !== 'string' || b.password.length < 6)
    return fail(res, 400, 'La contraseña debe tener al menos 6 caracteres');

  const email = b.email.trim().toLowerCase();
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email))
    return fail(res, 409, 'Ya existe una cuenta con ese correo');

  const info = db
    .prepare("INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, 'USER')")
    .run(b.name.trim(), email, auth.hashPassword(b.password));
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json({ token: auth.signToken(user), user: auth.publicUser(user) });
});

app.get('/api/auth/me', auth.requireAuth, (req, res) => res.json(req.user));

// Todo lo demás exige haber iniciado sesión
app.use('/api/professionals', auth.requireAuth);
app.use('/api/appointments', auth.requireAuth);

// ---------- PROFESIONALES ----------
// Ver: cualquier usuario con sesión. Crear, editar y eliminar: solo ADMIN
app.get('/api/professionals', (req, res) => {
  const rows = db.prepare('SELECT * FROM professionals ORDER BY name').all();
  res.json(rows.map(toProfessional));
});

app.get('/api/professionals/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM professionals WHERE id = ?').get(req.params.id);
  if (!row) return fail(res, 404, 'Profesional no encontrado');
  res.json(toProfessional(row));
});

app.post('/api/professionals', auth.requireRole('ADMIN'), (req, res) => {
  const msg = checkProfessional(req.body);
  if (msg) return fail(res, 400, msg);
  const b = req.body;
  const info = db
    .prepare(
      'INSERT INTO professionals (name, specialty, attention_start, attention_end) VALUES (?, ?, ?, ?)'
    )
    .run(b.name.trim(), b.specialty.trim(), b.attentionStart, b.attentionEnd);
  const row = db.prepare('SELECT * FROM professionals WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json(toProfessional(row));
});

app.put('/api/professionals/:id', auth.requireRole('ADMIN'), (req, res) => {
  const exists = db.prepare('SELECT id FROM professionals WHERE id = ?').get(req.params.id);
  if (!exists) return fail(res, 404, 'Profesional no encontrado');
  const msg = checkProfessional(req.body);
  if (msg) return fail(res, 400, msg);
  const b = req.body;
  db.prepare(
    'UPDATE professionals SET name = ?, specialty = ?, attention_start = ?, attention_end = ? WHERE id = ?'
  ).run(b.name.trim(), b.specialty.trim(), b.attentionStart, b.attentionEnd, req.params.id);
  const row = db.prepare('SELECT * FROM professionals WHERE id = ?').get(req.params.id);
  res.json(toProfessional(row));
});

app.delete('/api/professionals/:id', auth.requireRole('ADMIN'), (req, res) => {
  const exists = db.prepare('SELECT id FROM professionals WHERE id = ?').get(req.params.id);
  if (!exists) return fail(res, 404, 'Profesional no encontrado');
  const used = db
    .prepare('SELECT COUNT(*) AS c FROM appointments WHERE professional_id = ?')
    .get(req.params.id).c;
  if (used > 0)
    return fail(res, 409, 'No se puede eliminar: el profesional tiene citas registradas');
  db.prepare('DELETE FROM professionals WHERE id = ?').run(req.params.id);
  res.status(204).send();
});

// ---------- CITAS ----------
// ADMIN ve todas las citas. USER ve solo las suyas.
// Filtros opcionales: ?professionalId=1&date=2026-10-15&status=PENDIENTE
app.get('/api/appointments', (req, res) => {
  const where = [];
  const params = [];
  if (!isAdmin(req)) {
    where.push('user_id = ?');
    params.push(req.user.id);
  }
  if (req.query.professionalId) {
    where.push('professional_id = ?');
    params.push(req.query.professionalId);
  }
  if (req.query.date) {
    where.push('date = ?');
    params.push(req.query.date);
  }
  if (req.query.status) {
    where.push('status = ?');
    params.push(req.query.status);
  }
  const sql =
    'SELECT * FROM appointments' +
    (where.length ? ' WHERE ' + where.join(' AND ') : '') +
    ' ORDER BY date, start_time';
  res.json(db.prepare(sql).all(...params).map(toAppointment));
});

app.get('/api/appointments/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM appointments WHERE id = ?').get(req.params.id);
  if (!row || (!isAdmin(req) && row.user_id !== req.user.id))
    return fail(res, 404, 'Cita no encontrada');
  res.json(toAppointment(row));
});

// Cualquier usuario con sesión puede agendar. Si es USER, la cita queda a su nombre.
app.post('/api/appointments', (req, res) => {
  const b = isAdmin(req)
    ? { ...req.body }
    : { ...req.body, athleteName: req.user.name };
  const problem = checkAppointment(b);
  if (problem) return fail(res, problem.code, problem.error);
  const ownerId = isAdmin(req) ? null : req.user.id;
  const info = db
    .prepare(
      `INSERT INTO appointments
       (athlete_name, professional_id, date, start_time, end_time, status, reason, user_id)
       VALUES (?, ?, ?, ?, ?, 'PENDIENTE', ?, ?)`
    )
    .run(
      b.athleteName.trim(), b.professionalId, b.date, b.startTime, b.endTime,
      b.reason.trim(), ownerId
    );
  const row = db.prepare('SELECT * FROM appointments WHERE id = ?').get(info.lastInsertRowid);
  res.status(201).json(toAppointment(row));
});

// Editar y eliminar: solo ADMIN
app.put('/api/appointments/:id', auth.requireRole('ADMIN'), (req, res) => {
  const current = db.prepare('SELECT * FROM appointments WHERE id = ?').get(req.params.id);
  if (!current) return fail(res, 404, 'Cita no encontrada');
  const b = req.body;
  const status = b.status || current.status;
  if (!STATUSES.includes(status))
    return fail(res, 400, 'El estado debe ser PENDIENTE, ATENDIDA o CANCELADA');
  const problem = checkAppointment(b, current.id);
  if (problem) return fail(res, problem.code, problem.error);
  db.prepare(
    `UPDATE appointments
     SET athlete_name = ?, professional_id = ?, date = ?, start_time = ?, end_time = ?, status = ?, reason = ?
     WHERE id = ?`
  ).run(
    b.athleteName.trim(), b.professionalId, b.date, b.startTime, b.endTime,
    status, b.reason.trim(), current.id
  );
  const row = db.prepare('SELECT * FROM appointments WHERE id = ?').get(current.id);
  res.json(toAppointment(row));
});

app.delete('/api/appointments/:id', auth.requireRole('ADMIN'), (req, res) => {
  const info = db.prepare('DELETE FROM appointments WHERE id = ?').run(req.params.id);
  if (info.changes === 0) return fail(res, 404, 'Cita no encontrada');
  res.status(204).send();
});

// Cancelar: ADMIN cualquier cita, USER solo las suyas
app.patch('/api/appointments/:id/cancel', (req, res) => {
  const current = db.prepare('SELECT * FROM appointments WHERE id = ?').get(req.params.id);
  if (!current || (!isAdmin(req) && current.user_id !== req.user.id))
    return fail(res, 404, 'Cita no encontrada');
  if (current.status === 'CANCELADA') return fail(res, 409, 'La cita ya está cancelada');
  if (current.status === 'ATENDIDA')
    return fail(res, 409, 'No se puede cancelar una cita que ya fue atendida');
  db.prepare("UPDATE appointments SET status = 'CANCELADA' WHERE id = ?").run(current.id);
  const row = db.prepare('SELECT * FROM appointments WHERE id = ?').get(current.id);
  res.json(toAppointment(row));
});

// Marcar como atendida: solo ADMIN, y solo si la cita sigue pendiente
app.patch('/api/appointments/:id/attend', auth.requireRole('ADMIN'), (req, res) => {
  const current = db.prepare('SELECT * FROM appointments WHERE id = ?').get(req.params.id);
  if (!current) return fail(res, 404, 'Cita no encontrada');
  if (current.status === 'ATENDIDA') return fail(res, 409, 'La cita ya fue marcada como atendida');
  if (current.status === 'CANCELADA')
    return fail(res, 409, 'No se puede marcar como atendida una cita cancelada');
  db.prepare("UPDATE appointments SET status = 'ATENDIDA' WHERE id = ?").run(current.id);
  const row = db.prepare('SELECT * FROM appointments WHERE id = ?').get(current.id);
  res.json(toAppointment(row));
});

// ---------- Errores ----------
app.use((req, res) => fail(res, 404, 'Ruta no encontrada'));

app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return fail(res, 400, 'El JSON enviado no es válido');
  console.error(err);
  fail(res, 500, 'Error interno del servidor');
});

const PORT = 3000;
app.listen(PORT, () => console.log(`API de citas lista en http://localhost:${PORT}`));