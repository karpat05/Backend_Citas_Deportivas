const Database = require('better-sqlite3');

const db = new Database('citas.db');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS professionals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  specialty TEXT NOT NULL,
  attention_start TEXT NOT NULL,
  attention_end TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS appointments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  athlete_name TEXT NOT NULL,
  professional_id INTEGER NOT NULL,
  date TEXT NOT NULL,
  start_time TEXT NOT NULL,
  end_time TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDIENTE',
  reason TEXT NOT NULL,
  FOREIGN KEY (professional_id) REFERENCES professionals(id)
);
`);

// Datos de prueba (solo si la tabla está vacía)
const total = db.prepare('SELECT COUNT(*) AS c FROM professionals').get().c;
if (total === 0) {
  const insert = db.prepare(
    'INSERT INTO professionals (name, specialty, attention_start, attention_end) VALUES (?, ?, ?, ?)'
  );
  insert.run('Dra. Laura Gómez', 'Fisioterapia', '08:00', '16:00');
  insert.run('Dr. Andrés Ruiz', 'Medicina deportiva', '09:00', '17:00');
}

module.exports = db;