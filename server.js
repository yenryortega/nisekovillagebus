'use strict';
const express  = require('express');
const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');

const app  = express();
const pool = new Pool({ 
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway.internal') ? false : { rejectUnauthorized: false }
});
const JWT_SECRET = process.env.JWT_SECRET;
const PORT       = process.env.PORT || 3000;

if (!JWT_SECRET) throw new Error('Missing env var: JWT_SECRET');
if (!process.env.PASS_NISEKO) throw new Error('Missing env var: PASS_NISEKO');
if (!process.env.PASS_RITZ)   throw new Error('Missing env var: PASS_RITZ');
if (!process.env.PASS_MOXY)   throw new Error('Missing env var: PASS_MOXY');

// ── Users — credentials loaded exclusively from Railway environment variables ──
const USERS = {
  nisekovillage: { pass: process.env.PASS_NISEKO, role: 'master', label: 'Niseko Village',   hotelFilter: null },
  nvmoxy:        { pass: process.env.PASS_MOXY,   role: 'hotel',  label: 'Moxy',             hotelFilter: 'Moxy' },
  nvritz:        { pass: process.env.PASS_RITZ,   role: 'hotel',  label: 'The Ritz-Carlton', hotelFilter: 'Ritz-Carlton Reserve' },
};

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth middleware ────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function requireMaster(req, res, next) {
  if (req.user.role !== 'master') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// Apply hotel filter to queries — hotel role users only see their hotel
function hotelFilter(req) {
  return req.user.hotelFilter || null;
}

// ── POST /api/auth ─────────────────────────────────────────────────────────
app.post('/api/auth', (req, res) => {
  const { username, password } = req.body;
  const u = USERS[username];
  if (!u || u.pass !== password) return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign(
    { username, role: u.role, label: u.label, hotelFilter: u.hotelFilter },
    JWT_SECRET,
    { expiresIn: '12h' }
  );
  res.json({ token, role: u.role, label: u.label, hotelFilter: u.hotelFilter });
});

// ══════════════════════════════════════════════════════════════════════════
// RESERVATIONS
// ══════════════════════════════════════════════════════════════════════════

// GET /api/reservations
app.get('/api/reservations', requireAuth, async (req, res) => {
  try {
    const hotel = hotelFilter(req);
    const conditions = ['trashed_at IS NULL'];
    const params = [];
    if (hotel) { params.push(hotel); conditions.push(`hotel = $${params.length}`); }
    const { rows } = await pool.query(
      `SELECT * FROM reservations WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC`,
      params
    );
    res.json(rows.map(dbToRes));
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/reservations  (guest app — no auth required)
app.post('/api/reservations', async (req, res) => {
  try {
    const r = req.body;
    const { rows } = await pool.query(
      `INSERT INTO reservations
        (reservation_id, first, last, email, phone, guests, luggage, golf_bags,
         dir, bus, date, hotel, flight, flight_type, notes, status, source,
         created_by, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'pending',$16,$17, NOW())
       RETURNING *`,
      [
        r.reservationId || null,
        r.first, r.last, r.email,
        r.phone || null,
        r.guests || null,
        r.luggage || null,
        r.golfBags || null,
        r.dir, r.bus, r.date, r.hotel,
        r.flight || null,
        r.flightType || null,
        r.notes || null,
        r.source || 'guest',
        r.createdBy || null,
      ]
    );
    res.status(201).json(dbToRes(rows[0]));
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// PATCH /api/reservations/:id
app.patch('/api/reservations/:id', requireAuth, async (req, res) => {
  try {
    const hotel = hotelFilter(req);
    const r = req.body;
    const sets = [];
    const params = [];

    const allowed = [
      'reservation_id','first','last','email','phone','guests','luggage','golf_bags',
      'dir','bus','date','hotel','flight','flight_type','notes','status',
      'cancelled_by','cancelled_at','cancellation_reason','previous_status',
      'reactivated_at','reactivated_by',
    ];
    // Map camelCase from client to snake_case
    const camelToSnake = {
      reservationId:'reservation_id', golfBags:'golf_bags',
      flightType:'flight_type', cancelledBy:'cancelled_by',
      cancelledAt:'cancelled_at', cancellationReason:'cancellation_reason',
      previousStatus:'previous_status', reactivatedAt:'reactivated_at',
      reactivatedBy:'reactivated_by',
    };

    const fieldMap = { ...Object.fromEntries(allowed.map(f => [f,f])), ...camelToSnake };
    for (const [key, val] of Object.entries(r)) {
      const col = fieldMap[key];
      if (!col || key === 'id') continue;
      params.push(val === null ? null : val);
      sets.push(`${col} = $${params.length}`);
    }
    if (!sets.length) return res.status(400).json({ error: 'No fields to update' });

    params.push(req.params.id);
    const hotelClause = hotel ? `AND hotel = '${hotel.replace(/'/g,"''")}'` : '';
    const { rows } = await pool.query(
      `UPDATE reservations SET ${sets.join(', ')}, updated_at = NOW()
       WHERE id = $${params.length} ${hotelClause} AND trashed_at IS NULL RETURNING *`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(dbToRes(rows[0]));
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/reservations/:id  → move to trash
app.delete('/api/reservations/:id', requireAuth, requireMaster, async (req, res) => {
  try {
    await pool.query(
      `UPDATE reservations SET trashed_at = NOW() WHERE id = $1 AND trashed_at IS NULL`,
      [req.params.id]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/reservations/confirm-all  (master only)
app.post('/api/reservations/confirm-all', requireAuth, requireMaster, async (req, res) => {
  try {
    const { rowCount } = await pool.query(
      `UPDATE reservations SET status = 'confirmed', updated_at = NOW()
       WHERE status = 'pending' AND trashed_at IS NULL`
    );
    res.json({ confirmed: rowCount });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/reservations  → delete all (master only, used in settings)
app.delete('/api/reservations', requireAuth, requireMaster, async (req, res) => {
  try {
    await pool.query(`UPDATE reservations SET trashed_at = NOW() WHERE trashed_at IS NULL`);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════
// CANCELLATIONS
// ══════════════════════════════════════════════════════════════════════════

// GET /api/cancellations
app.get('/api/cancellations', requireAuth, async (req, res) => {
  try {
    const hotel = hotelFilter(req);
    const conditions = ['trashed_at IS NULL'];
    const params = [];
    if (hotel) { params.push(hotel); conditions.push(`hotel = $${params.length}`); }
    const { rows } = await pool.query(
      `SELECT * FROM cancellations WHERE ${conditions.join(' AND ')} ORDER BY created_at DESC`,
      params
    );
    res.json(rows.map(dbToCancel));
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/cancellations  (guest app — no auth required)
app.post('/api/cancellations', async (req, res) => {
  try {
    const r = req.body;
    const { rows } = await pool.query(
      `INSERT INTO cancellations (ref, first, last, email, date, hotel, reason, status, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'pending', NOW()) RETURNING *`,
      [r.ref, r.first, r.last, r.email, r.date, r.hotel || null, r.reason || null]
    );
    res.status(201).json(dbToCancel(rows[0]));
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// PATCH /api/cancellations/:id
app.patch('/api/cancellations/:id', requireAuth, async (req, res) => {
  try {
    const r = req.body;
    const sets = [];
    const params = [];
    const allowed = { status:'status', resolvedAt:'resolved_at', rejectedAt:'rejected_at' };
    for (const [key, col] of Object.entries(allowed)) {
      if (key in r) { params.push(r[key]); sets.push(`${col} = $${params.length}`); }
    }
    if (!sets.length) return res.status(400).json({ error: 'No fields to update' });
    params.push(req.params.id);
    const { rows } = await pool.query(
      `UPDATE cancellations SET ${sets.join(', ')} WHERE id = $${params.length} AND trashed_at IS NULL RETURNING *`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(dbToCancel(rows[0]));
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/cancellations/:id  → move to trash
app.delete('/api/cancellations/:id', requireAuth, requireMaster, async (req, res) => {
  try {
    await pool.query(
      `UPDATE cancellations SET trashed_at = NOW() WHERE id = $1 AND trashed_at IS NULL`,
      [req.params.id]
    );
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/cancellations  → delete all (master only)
app.delete('/api/cancellations', requireAuth, requireMaster, async (req, res) => {
  try {
    await pool.query(`UPDATE cancellations SET trashed_at = NOW() WHERE trashed_at IS NULL`);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════
// TRASH
// ══════════════════════════════════════════════════════════════════════════

// GET /api/trash
app.get('/api/trash', requireAuth, requireMaster, async (req, res) => {
  try {
    const [res1, can1] = await Promise.all([
      pool.query(`SELECT *, 'reservation' AS _trash_type FROM reservations WHERE trashed_at IS NOT NULL ORDER BY trashed_at DESC`),
      pool.query(`SELECT *, 'cancellation' AS _trash_type FROM cancellations WHERE trashed_at IS NOT NULL ORDER BY trashed_at DESC`),
    ]);
    const items = [
      ...res1.rows.map(r => ({ ...dbToRes(r), _trashType: 'reservation', _trashedAt: r.trashed_at })),
      ...can1.rows.map(r => ({ ...dbToCancel(r), _trashType: 'cancellation', _trashedAt: r.trashed_at })),
    ].sort((a, b) => new Date(b._trashedAt) - new Date(a._trashedAt));
    res.json(items);
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/trash/:id/restore
app.post('/api/trash/:id/restore', requireAuth, requireMaster, async (req, res) => {
  try {
    const { type } = req.body; // 'reservation' | 'cancellation'
    const table = type === 'cancellation' ? 'cancellations' : 'reservations';
    const { rows } = await pool.query(
      `UPDATE ${table} SET trashed_at = NULL WHERE id = $1 RETURNING *`,
      [req.params.id]
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/trash/:id  → permanent delete
app.delete('/api/trash/:id', requireAuth, requireMaster, async (req, res) => {
  try {
    const { type } = req.body;
    const table = type === 'cancellation' ? 'cancellations' : 'reservations';
    await pool.query(`DELETE FROM ${table} WHERE id = $1 AND trashed_at IS NOT NULL`, [req.params.id]);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/trash  → empty trash
app.delete('/api/trash', requireAuth, requireMaster, async (req, res) => {
  try {
    await Promise.all([
      pool.query(`DELETE FROM reservations WHERE trashed_at IS NOT NULL`),
      pool.query(`DELETE FROM cancellations WHERE trashed_at IS NOT NULL`),
    ]);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// ── Mappers: DB row → JS object (snake_case → camelCase) ──────────────────
function dbToRes(r) {
  return {
    id:                 r.id,
    reservationId:      r.reservation_id,
    first:              r.first,
    last:               r.last,
    email:              r.email,
    phone:              r.phone,
    guests:             r.guests,
    luggage:            r.luggage,
    golfBags:           r.golf_bags,
    dir:                r.dir,
    bus:                r.bus,
    date:               r.date,
    hotel:              r.hotel,
    flight:             r.flight,
    flightType:         r.flight_type,
    notes:              r.notes,
    status:             r.status,
    source:             r.source,
    createdBy:          r.created_by,
    cancelledBy:        r.cancelled_by,
    cancelledAt:        r.cancelled_at,
    cancellationReason: r.cancellation_reason,
    previousStatus:     r.previous_status,
    reactivatedAt:      r.reactivated_at,
    reactivatedBy:      r.reactivated_by,
    createdAt:          r.created_at,
    updatedAt:          r.updated_at,
  };
}

function dbToCancel(r) {
  return {
    id:         r.id,
    ref:        r.ref,
    first:      r.first,
    last:       r.last,
    email:      r.email,
    date:       r.date,
    hotel:      r.hotel,
    reason:     r.reason,
    notes:      r.notes,
    status:     r.status,
    resolvedAt: r.resolved_at,
    rejectedAt: r.rejected_at,
    createdAt:  r.created_at,
  };
}

// ── Health check ───────────────────────────────────────────────────────────
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── Clean URLs ────────────────────────────────────────────────────────────
app.get('/',      (req, res) => res.sendFile(path.join(__dirname, 'public', 'nisekovillagebus.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'nvbusadmin.html'), err => {
  if (err) { console.error('admin sendFile:', err.message); res.status(err.status || 500).end(); }
}));

// ── Fallback ──────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  if (req.path.startsWith('/api')) return res.status(404).json({ error: 'Not found' });
  res.status(404).send('Not found');
});

app.listen(PORT, () => console.log(`NVBus API running on port ${PORT}`));
