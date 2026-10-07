'use strict';
const express  = require('express');
const { Pool } = require('pg');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const pool = new Pool({ 
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway.internal') ? false : { rejectUnauthorized: false }
});
const JWT_SECRET = process.env.JWT_SECRET;
const PORT       = process.env.PORT || 3000;

if (!JWT_SECRET) throw new Error('Missing env var: JWT_SECRET');
for (const v of ['PASS_SUPERADMIN', 'PASS_STAFF', 'PASS_MOXY', 'PASS_RITZ']) {
  if (!process.env[v]) throw new Error(`Missing env var: ${v}`);
}

// ── Users — credentials loaded exclusively from Railway environment variables ──
//   superadmin → everything (incl. Analytics + Settings)
//   staff      → everything except Analytics + Settings
//   hotel      → only its own hotel (reservations, cancellations, history, trash)
const USERS = {
  superadmin: { pass: process.env.PASS_SUPERADMIN, role: 'superadmin', label: 'Super Admin',      hotelFilter: null },
  nvstaff:    { pass: process.env.PASS_STAFF,      role: 'staff',      label: 'NV Staff',         hotelFilter: null },
  nvmoxy:     { pass: process.env.PASS_MOXY,       role: 'hotel',      label: 'Moxy',             hotelFilter: 'Moxy' },
  nvritz:     { pass: process.env.PASS_RITZ,       role: 'hotel',      label: 'The Ritz-Carlton', hotelFilter: 'Ritz-Carlton Reserve' },
};

// ── Middleware ─────────────────────────────────────────────────────────────
app.set('trust proxy', 1);   // Railway proxy → real client IP for rate limiting
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

function requireSuperadmin(req, res, next) {
  if (req.user.role !== 'superadmin') return res.status(403).json({ error: 'Forbidden' });
  next();
}

// Apply hotel filter to queries — hotel role users only see their hotel
function hotelFilter(req) {
  return req.user.hotelFilter || null;
}

// Adds " AND hotel = $n" for hotel roles (pushes the value into params); '' otherwise
function hotelScope(req, params) {
  const h = hotelFilter(req);
  if (!h) return '';
  params.push(h);
  return ` AND hotel = $${params.length}`;
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

    if (hotel && 'hotel' in r && r.hotel !== hotel) return res.status(403).json({ error: 'Forbidden' });
    params.push(req.params.id);
    const idIdx = params.length;
    const scope = hotelScope(req, params);
    const { rows } = await pool.query(
      `UPDATE reservations SET ${sets.join(', ')}, updated_at = NOW()
       WHERE id = $${idIdx}${scope} AND trashed_at IS NULL RETURNING *`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(dbToRes(rows[0]));
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/reservations/:id  → move to trash
app.delete('/api/reservations/:id', requireAuth, async (req, res) => {
  try {
    const params = [req.params.id];
    const scope = hotelScope(req, params);
    await pool.query(
      `UPDATE reservations SET trashed_at = NOW() WHERE id = $1${scope} AND trashed_at IS NULL`,
      params
    );
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/reservations/confirm-all  (master only)
app.post('/api/reservations/confirm-all', requireAuth, async (req, res) => {
  try {
    const params = [];
    const scope = hotelScope(req, params);
    const { rowCount } = await pool.query(
      `UPDATE reservations SET status = 'confirmed', updated_at = NOW()
       WHERE status = 'pending' AND trashed_at IS NULL${scope}`,
      params
    );
    res.json({ confirmed: rowCount });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/reservations  → delete all (master only, used in settings)
app.delete('/api/reservations', requireAuth, requireSuperadmin, async (req, res) => {
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
    const idIdx = params.length;
    const scope = hotelScope(req, params);
    const { rows } = await pool.query(
      `UPDATE cancellations SET ${sets.join(', ')} WHERE id = $${idIdx}${scope} AND trashed_at IS NULL RETURNING *`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(dbToCancel(rows[0]));
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/cancellations/:id  → move to trash
app.delete('/api/cancellations/:id', requireAuth, async (req, res) => {
  try {
    const params = [req.params.id];
    const scope = hotelScope(req, params);
    await pool.query(
      `UPDATE cancellations SET trashed_at = NOW() WHERE id = $1${scope} AND trashed_at IS NULL`,
      params
    );
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/cancellations  → delete all (master only)
app.delete('/api/cancellations', requireAuth, requireSuperadmin, async (req, res) => {
  try {
    await pool.query(`UPDATE cancellations SET trashed_at = NOW() WHERE trashed_at IS NULL`);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════
// TRASH
// ══════════════════════════════════════════════════════════════════════════

// GET /api/trash
app.get('/api/trash', requireAuth, async (req, res) => {
  try {
    const params = [];
    const scope = hotelScope(req, params);
    const [res1, can1] = await Promise.all([
      pool.query(`SELECT *, 'reservation' AS _trash_type FROM reservations WHERE trashed_at IS NOT NULL${scope} ORDER BY trashed_at DESC`, params),
      pool.query(`SELECT *, 'cancellation' AS _trash_type FROM cancellations WHERE trashed_at IS NOT NULL${scope} ORDER BY trashed_at DESC`, params),
    ]);
    const items = [
      ...res1.rows.map(r => ({ ...dbToRes(r), _trashType: 'reservation', _trashedAt: r.trashed_at })),
      ...can1.rows.map(r => ({ ...dbToCancel(r), _trashType: 'cancellation', _trashedAt: r.trashed_at })),
    ].sort((a, b) => new Date(b._trashedAt) - new Date(a._trashedAt));
    res.json(items);
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// POST /api/trash/:id/restore
app.post('/api/trash/:id/restore', requireAuth, async (req, res) => {
  try {
    const { type } = req.body; // 'reservation' | 'cancellation'
    const table = type === 'cancellation' ? 'cancellations' : 'reservations';
    const params = [req.params.id];
    const scope = hotelScope(req, params);
    const { rows } = await pool.query(
      `UPDATE ${table} SET trashed_at = NULL WHERE id = $1${scope} RETURNING *`,
      params
    );
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/trash/:id  → permanent delete
app.delete('/api/trash/:id', requireAuth, async (req, res) => {
  try {
    const { type } = req.body;
    const table = type === 'cancellation' ? 'cancellations' : 'reservations';
    const params = [req.params.id];
    const scope = hotelScope(req, params);
    await pool.query(`DELETE FROM ${table} WHERE id = $1${scope} AND trashed_at IS NOT NULL`, params);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// DELETE /api/trash  → empty trash
app.delete('/api/trash', requireAuth, async (req, res) => {
  try {
    const params = [];
    const scope = hotelScope(req, params);
    await Promise.all([
      pool.query(`DELETE FROM reservations WHERE trashed_at IS NOT NULL${scope}`, params),
      pool.query(`DELETE FROM cancellations WHERE trashed_at IS NOT NULL${scope}`, params),
    ]);
    res.json({ ok: true });
  } catch (e) { console.error(e.message); res.status(500).json({ error: e.message }); }
});

// ══════════════════════════════════════════════════════════════════════════
// ANALYTICS (simple — no cookies, no IPs stored)
// ══════════════════════════════════════════════════════════════════════════
const ANALYTICS_SQL = `
  CREATE TABLE IF NOT EXISTS analytics_events (
    id         SERIAL PRIMARY KEY,
    event      TEXT NOT NULL,
    lang       TEXT,
    device     TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS analytics_events_created_idx ON analytics_events (created_at);
`;

const TRACK_EVENTS  = new Set(['visit', 'book_click', 'form_start']);
const TRACK_LANGS   = new Set(['en', 'ja', 'ko', 'zh']);
const TRACK_DEVICES = new Set(['mobile', 'tablet', 'desktop']);
const _trackHits    = new Map();               // simple per-IP rate limit (in memory only)
setInterval(() => _trackHits.clear(), 60 * 1000).unref();

// POST /api/track  (guest app — no auth required)
app.post('/api/track', async (req, res) => {
  const ip = req.ip || 'unknown';
  const hits = (_trackHits.get(ip) || 0) + 1;
  _trackHits.set(ip, hits);
  if (hits > 30) return res.status(429).end();
  const { event, lang, device } = req.body || {};
  if (!TRACK_EVENTS.has(event)) return res.status(400).end();
  try {
    await pool.query(
      `INSERT INTO analytics_events (event, lang, device) VALUES ($1, $2, $3)`,
      [event, TRACK_LANGS.has(lang) ? lang : null, TRACK_DEVICES.has(device) ? device : null]
    );
    res.status(204).end();
  } catch (e) { console.error(e.message); res.status(500).end(); }
});

// GET /api/analytics?days=30  (master only)
app.get('/api/analytics', requireAuth, requireSuperadmin, async (req, res) => {
  try {
    const days  = Math.min(Math.max(parseInt(req.query.days, 10) || 30, 1), 365);
    const jst   = new Date(Date.now() + 9 * 3600 * 1000);
    const to    = jst.toISOString().slice(0, 10);
    const fromD = new Date(Date.UTC(jst.getUTCFullYear(), jst.getUTCMonth(), jst.getUTCDate() - (days - 1)));
    const from  = fromD.toISOString().slice(0, 10);

    const day      = col => `(${col}::timestamptz AT TIME ZONE 'Asia/Tokyo')::date`;
    const pax      = `COALESCE(SUM(CASE WHEN guests::text ~ '^[0-9]+$' THEN guests::text::int ELSE 0 END), 0)::int`;
    const evWhere  = `${day('created_at')} >= $1::date`;
    const resWhere = `trashed_at IS NULL AND ${day('created_at')} >= $1::date`;
    const q = sql => pool.query(sql, [from]).then(r => r.rows);

    const [visitsDaily, bookingsDaily, events, langs, devices, hotels, buses, sources, cancelReq, cancelled] = await Promise.all([
      q(`SELECT to_char(${day('created_at')}, 'YYYY-MM-DD') AS day, COUNT(*)::int AS n FROM analytics_events WHERE event = 'visit' AND ${evWhere} GROUP BY 1`),
      q(`SELECT to_char(${day('created_at')}, 'YYYY-MM-DD') AS day, COUNT(*)::int AS n FROM reservations WHERE ${resWhere} GROUP BY 1`),
      q(`SELECT event AS key, COUNT(*)::int AS n FROM analytics_events WHERE ${evWhere} GROUP BY 1`),
      q(`SELECT COALESCE(lang, 'unknown') AS key, COUNT(*)::int AS n FROM analytics_events WHERE event = 'visit' AND ${evWhere} GROUP BY 1 ORDER BY 2 DESC`),
      q(`SELECT COALESCE(device, 'unknown') AS key, COUNT(*)::int AS n FROM analytics_events WHERE event = 'visit' AND ${evWhere} GROUP BY 1 ORDER BY 2 DESC`),
      q(`SELECT COALESCE(hotel, 'Unknown') AS key, COUNT(*)::int AS n, ${pax} AS pax FROM reservations WHERE ${resWhere} GROUP BY 1 ORDER BY 2 DESC`),
      q(`SELECT COALESCE(bus, 'Unknown') AS key, COUNT(*)::int AS n, ${pax} AS pax FROM reservations WHERE ${resWhere} GROUP BY 1 ORDER BY 2 DESC`),
      q(`SELECT COALESCE(source, 'guest') AS key, COUNT(*)::int AS n FROM reservations WHERE ${resWhere} GROUP BY 1`),
      q(`SELECT COUNT(*)::int AS n FROM cancellations WHERE ${resWhere}`),
      q(`SELECT COUNT(*)::int AS n FROM reservations WHERE ${resWhere} AND status = 'cancelled'`),
    ]);

    const ev   = Object.fromEntries(events.map(r => [r.key, r.n]));
    const src  = Object.fromEntries(sources.map(r => [r.key, r.n]));
    const vMap = Object.fromEntries(visitsDaily.map(r => [r.day, r.n]));
    const bMap = Object.fromEntries(bookingsDaily.map(r => [r.day, r.n]));
    const daily = [];
    for (let i = 0; i < days; i++) {
      const d = new Date(fromD.getTime() + i * 86400000).toISOString().slice(0, 10);
      daily.push({ day: d, visits: vMap[d] || 0, bookings: bMap[d] || 0 });
    }

    res.json({
      days, from, to, daily,
      totals: {
        visits:         ev.visit || 0,
        bookClicks:     ev.book_click || 0,
        formStarts:     ev.form_start || 0,
        bookings:       bookingsDaily.reduce((a, r) => a + r.n, 0),
        guestBookings:  src.guest || 0,
        staffBookings:  src.admin || 0,
        pax:            hotels.reduce((a, r) => a + r.pax, 0),
        cancelRequests: cancelReq[0].n,
        cancelled:      cancelled[0].n,
      },
      langs, devices, hotels, buses,
    });
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

// ── Startup: make sure all tables exist, then start listening ─────────────
// schema.sql only uses CREATE ... IF NOT EXISTS → safe to run on every boot,
// never deletes or changes existing data.
async function initDb() {
  const schemaPath = path.join(__dirname, 'schema.sql');
  if (fs.existsSync(schemaPath)) {
    await pool.query(fs.readFileSync(schemaPath, 'utf8'));
    console.log('Schema OK');
  } else {
    console.warn('schema.sql not found next to server.js — skipping table creation');
  }
  await pool.query(ANALYTICS_SQL);
  console.log('Analytics table OK');
}

initDb()
  .catch(e => console.error('DB init error:', e.message))
  .finally(() => app.listen(PORT, () => console.log(`NVBus API running on port ${PORT}`)));
