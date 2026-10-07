-- ═══════════════════════════════════════════════════════
-- Niseko Village Bus — PostgreSQL Schema
-- Run once in Railway's psql console or via railway run
-- ═══════════════════════════════════════════════════════

-- ── RESERVATIONS ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reservations (
  id                  TEXT        PRIMARY KEY DEFAULT (
                                    to_hex(floor(extract(epoch from now())*1000)::bigint) ||
                                    substr(md5(random()::text), 1, 3)
                                  ),
  reservation_id      TEXT,                          -- hotel booking ref (optional)
  first               TEXT        NOT NULL,
  last                TEXT        NOT NULL,
  email               TEXT        NOT NULL,
  phone               TEXT,
  guests              TEXT,
  luggage             TEXT,
  golf_bags           TEXT,
  dir                 TEXT        NOT NULL CHECK (dir IN ('arrival','departure')),
  bus                 TEXT        NOT NULL,
  date                DATE        NOT NULL,
  hotel               TEXT        NOT NULL CHECK (hotel IN (
                                    'Hilton Niseko Village',
                                    'Hinode Hills',
                                    'Ritz-Carlton Reserve',
                                    'Moxy'
                                  )),
  flight              TEXT,
  flight_type         TEXT        CHECK (flight_type IN ('domestic','international')),
  notes               TEXT,
  status              TEXT        NOT NULL DEFAULT 'pending'
                                  CHECK (status IN ('pending','confirmed','cancelled')),
  source              TEXT        NOT NULL DEFAULT 'guest'
                                  CHECK (source IN ('guest','admin')),
  created_by          TEXT,                          -- staff name if source = 'admin'

  -- Cancellation metadata
  cancelled_by        TEXT        CHECK (cancelled_by IN ('guest','admin')),
  cancelled_at        TIMESTAMPTZ,
  cancellation_reason TEXT,
  previous_status     TEXT,

  -- Reactivation metadata
  reactivated_at      TIMESTAMPTZ,
  reactivated_by      TEXT,

  -- Soft delete
  trashed_at          TIMESTAMPTZ,

  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_res_date    ON reservations (date);
CREATE INDEX IF NOT EXISTS idx_res_status  ON reservations (status);
CREATE INDEX IF NOT EXISTS idx_res_hotel   ON reservations (hotel);
CREATE INDEX IF NOT EXISTS idx_res_email   ON reservations (email);
CREATE INDEX IF NOT EXISTS idx_res_trashed ON reservations (trashed_at);

-- ── CANCELLATIONS ────────────────────────────────────────
CREATE TABLE IF NOT EXISTS cancellations (
  id          TEXT        PRIMARY KEY DEFAULT (
                            to_hex(floor(extract(epoch from now())*1000)::bigint) ||
                            substr(md5(random()::text), 1, 3)
                          ),
  ref         TEXT        NOT NULL,                  -- booking reference from guest
  first       TEXT        NOT NULL,
  last        TEXT        NOT NULL,
  email       TEXT        NOT NULL,
  date        DATE,
  hotel       TEXT        CHECK (hotel IN (
                            'Hilton Niseko Village',
                            'Hinode Hills',
                            'Ritz-Carlton Reserve',
                            'Moxy'
                          )),
  reason      TEXT,
  notes       TEXT,
  status      TEXT        NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','resolved','rejected')),
  resolved_at TIMESTAMPTZ,
  rejected_at TIMESTAMPTZ,

  -- Soft delete
  trashed_at  TIMESTAMPTZ,

  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cancel_status  ON cancellations (status);
CREATE INDEX IF NOT EXISTS idx_cancel_hotel   ON cancellations (hotel);
CREATE INDEX IF NOT EXISTS idx_cancel_email   ON cancellations (email);
CREATE INDEX IF NOT EXISTS idx_cancel_trashed ON cancellations (trashed_at);

-- ── ANALYTICS ────────────────────────────────────────────
-- (server.js also creates this automatically on startup)
CREATE TABLE IF NOT EXISTS analytics_events (
  id         SERIAL      PRIMARY KEY,
  event      TEXT        NOT NULL,          -- visit | book_click | form_start
  lang       TEXT,                          -- en | ja | ko | zh
  device     TEXT,                          -- mobile | tablet | desktop
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS analytics_events_created_idx ON analytics_events (created_at);
