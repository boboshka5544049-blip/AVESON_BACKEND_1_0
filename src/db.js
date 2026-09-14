const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false
});

async function query(text, params) {
  return pool.query(text, params);
}

async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('artist','admin')),
      display_name TEXT NOT NULL DEFAULT 'Artist',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS releases (
      id UUID PRIMARY KEY,
      artist_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'Single',
      artist_name TEXT NOT NULL,
      featuring TEXT,
      genre TEXT,
      language TEXT,
      release_date DATE,
      label TEXT,
      copyright_owner TEXT,
      lyrics TEXT,
      explicit BOOLEAN NOT NULL DEFAULT FALSE,
      audio_original_name TEXT,
      audio_path TEXT,
      cover_original_name TEXT,
      cover_path TEXT,
      status TEXT NOT NULL DEFAULT 'PENDING_REVIEW'
        CHECK (status IN ('DRAFT','PENDING_REVIEW','CHANGES_REQUIRED','APPROVED','REJECTED','RELEASED')),
      review_note TEXT,
      reviewed_by UUID REFERENCES users(id),
      reviewed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS releases_artist_idx ON releases(artist_id);
    CREATE INDEX IF NOT EXISTS releases_status_idx ON releases(status);
  `);
}

module.exports = { query, initDb, pool };