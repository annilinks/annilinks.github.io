-- Visits, taps and copies on every links page
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,          -- milliseconds since epoch (UTC)
  type TEXT NOT NULL,           -- view | click | copy
  ip TEXT,
  country TEXT,
  region TEXT,
  city TEXT,
  device TEXT,                  -- Mobile | Tablet | Desktop
  browser TEXT,
  os TEXT,
  source TEXT,                  -- where a view came from (views only)
  link_title TEXT,              -- clicks and copies only
  link_url TEXT,
  page TEXT                     -- username of the page that was visited
);

CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS events_page_ts ON events (page, ts);

-- One row per account; the links page itself is stored as JSON
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,    -- lowercase
  display TEXT NOT NULL,        -- as the person typed it
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,           -- PBKDF2-SHA256 of the password
  iterations INTEGER NOT NULL,
  created INTEGER NOT NULL,
  page TEXT NOT NULL,           -- JSON: { title, subtitle, columns }
  disabled INTEGER NOT NULL DEFAULT 0
);

-- Login sessions; only a hash of each token is stored
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  created INTEGER NOT NULL,
  expires INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user ON sessions (username);

-- Failed login attempts, for rate limiting
CREATE TABLE IF NOT EXISTS attempts (
  ip TEXT NOT NULL,
  ts INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS attempts_ip_ts ON attempts (ip, ts);
