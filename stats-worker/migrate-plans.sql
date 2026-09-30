ALTER TABLE users ADD COLUMN plan TEXT NOT NULL DEFAULT 'free';
ALTER TABLE users ADD COLUMN plan_until INTEGER;

CREATE TABLE IF NOT EXISTS payments (
  order_id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  period TEXT NOT NULL,
  amount INTEGER NOT NULL,
  status TEXT NOT NULL,
  payment_id TEXT,
  created INTEGER NOT NULL,
  paid INTEGER
);

CREATE INDEX IF NOT EXISTS payments_user ON payments (username);
