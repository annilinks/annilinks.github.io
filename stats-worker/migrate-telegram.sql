ALTER TABLE users ADD COLUMN tg_chat_id TEXT;
ALTER TABLE users ADD COLUMN tg_name TEXT;
ALTER TABLE users ADD COLUMN link_code TEXT;
ALTER TABLE users ADD COLUMN link_expires INTEGER;
ALTER TABLE users ADD COLUMN reset_salt TEXT;
ALTER TABLE users ADD COLUMN reset_hash TEXT;
ALTER TABLE users ADD COLUMN reset_expires INTEGER;

CREATE INDEX IF NOT EXISTS users_link_code ON users (link_code);
