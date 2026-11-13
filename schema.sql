CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(254) NOT NULL UNIQUE,
  name VARCHAR(80) NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'author' CHECK (role IN ('reader','author','admin')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS books (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(180) NOT NULL,
  author VARCHAR(120) NOT NULL,
  genre VARCHAR(80) NOT NULL DEFAULT 'Фэнтези',
  description TEXT NOT NULL DEFAULT '',
  cover_url TEXT,
  owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  is_published BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS chapters (
  id BIGSERIAL PRIMARY KEY,
  book_id BIGINT NOT NULL REFERENCES books(id) ON DELETE CASCADE,
  chapter_index INTEGER NOT NULL CHECK (chapter_index >= 0),
  title VARCHAR(180) NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(book_id, chapter_index)
);
CREATE TABLE IF NOT EXISTS reading_progress (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  book_id BIGINT NOT NULL REFERENCES books(id) ON DELETE CASCADE,
  chapter_index INTEGER NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY(user_id,book_id)
);
CREATE TABLE IF NOT EXISTS bookmarks (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  book_id BIGINT NOT NULL REFERENCES books(id) ON DELETE CASCADE,
  chapter_index INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(user_id,book_id,chapter_index)
);
CREATE INDEX IF NOT EXISTS books_published_created_idx ON books(is_published,created_at DESC);
CREATE INDEX IF NOT EXISTS chapters_book_order_idx ON chapters(book_id,chapter_index);
UPDATE users SET role='author' WHERE role='reader';
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'author';
