DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS docs;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL  -- 'gc' or 'sub'
);

CREATE TABLE docs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    link TEXT NOT NULL,
    date_submitted TEXT,
    expiry_date TEXT,
    confirmation TEXT,
    doc_type TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
);