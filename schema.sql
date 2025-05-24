CREATE TABLE admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL, 
    name TEXT);

CREATE TABLE sqlite_sequence(name,seq);

CREATE TABLE submitting_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    invited_by INTEGER NOT NULL, name TEXT,
    FOREIGN KEY (invited_by) REFERENCES admin_users(id)
);

CREATE TABLE project (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_number INTEGER NOT NULL,
    project_name TEXT NOT NULL,
    project_admin_id INTEGER NOT NULL,
    FOREIGN KEY (project_admin_id) REFERENCES admin_users(id)
);

CREATE TABLE requirements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    set_id INTEGER NOT NULL,
    doc_type TEXT NOT NULL, 
    is_required BOOLEAN DEFAULT 1, 
    expiry_required BOOLEAN DEFAULT 0,
    FOREIGN KEY (set_id) REFERENCES requirement_sets(id),
    UNIQUE (set_id, doc_type)
);

CREATE TABLE users_docs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    name TEXT NOT NULL, 
    description TEXT, 
    user_id TEXT, 
    expiry_required BOOLEAN DEFAULT 0, 
    FOREIGN KEY (user_id) 
    REFERENCES admin_users(id)
);

CREATE TABLE requirement_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    admin_user_id INTEGER NOT NULL,
    FOREIGN KEY (admin_user_id) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS "requests" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL,
    submitter_id INTEGER NOT NULL,
    requirement_set_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    token TEXT UNIQUE,
    status TEXT DEFAULT 'pending review',
    date_requested TEXT DEFAULT CURRENT_TIMESTAMP, 
    name TEXT, 
    description TEXT
);

CREATE TABLE deleted_docs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_doc_id INTEGER,
    submitter_id INTEGER,
    filepath TEXT,
    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "docs" (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link TEXT NOT NULL,
    date_submitted TEXT,
    expiry_date TEXT,
    confirmation TEXT,
    doc_type TEXT NOT NULL,
    submitting_user_id INTEGER NOT NULL,
    admin_user_id INTEGER NOT NULL,
    request_id INTEGER,
    doc_status TEXT DEFAULT "pending_review",
    filepath TEXT, 
    revision INTEGER DEFAULT 0,
    revised_at TIMESTAMP,
    comment TEXT,
    FOREIGN KEY (submitting_user_id) REFERENCES submitting_users(id),
    FOREIGN KEY (admin_user_id) REFERENCES admin_users(id),
    FOREIGN KEY (request_id) REFERENCES requests(id)
);