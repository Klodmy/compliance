CREATE TABLE admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL
);

CREATE TABLE submitting_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    invited_by INTEGER NOT NULL,
    FOREIGN KEY (invited_by) REFERENCES admin_users(id)
);

CREATE TABLE project (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_number INTEGER NOT NULL,
    project_name TEXT NOT NULL,
    project_admin_id INTEGER NOT NULL,
    FOREIGN KEY (project_admin_id) REFERENCES admin_users(id)
);

CREATE TABLE requirement_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    admin_user_id INTEGER NOT NULL,
    submitting_user_id INTEGER NOT NULL,
    FOREIGN KEY (admin_user_id) REFERENCES admin_users(id),
    FOREIGN KEY (submitting_user_id) REFERENCES submitting_users(id)
);

CREATE TABLE requirements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    set_id INTEGER NOT NULL,
    doc_type TEXT NOT NULL,
    FOREIGN KEY (set_id) REFERENCES requirement_sets(id),
    UNIQUE (set_id, doc_type)
);

CREATE TABLE docs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link TEXT NOT NULL,
    date_submitted TEXT,
    expiry_date TEXT,
    confirmation TEXT,
    doc_type TEXT NOT NULL,
    submitting_user_id INTEGER NOT NULL,
    admin_user_id INTEGER NOT NULL,
    FOREIGN KEY (submitting_user_id) REFERENCES submitting_users(id),
    FOREIGN KEY (admin_user_id) REFERENCES admin_users(id)
);



