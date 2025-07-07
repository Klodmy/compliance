import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

conn = psycopg2.connect(os.getenv("DATABASE_URL"))
cur = conn.cursor()

cur.execute("""
CREATE TABLE admin_users (
    id SERIAL PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    name TEXT,
    description TEXT,
    phone TEXT,
    address TEXT
);
""")

cur.execute("""
CREATE TABLE submitting_users (
    id SERIAL PRIMARY KEY,
    login TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    name TEXT,
    description TEXT,
    phone TEXT,
    address TEXT
);
""")

cur.execute("""
CREATE TABLE requirement_sets (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    admin_user_id INTEGER NOT NULL REFERENCES admin_users(id)
);
""")

cur.execute("""
CREATE TABLE requirements (
    id SERIAL PRIMARY KEY,
    set_id INTEGER NOT NULL REFERENCES requirement_sets(id),
    doc_type TEXT NOT NULL,
    is_required BOOLEAN DEFAULT TRUE,
    expiry_required BOOLEAN DEFAULT FALSE,
    UNIQUE (set_id, doc_type)
);
""")

cur.execute("""
CREATE TABLE users_docs (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    user_id INTEGER REFERENCES admin_users(id),
    expiry_required BOOLEAN DEFAULT FALSE
);
""")

cur.execute("""
CREATE TABLE project (
    id SERIAL PRIMARY KEY,
    project_number INTEGER NOT NULL,
    project_name TEXT NOT NULL,
    project_admin_id INTEGER NOT NULL REFERENCES admin_users(id)
);
""")

cur.execute("""
CREATE TABLE requests (
    id SERIAL PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES project(id),
    submitter_id INTEGER NOT NULL REFERENCES submitting_users(id),
    requirement_set_id INTEGER NOT NULL REFERENCES requirement_sets(id),
    admin_id INTEGER NOT NULL REFERENCES admin_users(id),
    token TEXT UNIQUE,
    status TEXT DEFAULT 'pending review',
    date_requested TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    name TEXT,
    description TEXT
);
""")

cur.execute("""
CREATE TABLE docs (
    id SERIAL PRIMARY KEY,
    link TEXT NOT NULL,
    date_submitted TIMESTAMP,
    expiry_date TIMESTAMP,
    confirmation TEXT,
    doc_type TEXT NOT NULL,
    submitting_user_id INTEGER NOT NULL REFERENCES submitting_users(id),
    admin_user_id INTEGER NOT NULL REFERENCES admin_users(id),
    request_id INTEGER REFERENCES requests(id),
    doc_status TEXT DEFAULT 'pending_review',
    filepath TEXT,
    revision INTEGER DEFAULT 0,
    revised_at TIMESTAMP,
    comment TEXT,
    expiry_required BOOLEAN DEFAULT FALSE
);
""")

cur.execute("""
CREATE TABLE deleted_docs (
    id SERIAL PRIMARY KEY,
    original_doc_id INTEGER,
    submitter_id INTEGER,
    filepath TEXT,
    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
""")

cur.execute("""
CREATE TABLE admin_submitters (
    id SERIAL PRIMARY KEY,
    admin_id INTEGER NOT NULL REFERENCES admin_users(id),
    submitter_id INTEGER NOT NULL REFERENCES submitting_users(id)
);
""")

conn.commit()
cur.close()
conn.close()

print("Tables created successfully.")
