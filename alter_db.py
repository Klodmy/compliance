import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()

def get_db():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

def run_alter():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        ALTER TABLE project
        ALTER COLUMN project_number TYPE TEXT;
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Column type updated.")

run_alter()

