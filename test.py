import sqlite3

conn = sqlite3.connect("database.db")
c = conn.cursor()

# Insert a test subcontractor
c.execute("""
    INSERT INTO subcontractors (name, token, email)
    VALUES (?, ?, ?)
""", ("Test Sub Inc", "abc123", "test@sub.com"))

conn.commit()
conn.close()

print("Subcontractor added.")