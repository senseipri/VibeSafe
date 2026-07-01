import sqlite3

def get_user(username: str):
    conn = sqlite3.connect("db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")  # VULN
    return cursor.fetchone()
