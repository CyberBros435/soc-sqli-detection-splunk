"""
Vulnerable SQLi Target (for local testing ONLY)
Real SQLite backend with a genuinely unsafe string-concatenated query.
Logs every real request + whether the query errored or bypassed auth.
Run this FIRST, then run sqli_attacker.py against it.
"""
from flask import Flask, request
import sqlite3
import datetime
import os

app = Flask(__name__)
DB_FILE = "users.db"
LOG_FILE = "sqli_logs.log"

def init_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    c.execute("INSERT INTO users (username, password) VALUES ('mudasir', 'S0cAnalyst2026')")
    c.execute("INSERT INTO users (username, password) VALUES ('admin', 'AdminPass123')")
    conn.commit()
    conn.close()

def log_attempt(ip, query, status, row_count, error):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event_code = "SQLI_ERROR" if error else ("SQLI_BYPASS" if status == "bypass" else "SQLI_NORMAL")
    line = (f"{ts} EventType={event_code} src_ip={ip} dest_host=FLASK-SQLI "
            f"query=\"{query}\" row_count={row_count} status={status} "
            f"error=\"{error if error else '-'}\"")
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    user = request.form.get("username", "")
    pw = request.form.get("password", "")

    # INTENTIONALLY VULNERABLE — raw string concatenation, real SQLi surface
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{pw}'"

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    error = None
    rows = []
    try:
        c.execute(query)
        rows = c.fetchall()
    except sqlite3.Error as e:
        error = str(e)
    conn.close()

    if error:
        log_attempt(ip, query, "error", 0, error)
        return {"status": "db_error", "detail": error}, 500

    if len(rows) > 0:
        status = "bypass" if pw not in ["S0cAnalyst2026", "AdminPass123"] else "success"
        log_attempt(ip, query, status, len(rows), None)
        return {"status": status, "rows_returned": len(rows)}, 200

    log_attempt(ip, query, "no_match", 0, None)
    return {"status": "no_match"}, 401

if __name__ == "__main__":
    init_db()
    print(f"[+] SQLi target running at http://127.0.0.1:5001/login")
    print(f"[+] Real SQLite DB created: {DB_FILE}")
    print(f"[+] Logging real query attempts to {LOG_FILE}")
    app.run(host="127.0.0.1", port=5001)
