# SQL Injection Attack Detection — Splunk SIEM Analysis
Simulated a real SQL injection attack (real payloads, real SQLite backend —
not fake data) against a genuinely vulnerable Flask login endpoint, then
detected and analyzed the attack end-to-end in Splunk. Includes real SPL
queries, a working detection alert, a detection dashboard, and MITRE
ATT&CK mapping.

**Full report:** [report/report.md](report/report.md)

## Quick Summary
- Real attack: 10 SQL injection payloads sent against a live vulnerable target
- 6 auth bypasses (including 1 UNION-based credential extraction), 2 SQL errors, 2 normal fails
- Detected via custom `EventType` field and raw query pattern matching (no numeric EventCode)
- Mapped to MITRE ATT&CK T1190 (Exploit Public-Facing Application) and T1213 (Data from Information Repositories)
- Built a working Splunk alert + detection dashboard

## How the Attack Data Was Generated
Two Python scripts in this repo generate the real log data analyzed in this project — no fabricated logs.

### `vulnerable_sqli_target.py`
A real Flask + SQLite login endpoint with an intentionally unsafe, string-concatenated SQL query:
```python
query = f"SELECT * FROM users WHERE username='{user}' AND password='{pw}'"
```
This is real SQL injection surface — not a simulation of one. It creates a real SQLite database (`users.db`) with two seeded accounts, then logs every real login attempt (success, bypass, error, or no-match) to `sqli_logs.log` in `key=value` format.

### `sqli_attacker.py`
Sends 10 real HTTP POST requests to the target with classic SQL injection payloads — comment-based bypass (`admin'--`), tautology bypass (`' OR '1'='1`), and UNION-based data extraction (`' UNION SELECT 1,username,password FROM users--`). Every request is genuinely processed by the vulnerable query.

## Requirements
```
flask
requests
```
Save as `requirements.txt` and install with:
```bash
pip install -r requirements.txt --break-system-packages
```
(Both packages are part of the Python standard toolkit needs — `sqlite3` used by the target is built into Python, no separate install needed.)

## How to Reproduce
1. Open two terminals, both in this repo's folder.
2. **Terminal 1** — start the vulnerable target:
   ```bash
   python3 vulnerable_sqli_target.py
   ```
   Leave this running. It creates `users.db` and begins listening on `http://127.0.0.1:5001/login`.
3. **Terminal 2** — run the attacker:
   ```bash
   python3 sqli_attacker.py
   ```
   This fires all 10 payloads and prints each result live.
4. Check `sqli_logs.log` — it now contains real `SQLI_BYPASS`, `SQLI_ERROR`, and `SQLI_NORMAL` events.
5. Import `sqli_logs.log` into Splunk (Add Data → Upload) and follow the SPL queries in [report/report.md](report/report.md) to reproduce the full analysis, alert, and dashboard.

## Tools
Splunk Enterprise (local), Python 3 (Flask, SQLite3, Requests)

## Skills Demonstrated
SPL querying, real SQLi attack simulation, regex-based detection logic,
alert creation, dashboard building, MITRE ATT&CK mapping
