"""
Deliberately insecure Flask app for Snyk SCA + SAST training.

DO NOT use these patterns in real applications.
"""

from flask import Flask, request, render_template_string
import requests
import sqlite3
import subprocess
import pickle
import os

# Hard-coded secret (Snyk Code should flag this)
API_KEY = "sk_live_TOTALLY_INSECURE_DEMO_KEY_123456"

DB_PATH = "users.db"

app = Flask(__name__)


def init_db():
    """Initialize a simple SQLite DB (for demo only)."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, name TEXT)"
    )
    conn.commit()
    conn.close()


# 1) SQL Injection
@app.route("/search")
def search():
    """
    /search?name=alice

    Insecure: builds SQL query via string concatenation.
    Snyk Code should flag this as SQL injection.
    """
    name = request.args.get("name", "anonymous")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # VULNERABLE: unescaped user input directly in query string
    query = f"SELECT * FROM users WHERE name = '{name}'"
    print(f"[DEBUG] Executing query: {query}")
    cur.execute(query)

    rows = cur.fetchall()
    conn.close()
    return {"rows": rows}


# 2) Command Injection
@app.route("/ping")
def ping():
    """
    /ping?host=127.0.0.1

    Insecure: uses shell=True with user-controlled host.
    Snyk Code should flag this as command injection.
    """
    host = request.args.get("host", "127.0.0.1")

    # VULNERABLE: concatenating user input into shell command
    cmd = "ping -c 1 " + host
    print(f"[DEBUG] Running command: {cmd}")
    output = subprocess.check_output(cmd, shell=True)  # unsafe
    return f"<pre>{output.decode('utf-8')}</pre>"


# 3) Server-Side Template Injection (SSTI)
@app.route("/render")
def render():
    """
    /render?template=Hello+{{+7*7+}}

    Insecure: passes user-controlled string as template source.
    Snyk Code should flag this as SSTI.
    """
    template = request.args.get("template", "Hello {{ name }}!")
    # VULNERABLE: template string fully controlled by user
    return render_template_string(template, name="Bobby")


# 4) Insecure HTTP request
@app.route("/proxy")
def proxy():
    """
    /proxy?url=https://example.com

    Insecure: requests.get with verify=False.
    Snyk Code should flag this as insecure TLS usage.
    """
    url = request.args.get("url", "https://example.com")

    # VULNERABLE: verify=False disables TLS cert validation
    resp = requests.get(url, verify=False)
    return resp.text


# 5) Insecure deserialization
@app.route("/session")
def session():
    """
    /session?blob=<hex-encoded-pickle>

    Insecure: pickle.loads on untrusted data.
    Snyk Code should flag insecure deserialization.
    """
    blob = request.args.get("blob", "")
    if not blob:
        return "Provide ?blob=<hex-encoded-pickle>"

    try:
        data = bytes.fromhex(blob)
        # VULNERABLE: never unpickle untrusted input
        session_obj = pickle.loads(data)
        return f"Loaded session: {session_obj}"
    except Exception as exc:
        return f"Error loading session: {exc}"


@app.route("/")
def index():
    return (
        "Insecure demo app for Snyk training.\n"
        "Try:\n"
        "  /search?name=alice\n"
        "  /ping?host=127.0.0.1\n"
        "  /render?template=Hello+{{+7*7+}}\n"
        "  /proxy?url=https://example.com\n"
        "  /session?blob=<hex-encoded-pickle>\n"
    )


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 8080))
    print(f"[DEBUG] Insecure Flask app listening on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)