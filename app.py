import os
import base64
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash

# Config
DATABASE = os.environ.get("DB_PATH", "data/licenses.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS_HASH")  # hashed password expected
if not ADMIN_PASS:
    # fallback: if plain password provided in env, hash it (only for dev)
    raw = os.environ.get("ADMIN_PASS", "changeme")
    ADMIN_PASS = generate_password_hash(raw)

SECRET_KEY = os.environ.get("FLASK_SECRET", "dev-secret-key")
APP_HOST = "0.0.0.0"
APP_PORT = int(os.environ.get("PORT", 5000))

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY)

# DB helpers
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DATABASE) or ".", exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL, -- pending | ok | revoked | error
        key TEXT, -- base64 encoded license payload (optional)
        expires_at TEXT, -- ISO datetime UTC or NULL
        note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()

def upsert_license(hwid, status="pending", key=None, expires_at=None, note=None):
    now = datetime.utcnow().isoformat()
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id FROM licenses WHERE hwid = ?", (hwid,))
    row = c.fetchone()
    if row:
        c.execute("""UPDATE licenses SET status=?, key=?, expires_at=?, note=?, updated_at=? WHERE hwid=?""",
                  (status, key, expires_at, note, now, hwid))
    else:
        c.execute("""INSERT INTO licenses (hwid,status,key,expires_at,note,created_at,updated_at)
                     VALUES (?,?,?,?,?,?,?)""", (hwid,status,key,expires_at,note,now,now))
    conn.commit(); conn.close()

def get_license_by_hwid(hwid):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE hwid = ?", (hwid,))
    row = c.fetchone(); conn.close()
    return row

def list_licenses(limit=200):
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM licenses ORDER BY updated_at DESC LIMIT ?", (limit,))
    rows = c.fetchall(); conn.close(); return rows

def update_status(hwid, status, expires_at=None, note=None, key=None):
    now = datetime.utcnow().isoformat()
    conn = get_db(); c = conn.cursor()
    c.execute("""UPDATE licenses SET status=?, expires_at=?, note=?, key=?, updated_at=? WHERE hwid=?""",
              (status, expires_at, note, key, now, hwid))
    conn.commit(); conn.close()

def hwid_expired_or_revoke_if_needed(row):
    """
    Check a DB row and if expires_at passed, mark revoked/expired.
    Returns effective status string.
    """
    if not row:
        return "error"
    status = row["status"]
    exp = row["expires_at"]
    if exp:
        try:
            exp_dt = datetime.fromisoformat(exp)
            if datetime.utcnow() > exp_dt:
                # expire it
                update_status(row["hwid"], "revoked", expires_at=exp, note="expired")
                return "revoked"
        except Exception:
            pass
    return status

# API endpoint that the desktop client expects
# e.g. GET /api/lisans?hwid=XXXX
@app.route("/api/lisans", methods=["GET"])
def api_lisans():
    hwid = request.args.get("hwid", "").strip()
    if not hwid:
        return jsonify({"status":"error", "message":"hwid required"}), 400

    row = get_license_by_hwid(hwid)
    if not row:
        # not found -> pending by default (or return error). We'll return pending so admin can see.
        upsert_license(hwid, status="pending", key=None, expires_at=None, note="auto-created pending")
        return jsonify({"status":"pending", "message":"Awaiting admin approval", "hwid":hwid})
    # check expiry and auto-update if needed
    effective_status = hwid_expired_or_revoke_if_needed(row)
    # If ok -> return license key in format client expects
    if effective_status == "ok":
        # client-side code expects something like LNR_KEY::BASE64DATA or raw key. we'll return LNR_KEY::<base64>
        payload = row["key"] or ""
        if payload:
            return jsonify({"status":"ok", "key": f"LNR_KEY::{payload}"})
        else:
            # no local key stored; return ok but no key (client will treat ok -> try to save)
            return jsonify({"status":"ok", "key": ""})
    elif effective_status in ("pending",):
        return jsonify({"status":"pending", "message":"Onay bekleniyor", "hwid":hwid})
    elif effective_status in ("revoked","error","revoked_by_admin"):
        return jsonify({"status":"error", "message":"Lisans reddedildi veya süresi doldu", "hwid":hwid})
    else:
        return jsonify({"status":"error", "message":"Bilinmeyen durum", "hwid":hwid})

# --- Admin UI (very small, password protected) ---
def is_logged_in():
    return session.get("admin_logged") is True

@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        user = request.form.get("username","")
        passwd = request.form.get("password","")
        if user == ADMIN_USER and check_password_hash(ADMIN_PASS, passwd):
            session["admin_logged"] = True
            flash("Giriş başarılı", "success")
            return redirect(url_for("admin_index"))
        flash("Kullanıcı adı veya parola hatalı", "danger")
    return render_template("login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged", None)
    flash("Çıkış yapıldı", "info")
    return redirect(url_for("admin_login"))

@app.route("/admin")
def admin_index():
    if not is_logged_in():
        return redirect(url_for("admin_login"))
    rows = list_licenses()
    # convert to dicts for template
    data = []
    for r in rows:
        r = dict(r)
        # effective status (and display)
        eff = hwid_expired_or_revoke_if_needed(r)
        r["effective_status"] = eff
        data.append(r)
    return render_template("admin_index.html", licenses=data)

@app.route("/admin/approve", methods=["POST"])
def admin_approve():
    if not is_logged_in(): return redirect(url_for("admin_login"))
    hwid = request.form.get("hwid")
    days = int(request.form.get("days", "30"))
    note = request.form.get("note", "")
    # create a simple license payload (base64 of JSON) - adapt to your encryption scheme
    payload_obj = {"hwid": hwid, "bitis": (datetime.utcnow() + timedelta(days=days)).date().isoformat()}
    payload_b64 = base64.urlsafe_b64encode(str(payload_obj).encode()).decode()
    expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
    upsert_license(hwid, status="ok", key=payload_b64, expires_at=expires_at, note=note)
    flash(f"{hwid} onaylandı ({days} gün).", "success")
    return redirect(url_for("admin_index"))

@app.route("/admin/revoke", methods=["POST"])
def admin_revoke():
    if not is_logged_in(): return redirect(url_for("admin_login"))
    hwid = request.form.get("hwid")
    note = request.form.get("note", "revoked_by_admin")
    update_status(hwid, "revoked", expires_at=None, note=note)
    flash(f"{hwid} reddedildi/iptal edildi.", "warning")
    return redirect(url_for("admin_index"))

@app.route("/admin/reactivate", methods=["POST"])
def admin_reactivate():
    if not is_logged_in(): return redirect(url_for("admin_login"))
    hwid = request.form.get("hwid")
    days = int(request.form.get("days", "30"))
    note = request.form.get("note", "reactivated")
    payload_obj = {"hwid": hwid, "bitis": (datetime.utcnow() + timedelta(days=days)).date().isoformat()}
    payload_b64 = base64.urlsafe_b64encode(str(payload_obj).encode()).decode()
    expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
    update_status(hwid, "ok", expires_at=expires_at, note=note, key=payload_b64)
    flash(f"{hwid} tekrar aktif edildi ({days} gün).", "success")
    return redirect(url_for("admin_index"))

# admin create manual pending or delete endpoints (optional)
@app.route("/admin/delete", methods=["POST"])
def admin_delete():
    if not is_logged_in(): return redirect(url_for("admin_login"))
    hwid = request.form.get("hwid")
    conn = get_db(); c = conn.cursor(); c.execute("DELETE FROM licenses WHERE hwid=?", (hwid,)); conn.commit(); conn.close()
    flash(f"{hwid} silindi.", "info")
    return redirect(url_for("admin_index"))

# health & root
@app.route("/")
def index():
    return "HWID License Server. Admin: /admin"

if __name__ == "__main__":
    init_db()
    app.run(host=APP_HOST, port=APP_PORT)
