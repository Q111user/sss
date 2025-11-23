import os
import base64
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash

# --- AYARLAR ---
DATABASE = os.environ.get("DB_PATH", "data/licenses.db")
SECRET_KEY = os.environ.get("FLASK_SECRET", "lunar-secret-key-change-me")
RAW_PASSWORD = os.environ.get("ADMIN_PASS", "admin123")
ADMIN_PASS_HASH = generate_password_hash(RAW_PASSWORD)

app = Flask(__name__)
app.config.update(SECRET_KEY=SECRET_KEY)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# --- VERİTABANI ---
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    directory = os.path.dirname(DATABASE)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hwid TEXT UNIQUE NOT NULL,
        status TEXT NOT NULL, 
        key TEXT, 
        expires_at TEXT, 
        note TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()

with app.app_context():
    init_db()

# --- YARDIMCI FONKSİYONLAR ---
def upsert_license(hwid, status="pending", key=None, expires_at=None, note=None):
    now = datetime.utcnow().isoformat()
    conn = get_db(); c = conn.cursor()
    try:
        c.execute("SELECT id FROM licenses WHERE hwid = ?", (hwid,))
        row = c.fetchone()
        if row:
            # Mevcut kaydı güncelle
            c.execute("""UPDATE licenses SET status=?, key=?, expires_at=?, note=?, updated_at=? WHERE hwid=?""",
                      (status, key, expires_at, note, now, hwid))
        else:
            # Yeni kayıt
            c.execute("""INSERT INTO licenses (hwid,status,key,expires_at,note,created_at,updated_at)
                         VALUES (?,?,?,?,?,?,?)""", (hwid,status,key,expires_at,note,now,now))
        conn.commit()
    finally:
        conn.close()

def get_licenses():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM licenses ORDER BY updated_at DESC")
    rows = c.fetchall(); conn.close(); return rows

def update_status_db(hwid, status, expires_at=None, note=None, key=None):
    now = datetime.utcnow().isoformat()
    conn = get_db(); c = conn.cursor()
    c.execute("""UPDATE licenses SET status=?, expires_at=?, note=?, key=?, updated_at=? WHERE hwid=?""",
              (status, expires_at, note, key, now, hwid))
    conn.commit(); conn.close()

def check_expiry(row):
    if not row: return "error"
    status = row["status"]
    if row["expires_at"]:
        try:
            exp_dt = datetime.fromisoformat(row["expires_at"])
            if datetime.utcnow() > exp_dt:
                # Veritabanında güncellemeye gerek yok, anlık kontrol yeterli
                # Ancak 'revoked' olarak işaretlemek istersek burada update_status_db çağrılabilir.
                # Şimdilik sadece durumu döndürüyoruz.
                return "revoked"
        except: pass
    return status

# --- API ---
@app.route("/api/lisans", methods=["GET"])
def api_lisans():
    hwid = request.args.get("hwid", "").strip()
    if not hwid: return jsonify({"status":"error", "message":"HWID gerekli"}), 400

    conn = get_db(); c = conn.cursor()
    c.execute("SELECT * FROM licenses WHERE hwid = ?", (hwid,))
    row = c.fetchone(); conn.close()

    if not row:
        upsert_license(hwid, status="pending", note="Otomatik talep")
        return jsonify({"status":"pending", "message":"Onay Bekleniyor", "hwid":hwid})

    status = check_expiry(row)
    
    if status == "ok":
        return jsonify({"status":"ok", "key": f"LNR_KEY::{row['key']}" if row['key'] else ""})
    elif status == "pending":
        return jsonify({"status":"pending", "message":"Onay Bekleniyor"})
    else:
        return jsonify({"status":"error", "message":"Lisans Gecersiz"})

# --- ADMIN ROUTES ---
@app.route("/admin/login", methods=["GET","POST"])
def admin_login():
    if request.method == "POST":
        password = request.form.get("password")
        if check_password_hash(ADMIN_PASS_HASH, password):
            session["admin_logged"] = True
            session.permanent = True
            return redirect(url_for("admin_index"))
        else:
            flash("Hatalı Şifre!", "danger")
    return render_template("login.html")

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_login"))

@app.route("/admin")
def admin_index():
    if not session.get("admin_logged"): return redirect(url_for("admin_login"))
    
    raw_rows = get_licenses()
    
    pending_list = []
    active_list = []
    
    stats = {"total": 0, "active": 0, "pending": 0, "banned": 0}
    
    for r in raw_rows:
        r_dict = dict(r)
        eff_status = check_expiry(r)
        r_dict["effective_status"] = eff_status
        
        # İstatistikler
        stats["total"] += 1
        if eff_status == "ok": stats["active"] += 1
        elif eff_status == "pending": stats["pending"] += 1
        else: stats["banned"] += 1

        # Kalan Gün Hesaplama
        remaining_str = "-"
        if r_dict.get("expires_at"):
            try:
                exp_dt = datetime.fromisoformat(r_dict["expires_at"])
                delta = exp_dt - datetime.utcnow()
                if delta.days < 0:
                    remaining_str = "Süresi Doldu"
                else:
                    remaining_str = f"{delta.days} Gün"
            except: pass
        r_dict["remaining_days"] = remaining_str

        # Listelere Ayırma
        if eff_status == "pending":
            pending_list.append(r_dict)
        else:
            active_list.append(r_dict)
        
    return render_template("admin_index.html", 
                           pending_licenses=pending_list, 
                           active_licenses=active_list, 
                           stats=stats)

@app.route("/admin/action", methods=["POST"])
def admin_action():
    if not session.get("admin_logged"): return redirect(url_for("admin_login"))
    
    action = request.form.get("action")
    hwid = request.form.get("hwid")
    days = int(request.form.get("days", 30))
    note = request.form.get("note", "")

    if action == "approve":
        exp_date = (datetime.utcnow() + timedelta(days=days))
        # Basit JSON payload
        payload = {"hwid": hwid, "bitis": exp_date.strftime("%Y-%m-%d")}
        key_b64 = base64.urlsafe_b64encode(str(payload).encode()).decode()
        
        upsert_license(hwid, "ok", key=key_b64, expires_at=exp_date.isoformat(), note=note)
        flash(f"{hwid} onaylandı ({days} gün).", "success")
        
    elif action == "revoke":
        update_status_db(hwid, "revoked", note=note or "Yönetici tarafından iptal")
        flash(f"{hwid} erişimi kapatıldı.", "warning")
        
    elif action == "delete":
        conn = get_db(); c = conn.cursor()
        c.execute("DELETE FROM licenses WHERE hwid=?", (hwid,))
        conn.commit(); conn.close()
        flash(f"{hwid} silindi.", "danger")

    return redirect(url_for("admin_index"))

@app.route("/")
def index():
    return "Lunar License Server Active."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
