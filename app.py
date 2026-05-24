from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_session import Session
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.utils import secure_filename

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart

from dotenv import load_dotenv

import sqlite3
import os
import hashlib
import shutil
import smtplib
import pytz
import resend
from datetime import datetime

from email.mime.text import MIMEText

# ================= LOAD ENV =================
load_dotenv()

# ================= APP =================
app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", "dev_secret")

app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# ================= IMPORTANT FOR RENDER =================
PORT = int(os.environ.get("PORT", 5000))

# ================= FOLDERS =================
UPLOAD_FOLDER = "uploads"
ORIGINAL_FOLDER = "original_files"
REPORT_FOLDER = "reports"

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ORIGINAL_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# ================= GOOGLE LOGIN =================
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

google_bp = make_google_blueprint(
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    scope=[
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "openid"
    ],
    redirect_url="/google_login"
)

app.register_blueprint(google_bp, url_prefix="/login")

# ================= DATABASE =================
def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS file_history(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            upload_time TEXT,
            modified_time TEXT,
            status TEXT,
            hash TEXT,
            score INTEGER,
            risk TEXT,
            changes TEXT,
            user_email TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# ================= TIME =================
def indian_time():
    tz = pytz.timezone("Asia/Kolkata")
    return datetime.now(tz).strftime("%d-%m-%Y %H:%M:%S")

# ================= HASH =================
def sha256(filepath):
    h = hashlib.sha256()

    with open(filepath, "rb") as file:
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()

# ================= CHANGE DETECTION =================
def detect_changes(old_file, new_file):
    try:
        with open(old_file, "r", errors="ignore") as f1:
            old_lines = f1.readlines()

        with open(new_file, "r", errors="ignore") as f2:
            new_lines = f2.readlines()
    except Exception:
        return "Binary or unreadable file"

    changed_lines = []
    max_len = max(len(old_lines), len(new_lines))

    for i in range(max_len):
        old = old_lines[i].strip() if i < len(old_lines) else ""
        new = new_lines[i].strip() if i < len(new_lines) else ""

        if old != new:
            changed_lines.append(i + 1)

    if not changed_lines:
        return "No changes"

    if len(changed_lines) > 15:
        return f"{len(changed_lines)} lines modified"

    return "Lines Changed: " + ", ".join(map(str, changed_lines))

# ================= SECURITY SCORE =================
def security_score(changes):
    count = len(changes.split(","))

    if count == 0:
        return 100, "Low"
    elif count <= 3:
        return 70, "Medium"
    elif count <= 7:
        return 40, "High"
    return 10, "Critical"

# ================= EMAIL (FIXED FOR RENDER SAFE EXECUTION) =================

resend.api_key = os.getenv("RESEND_API_KEY")

def send_email(receiver, filename, upload_time, modified_time):

    try:
        resend.Emails.send({
            "from": "onboarding@resend.dev",
            "to": receiver,
            "subject": "File Integrity Alert",
            "html": f"""
                <h2>File Modified Alert</h2>
                <p><b>File:</b> {filename}</p>
                <p><b>Upload Time:</b> {upload_time}</p>
                <p><b>Modified Time:</b> {modified_time}</p>
            """
        })

        print("EMAIL SENT SUCCESS")

    except Exception as e:
        print("EMAIL FAILED:", str(e))
# ================= ROUTES =================
@app.route("/")
def home():
    return render_template("login.html")

@app.route("/google_login")
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    resp = google.get("/oauth2/v2/userinfo")
    info = resp.json()

    session["email"] = info["email"]
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    if "email" not in session:
        return redirect("/")

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM file_history ORDER BY id DESC")
    data = cur.fetchall()

    conn.close()

    return render_template("dashboard.html", email=session["email"], history=data)

@app.route("/upload", methods=["POST"])
def upload():

    if "email" not in session:
        return redirect("/")

    file = request.files.get("file")

    if not file or file.filename == "":
        flash("No file uploaded")
        return redirect("/dashboard")

    filename = secure_filename(file.filename)
    upload_path = os.path.join(UPLOAD_FOLDER, filename)

    file.save(upload_path)

    current_hash = sha256(upload_path)

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM file_history WHERE filename=? ORDER BY id DESC LIMIT 1",
        (filename,)
    )

    existing = cur.fetchone()
    upload_time = indian_time()

    if existing is None:

        shutil.copy(upload_path, os.path.join(ORIGINAL_FOLDER, filename))

        cur.execute("""
            INSERT INTO file_history VALUES (NULL,?,?,?,?,?,?,?,?,?)
        """, (
            filename, upload_time, "-", "Original",
            current_hash, 100, "Low", "No changes", session["email"]
        ))

        flash("Original file uploaded")

    else:

        old_hash = existing[5]

        if old_hash != current_hash:

            original = os.path.join(ORIGINAL_FOLDER, filename)
            changes = detect_changes(original, upload_path)
            score, risk = security_score(changes)
            modified_time = indian_time()

            # SAFE EMAIL CALL (won’t crash app)
            send_email(session["email"], filename, existing[2], modified_time)

            cur.execute("""
                INSERT INTO file_history VALUES (NULL,?,?,?,?,?,?,?,?,?)
            """, (
                filename, existing[2], modified_time, "Modified",
                current_hash, score, risk, changes, session["email"]
            ))

            flash("Modified file detected")

        else:

            cur.execute("""
                INSERT INTO file_history VALUES (NULL,?,?,?,?,?,?,?,?,?)
            """, (
                filename, upload_time, "-", "Unchanged",
                current_hash, 100, "Low", "No changes", session["email"]
            ))

            flash("File unchanged")

    conn.commit()
    conn.close()

    return redirect("/dashboard")

@app.route("/restore/<filename>")
def restore(filename):

    shutil.copy(
        os.path.join(ORIGINAL_FOLDER, filename),
        os.path.join(UPLOAD_FOLDER, filename)
    )

    flash("Restored successfully")
    return redirect("/dashboard")

@app.route("/clear")
def clear():

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM file_history")
    conn.commit()
    conn.close()

    flash("History cleared")
    return redirect("/dashboard")

@app.route("/report/<int:file_id>")
def report(file_id):

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM file_history WHERE id=?", (file_id,))
    row = cur.fetchone()
    conn.close()

    path = os.path.join(REPORT_FOLDER, f"report_{file_id}.pdf")

    doc = SimpleDocTemplate(path)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("File Integrity Report", styles['Title']))
    story.append(Spacer(1, 20))

    for item in [
        f"File: {row[1]}",
        f"Upload: {row[2]}",
        f"Modified: {row[3]}",
        f"Status: {row[4]}",
        f"Score: {row[6]}",
        f"Risk: {row[7]}",
        f"Email: {row[9]}",
        f"Changes: {row[8]}"
    ]:
        story.append(Paragraph(item, styles['BodyText']))
        story.append(Spacer(1, 10))

    doc.build(story)

    return send_file(path, as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ================= RENDER SAFE START =================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
