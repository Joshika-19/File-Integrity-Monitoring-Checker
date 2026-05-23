from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from flask_session import Session
from flask_dance.contrib.google import make_google_blueprint, google
from werkzeug.utils import secure_filename
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics import renderPDF
from reportlab.graphics.widgets.markers import makeMarker
from reportlab.platypus.flowables import Flowable
import sqlite3
import os
import hashlib
import difflib
import shutil
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
import pytz

app = Flask(__name__)

app.secret_key = "SUPER_SECRET_KEY"

app.config["SESSION_TYPE"] = "filesystem"
Session(app)

UPLOAD_FOLDER = "uploads"
ORIGINAL_FOLDER = "original_files"
REPORT_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ORIGINAL_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# ================= GOOGLE LOGIN =================

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

google_bp = make_google_blueprint(
    client_id="681899477080-ot5p2hifd882k2gbg5nqtj8ff25glq67.apps.googleusercontent.com",
    client_secret="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",
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
        while chunk := file.read(4096):
            h.update(chunk)

    return h.hexdigest()

# ================= CHANGE DETECTION =================

def detect_changes(old_file, new_file):

    with open(old_file, "r", errors="ignore") as f1:
        old_lines = f1.readlines()

    with open(new_file, "r", errors="ignore") as f2:
        new_lines = f2.readlines()

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
    count = len(changes.splitlines())

    if count == 0:
        return 100, "Low"

    elif count <= 3:
        return 70, "Medium"

    elif count <= 7:
        return 40, "High"

    return 10, "High"

# ================= EMAIL =================

def send_email(receiver, filename, upload_time, modified_time):

    sender = "joshikakavitha47@gmail.com"
    password = "naoo sbyy xffv unlv"

    body = f"""
Warning: File integrity violation detected

File Name: {filename}

Upload Time: {upload_time}

Modified Time: {modified_time}

User: {receiver}
"""

    msg = MIMEText(body)

    msg["Subject"] = "File Integrity Alert"
    msg["From"] = sender
    msg["To"] = receiver

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
        server.quit()

    except Exception as e:
        print(e)

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

    return render_template(
        "dashboard.html",
        email=session["email"],
        history=data
    )

# ================= UPLOAD =================

@app.route("/upload", methods=["POST"])
def upload():

    if "file" not in request.files:
        return redirect("/dashboard")

    file = request.files["file"]

    if file.filename == "":
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
            INSERT INTO file_history
            (filename, upload_time, modified_time, status, hash, score, risk, changes, user_email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            filename,
            upload_time,
            "-",
            "Original",
            current_hash,
            100,
            "Low",
            "No changes",
            session["email"]
        ))

    else:

        old_hash = existing[5]

        if old_hash != current_hash:

            original = os.path.join(ORIGINAL_FOLDER, filename)

            changes = detect_changes(original, upload_path)

            score, risk = security_score(changes)

            modified_time = indian_time()

            send_email(
                session["email"],
                filename,
                existing[2],
                modified_time
            )

            cur.execute("""
                INSERT INTO file_history
                (filename, upload_time, modified_time, status, hash, score, risk, changes, user_email)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                filename,
                existing[2],
                modified_time,
                "Modified",
                current_hash,
                score,
                risk,
                changes,
                session["email"]
            ))

        else:

            cur.execute("""
                INSERT INTO file_history
                (filename, upload_time, modified_time, status, hash, score, risk, changes, user_email)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                filename,
                upload_time,
                "-",
                "Unchanged",
                current_hash,
                100,
                "Low",
                "No changes",
                session["email"]
            ))

    conn.commit()
    conn.close()

    flash("File uploaded successfully")

    return redirect("/dashboard")

# ================= RESTORE =================

@app.route("/restore/<filename>")
def restore(filename):

    original = os.path.join(ORIGINAL_FOLDER, filename)
    upload = os.path.join(UPLOAD_FOLDER, filename)

    shutil.copy(original, upload)

    flash("Original file restored successfully")

    return redirect("/dashboard")

# ================= CLEAR =================

@app.route("/clear")
def clear():

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("DELETE FROM file_history")

    conn.commit()
    conn.close()

    flash("History Cleared")

    return redirect("/dashboard")

# ================= PDF =================

@app.route("/report/<int:file_id>")
def report(file_id):

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM file_history WHERE id=?", (file_id,))

    row = cur.fetchone()

    conn.close()

    filename = f"report_{file_id}.pdf"

    path = os.path.join(REPORT_FOLDER, filename)

    doc = SimpleDocTemplate(path)

    styles = getSampleStyleSheet()

    story = []

    story.append(Paragraph("<b>File Integrity Monitoring Report</b>", styles['Title']))
    story.append(Spacer(1, 20))

    fields = [
        f"File Name: {row[1]}",
        f"Upload Time: {row[2]}",
        f"Modified Time: {row[3]}",
        f"Status: {row[4]}",
        f"Security Score: {row[6]}",
        f"Risk Level: {row[7]}",
        f"User Email: {row[9]}",
        f"Changes: {row[8]}"
    ]

    for item in fields:
        story.append(Paragraph(item, styles['BodyText']))
        story.append(Spacer(1, 10))

    drawing = Drawing(400, 200)

    chart = VerticalBarChart()

    chart.x = 50
    chart.y = 50
    chart.height = 125
    chart.width = 300

    chart.data = [[row[6]]]

    chart.categoryAxis.categoryNames = ["Risk Score"]

    drawing.add(chart)

    story.append(drawing)

    doc.build(story)

    return send_file(path, as_attachment=True)

# ================= LOGOUT =================

@app.route("/logout")
def logout():

    session.clear()

    try:
        del google_bp.token
    except:
        pass

    return redirect("/")

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000)
