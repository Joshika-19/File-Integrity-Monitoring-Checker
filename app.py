from flask import Flask, render_template, request, redirect
import os
import hashlib
import json
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"

# 🔐 Hash Function
def generate_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# 📂 Load DB
def load_db():
    try:
        with open("database.json", "r") as f:
            return json.load(f)
    except:
        return {}

# 💾 Save DB
def save_db(data):
    with open("database.json", "w") as f:
        json.dump(data, f, indent=4)

# 🏠 Dashboard
@app.route("/")
def dashboard():
    db = load_db()
    return render_template("dashboard.html", data=db)

# 📤 Upload
@app.route("/upload", methods=["POST"])
def upload():
    file = request.files["file"]

    if file:
        path = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(path)

        file_hash = generate_hash(path)
        db = load_db()

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 🔥 FIXED LOGIC
        if file.filename in db:
            if db[file.filename]["hash"] == file_hash:
                status = "Safe"
                upload_time = db[file.filename]["upload_time"]
                modified_time = db[file.filename]["modified_time"]
            else:
                status = "Modified"
                upload_time = db[file.filename]["upload_time"]
                modified_time = current_time
        else:
            status = "New File"
            upload_time = current_time
            modified_time = "-"   # 👈 important fix

        db[file.filename] = {
            "hash": file_hash,
            "status": status,
            "upload_time": upload_time,
            "modified_time": modified_time
        }

        save_db(db)

        return redirect("/")

    return "No file selected"

# 🧹 Clear History
@app.route("/clear")
def clear():
    with open("database.json", "w") as f:
        json.dump({}, f)
    return redirect("/")

# ▶️ Run
if __name__ == "__main__":
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)

    app.run(debug=True)