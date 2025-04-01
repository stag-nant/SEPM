# app.py (Final Clean Version with User Stories 1-9)

from flask import Flask, request, jsonify, render_template, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///safecode.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'safecode_secret'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# =====================
# Database Models
# =====================

class ScanLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.Text, nullable=False)
    vulnerabilities = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(50))  # alert or update
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# =====================
# Vulnerability Database
# =====================

vulnerability_db = {
    "eval": {"severity": "Critical", "fix": "Avoid using eval()."},
    "exec": {"severity": "High", "fix": "Avoid using exec()."},
    "input": {"severity": "Medium", "fix": "Sanitize user input."},
    "print": {"severity": "Low", "fix": "Remove debug prints."},
    "os.system": {"severity": "Critical", "fix": "Use subprocess module."},
    "pickle": {"severity": "High", "fix": "Avoid unsafe deserialization."}
}

# =====================
# Utility Functions
# =====================

def analyze_code(code):
    issues = []
    for keyword, detail in vulnerability_db.items():
        if keyword in code:
            issues.append({
                "keyword": keyword,
                "severity": detail['severity'],
                "fix": detail['fix']
            })

    if any(i['severity'] == 'Critical' for i in issues):
        db.session.add(Notification(message="Critical vulnerability detected!", type="alert"))

    return issues

# =====================
# Routes
# =====================

@app.route('/')
def index():
    notifications = Notification.query.order_by(Notification.timestamp.desc()).limit(5).all()
    return render_template("index.html", notifications=notifications)

@app.route('/upload', methods=['POST'])
def upload():
    data = request.get_json()
    code = data.get("code", "")
    if not code:
        return jsonify({"error": "No code received"}), 400

    issues = analyze_code(code)
    scan = ScanLog(code=code, vulnerabilities=str(issues) if issues else "None")
    db.session.add(scan)
    db.session.commit()

    return jsonify({
        "status": "Vulnerabilities found" if issues else "No vulnerabilities found",
        "vulnerabilities": issues
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()
    code = data.get("code", "")

    if not code:
        return jsonify({
            "success": False,
            "error": "No code provided"
        }), 400

    issues = analyze_code(code)

    # Do not save code to DB for API scans (to support privacy)
    return jsonify({
        "success": True,
        "vulnerabilities": issues,
        "status": "Vulnerabilities found" if issues else "No vulnerabilities found"
    }), 200

@app.route('/report')
def report():
    path = "scan_report.txt"
    with open(path, 'w') as f:
        logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).all()
        for log in logs:
            f.write(f"Time: {log.timestamp}\nCode: {log.code}\nVulns: {log.vulnerabilities}\n{'='*30}\n")
    return send_file(path, as_attachment=True)

@app.route('/admin')
def admin():
    logs = ScanLog.query.order_by(ScanLog.timestamp.desc()).all()
    notifications = Notification.query.order_by(Notification.timestamp.desc()).all()
    return render_template('admin.html', logs=logs, notifications=notifications)


@app.route('/admin/notify', methods=['POST'])
def admin_notify():
    data = request.get_json()
    msg = data.get("message", "")
    if msg:
        db.session.add(Notification(message=msg, type="update"))
        db.session.commit()
        return jsonify({"status": "Notification sent"})
    return jsonify({"error": "No message provided"}), 400

if __name__ == '__main__':
    app.run(debug=True)
