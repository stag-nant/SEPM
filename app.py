from flask import Flask, request, jsonify, send_file, render_template
import os
import datetime

app = Flask(__name__)

# Simulated vulnerability database with severity and fix suggestions
vulnerability_db = {
    "eval": {"severity": "Critical", "fix": "Avoid using eval() in production code."},
    "exec": {"severity": "High", "fix": "Replace exec() with safer alternatives."},
    "input": {"severity": "Medium", "fix": "Sanitize user input properly."},
    "print": {"severity": "Low", "fix": "Remove debug statements in production."},
    "os.system": {"severity": "Critical", "fix": "Use subprocess module instead of os.system."},
    "pickle": {"severity": "High", "fix": "Avoid untrusted pickle loading due to RCE risks."}
}

# Store scan logs for reports
logs = []

# Function to categorize vulnerabilities by severity
def categorize_severity(code):
    issues = []
    for keyword, details in vulnerability_db.items():
        if keyword in code:
            issues.append({
                "keyword": keyword,
                "severity": details["severity"],
                "fix": details["fix"]
            })
    return issues

# Home route for the web interface
@app.route('/')
def index():
    return render_template('index.html')

# Upload endpoint for code analysis
@app.route('/upload', methods=['POST'])
def upload():
    data = request.get_json()

    if not data or 'code' not in data:
        return jsonify({"error": "Invalid request"}), 400

    code = data['code']
    
    vulnerabilities = categorize_severity(code)

    # Log the scan results
    if vulnerabilities:
        log_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "code": code,
            "vulnerabilities": vulnerabilities
        }
        logs.append(log_entry)

        response = {
            "status": "Vulnerabilities found",
            "vulnerabilities": vulnerabilities
        }
    else:
        response = {"status": "No vulnerabilities found"}

    return jsonify(response), 200

# Generate and download scan report
@app.route('/report', methods=['GET'])
def download_report():
    report_file = "scan_report.txt"

    with open(report_file, "w") as file:
        file.write("SafeCode Vulnerability Scan Report\n")
        file.write("="*40 + "\n\n")
        
        for log in logs:
            file.write(f"Timestamp: {log['timestamp']}\n")
            file.write(f"Scanned Code:\n{log['code']}\n")
            
            if log['vulnerabilities']:
                file.write("\nDetected Vulnerabilities:\n")
                for vuln in log['vulnerabilities']:
                    file.write(f"  - Keyword: {vuln['keyword']}\n")
                    file.write(f"    Severity: {vuln['severity']}\n")
                    file.write(f"    Fix: {vuln['fix']}\n")
                    file.write("\n")
            else:
                file.write("\nNo vulnerabilities found.\n")

            file.write("="*40 + "\n\n")

    return send_file(report_file, as_attachment=True)

# Run the server
if __name__ == '__main__':
    app.run(debug=True)
