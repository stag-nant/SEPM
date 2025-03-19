from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# Simple security patterns for demonstration
SECURITY_PATTERNS = {
    "Critical": [r"eval\(", r"exec\(", r"pickle\.loads"],
    "High": [r"subprocess\.Popen", r"os\.system", r"open\(.*'w'"],
    "Medium": [r"md5\(", r"sha1\("],
    "Low": [r"print\(", r"debug"]
}

def analyze_code(code):
    vulnerabilities = []
    
    for severity, patterns in SECURITY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, code):
                vulnerabilities.append({"severity": severity, "issue": pattern})
    
    return vulnerabilities

@app.route('/upload', methods=['POST'])
def upload_code():
    data = request.get_json()
    if not data or 'code' not in data:
        return jsonify({"error": "No code provided"}), 400
    
    code = data['code']
    vulnerabilities = analyze_code(code)
    
    return jsonify({
        "message": "Security analysis complete",
        "vulnerabilities": vulnerabilities
    })

if __name__ == '__main__':
    app.run(debug=True)
