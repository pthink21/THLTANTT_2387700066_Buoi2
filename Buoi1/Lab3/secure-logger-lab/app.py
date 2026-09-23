"""
Flask API Demo — SecureLogger + SecureValidator Integration
Endpoints:
  GET  /              — Trang chủ / hướng dẫn
  POST /api/validate  — Gọi SecureValidator + ghi SecureLogger
  GET  /api/integrity — Kiểm tra tamper detection
  GET  /api/log/view  — Xem 20 dòng log gần nhất

Security:
  - Không hiển thị stack trace ra UI
  - PII trong log được mask tự động
  - Không log secret, password
"""

import os
import json
from flask import Flask, request, jsonify, render_template_string

from securevalidator import (
    validate_email,
    validate_url,
    validate_filename,
    sanitize_sql_input,
    sanitize_html_input,
)
from securelogger import SecureLogger

app = Flask(__name__)
app.config["DEBUG"] = False

# Khởi tạo SecureLogger (tập trung một instance)
LOG_FILE = "secure.log"
logger = SecureLogger(log_file=LOG_FILE)

# Ghi log khởi động
logger.info("SecureLogger Flask app started", event="app_startup", source="app")


# ─────────────────────────────────────────────────────────────
# HOME PAGE
# ─────────────────────────────────────────────────────────────

HOME_HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
  <meta charset="UTF-8"/>
  <title>SecureLogger Demo</title>
  <style>
    body { font-family: 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #333; }
    h1 { color: #1a237e; }
    h2 { color: #283593; margin-top: 30px; }
    code { background: #e8eaf6; padding: 2px 6px; border-radius: 3px; font-size: 0.9em; }
    pre { background: #f5f5f5; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 0.88em; }
    .endpoint { margin: 12px 0; padding: 12px; border-left: 4px solid #3949ab; background: #e8eaf6; }
    .method { font-weight: bold; color: #1a237e; }
    .note { background: #fff8e1; padding: 12px; border-radius: 6px; border-left: 4px solid #ffa000; margin: 12px 0; }
  </style>
</head>
<body>
  <h1>🔐 SecureLogger API Demo</h1>
  <p>Hệ thống ghi nhật ký bảo mật với PII masking và tamper detection.</p>

  <h2>📡 API Endpoints</h2>

  <div class="endpoint">
    <span class="method">POST</span> <code>/api/validate</code><br>
    Body JSON: <code>{"type": "email", "input": "user@example.com"}</code><br>
    Types: <code>email</code>, <code>url</code>, <code>filename</code>, <code>sql</code>, <code>html</code>
  </div>

  <div class="endpoint">
    <span class="method">GET</span> <code>/api/integrity</code><br>
    Kiểm tra tamper detection — xác nhận log file chưa bị thay đổi.
  </div>

  <div class="endpoint">
    <span class="method">GET</span> <code>/api/log/view</code><br>
    Xem 20 dòng log gần nhất (cho mục đích demo).
  </div>

  <h2>📝 Ví dụ với Postman / curl</h2>
  <pre>POST http://127.0.0.1:5000/api/validate
Content-Type: application/json

{
  "type": "email",
  "input": "user@example.com"
}</pre>

  <pre>curl -X POST http://127.0.0.1:5000/api/validate \\
     -H "Content-Type: application/json" \\
     -d '{"type": "email", "input": "user@example.com"}'</pre>

  <h2>🛡️ PII Masking Demo</h2>
  <pre>POST /api/validate
{
  "type": "email",
  "input": "nguyen.van.an@example.com"
}

→ Log ghi: "[email] Input: 'n***@example.com'"
   (Email bị mask trước khi ghi vào log)</pre>

  <h2>🔍 Tamper Detection</h2>
  <pre>GET /api/integrity

→ {"valid": true, "reason": "Log file toàn vẹn..."}</pre>

  <div class="note">
    ⚠️ <strong>Lưu ý:</strong> Log file <code>secure.log</code> và <code>secure.log.sig</code>
    được tạo trong thư mục chạy app. Không commit các file này vào repository.
  </div>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HOME_HTML)


# ─────────────────────────────────────────────────────────────
# VALIDATE ENDPOINT
# ─────────────────────────────────────────────────────────────

VALIDATOR_MAP = {
    "email": validate_email,
    "url": validate_url,
    "filename": validate_filename,
    "sql": sanitize_sql_input,
    "html": sanitize_html_input,
}


@app.route("/api/validate", methods=["POST"])
def api_validate():
    """
    Gọi SecureValidator và ghi kết quả vào SecureLogger.
    PII trong input sẽ được mask tự động trước khi log.
    """
    data = request.get_json(silent=True)
    if not data:
        logger.warning("Invalid request: no JSON body", event="bad_request", source="api")
        return jsonify({"error": "Yêu cầu phải có body JSON."}), 400

    validation_type = str(data.get("type", "")).lower().strip()
    input_value = data.get("input", "")

    if validation_type not in VALIDATOR_MAP:
        logger.warning(
            f"Unknown validation type: {validation_type}",
            event="bad_request", source="api"
        )
        return jsonify({
            "error": f"Type không hợp lệ. Chọn một trong: {', '.join(VALIDATOR_MAP.keys())}"
        }), 400

    if not isinstance(input_value, str):
        input_value = str(input_value)

    # Giới hạn độ dài input
    input_value = input_value[:2000]

    # Gọi validator
    validator_fn = VALIDATOR_MAP[validation_type]
    result = validator_fn(input_value)

    # Ghi log (PII tự động được mask trong logger.log_validation)
    logger.log_validation(
        validation_type=validation_type,
        input_value=input_value,
        result=result,
        source="api",
    )

    return jsonify({
        "type": validation_type,
        "input": input_value[:100] + ("..." if len(input_value) > 100 else ""),
        "result": result,
        "log_file": LOG_FILE,
    })


# ─────────────────────────────────────────────────────────────
# INTEGRITY CHECK ENDPOINT
# ─────────────────────────────────────────────────────────────

@app.route("/api/integrity", methods=["GET"])
def api_integrity():
    """Kiểm tra tính toàn vẹn của log file bằng tamper detection."""
    integrity = logger.verify_integrity()
    logger.info(
        f"Integrity check: {integrity['reason']}",
        event="integrity_check", source="api"
    )
    return jsonify(integrity)


# ─────────────────────────────────────────────────────────────
# VIEW LOG ENDPOINT (Demo only)
# ─────────────────────────────────────────────────────────────

@app.route("/api/log/view", methods=["GET"])
def api_log_view():
    """
    Xem 20 dòng log gần nhất.
    Demo only — trong production không expose endpoint này ra public.
    """
    if not os.path.exists(LOG_FILE):
        return jsonify({"entries": [], "message": "Log file chưa tồn tại."})

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Lấy 20 dòng cuối
        recent_lines = lines[-20:]
        entries = []
        for line in recent_lines:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    entries.append({"raw": line})

        return jsonify({"entries": entries, "total_lines": len(lines)})
    except Exception:
        # Không để lộ chi tiết lỗi
        return jsonify({"error": "Không thể đọc log file."}), 500


# ─────────────────────────────────────────────────────────────
# ERROR HANDLERS
# ─────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Không tìm thấy endpoint."}), 404


@app.errorhandler(500)
def server_error(e):
    logger.error("Internal server error occurred", event="server_error")
    return jsonify({"error": "Lỗi server nội bộ. Vui lòng thử lại."}), 500


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n[SecureLogger] Khởi động Flask app tại http://127.0.0.1:5001/")
    print(f"[SecureLogger] Log file: {LOG_FILE}")
    print(f"[SecureLogger] Signature: {LOG_FILE}.sig\n")
    app.run(host="127.0.0.1", port=5001, debug=False)
