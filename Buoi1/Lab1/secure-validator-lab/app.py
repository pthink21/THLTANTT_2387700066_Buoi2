"""
Flask Web Application — SecureValidator Demo
Cung cấp giao diện web để demo các chức năng của SecureValidator.

Security notes:
- Không hiển thị stack trace ra UI
- Không tin tưởng input từ người dùng
- Validate trước khi process
"""

from flask import Flask, render_template, request, jsonify

from securevalidator import (
    validate_email,
    validate_url,
    validate_filename,
    sanitize_sql_input,
    sanitize_html_input,
)

app = Flask(__name__)

# Tắt debug mode trong production
app.config["DEBUG"] = False
# Không hiển thị exception details ra user
app.config["PROPAGATE_EXCEPTIONS"] = False


@app.route("/")
def index():
    """Trang chính — giao diện demo."""
    return render_template("index.html")


@app.route("/api/validate/email", methods=["POST"])
def api_validate_email():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    result = validate_email(str(email))
    return jsonify({"input": str(email)[:500], "result": result})


@app.route("/api/validate/url", methods=["POST"])
def api_validate_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    result = validate_url(str(url))
    return jsonify({"input": str(url)[:500], "result": result})


@app.route("/api/validate/filename", methods=["POST"])
def api_validate_filename():
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "")
    result = validate_filename(str(filename))
    return jsonify({"input": str(filename)[:500], "result": result})


@app.route("/api/sanitize/sql", methods=["POST"])
def api_sanitize_sql():
    data = request.get_json(silent=True) or {}
    sql_input = data.get("input", "")
    result = sanitize_sql_input(str(sql_input))
    return jsonify({"input": str(sql_input)[:500], "result": result})


@app.route("/api/sanitize/html", methods=["POST"])
def api_sanitize_html():
    data = request.get_json(silent=True) or {}
    html_input = data.get("input", "")
    result = sanitize_html_input(str(html_input))
    return jsonify({"input": str(html_input)[:500], "result": result})


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Không tìm thấy tài nguyên."}), 404


@app.errorhandler(500)
def server_error(e):
    # KHÔNG để lộ chi tiết lỗi nội bộ
    return jsonify({"error": "Có lỗi xảy ra trên server. Vui lòng thử lại."}), 500


if __name__ == "__main__":
    # Chỉ bind localhost khi chạy development
    app.run(host="127.0.0.1", port=5000, debug=False)
