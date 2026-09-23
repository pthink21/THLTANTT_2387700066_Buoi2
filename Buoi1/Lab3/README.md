# Lab 3 — SecureLogger

## 1. Mục tiêu

Xây dựng hệ thống **SecureLogger** — ghi nhật ký bảo mật với các tính năng:

| Tính năng | Mô tả |
|---|---|
| Log Levels | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| PII Masking | Tự động mask email, CCCD, IP, số điện thoại |
| Log Rotation | Rotate khi file > 5MB, giữ 5 bản backup |
| Compression | Nén file log cũ bằng gzip |
| Tamper Detection | SHA-256 hash để phát hiện log bị thay đổi |
| JSON Format | Log có cấu trúc JSON |
| SecureValidator | Tích hợp ghi log mỗi lần validation |

---

## 2. Cấu trúc project

```
secure-logger-lab/
├── app.py                     # Flask API demo
├── requirements.txt
├── securevalidator/           # Từ Lab1 (copy)
│   ├── __init__.py
│   └── core.py
└── securelogger/
    ├── __init__.py
    └── logger.py              # SecureLogger implementation
```

---

## 3. Cài đặt

### Tạo virtual environment (khuyến nghị)

```bash
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux/macOS
```

### Cài dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Chạy ứng dụng

```bash
python app.py
```

App chạy tại: **http://127.0.0.1:5001/**

---

## 5. API Endpoints

### POST /api/validate

Gọi SecureValidator và ghi log. PII tự động được mask.

**Request:**
```json
{
  "type": "email",
  "input": "nguyen.van.an@example.com"
}
```

**Types hỗ trợ:** `email`, `url`, `filename`, `sql`, `html`

**curl:**
```bash
curl -X POST http://127.0.0.1:5001/api/validate \
     -H "Content-Type: application/json" \
     -d '{"type": "email", "input": "nguyen.van.an@example.com"}'
```

**Response:**
```json
{
  "type": "email",
  "input": "nguyen.van.an@example.com",
  "result": {"valid": true, "reason": "Email hợp lệ."},
  "log_file": "secure.log"
}
```

### GET /api/integrity

Kiểm tra tamper detection.

```bash
curl http://127.0.0.1:5001/api/integrity
```

**Response (log toàn vẹn):**
```json
{
  "valid": true,
  "stored_hash": "abc123...",
  "current_hash": "abc123...",
  "reason": "Log file toàn vẹn — không bị thay đổi."
}
```

### GET /api/log/view

Xem 20 dòng log gần nhất (demo only).

```bash
curl http://127.0.0.1:5001/api/log/view
```

---

## 6. Sử dụng SecureLogger trực tiếp

```python
from securelogger import SecureLogger

logger = SecureLogger(log_file="secure.log")

# Ghi log bình thường
logger.info("User logged in", event="login", user_id="user_123")
logger.warning("Invalid input detected", event="validation_failed")
logger.error("Database connection failed", event="db_error")

# PII tự động được mask
logger.info("Email: nguyen.van.an@example.com đã đăng ký")
# → Log ghi: "Email: n***@example.com đã đăng ký"

logger.info("IP người dùng: 192.168.1.100")
# → Log ghi: "IP người dùng: 192.168.*.*"
```

---

## 7. Format JSON Log

Mỗi entry trong `secure.log`:

```json
{
  "timestamp": "2024-01-15T10:30:45Z",
  "level": "INFO",
  "event": "validation_success",
  "message": "[email] Input: 'n***@example.com'",
  "source": "app.api_validate",
  "validation_type": "email",
  "validation_result": "True"
}
```

---

## 8. PII Masking Demo

| Dữ liệu gốc | Sau khi mask |
|---|---|
| `user@example.com` | `u***@example.com` |
| `nguyen.van.an@gmail.com` | `n***@gmail.com` |
| `192.168.1.100` | `192.168.*.*` |
| `123456789012` (CCCD) | `123***789012` |
| `0987654321` (SĐT) | `098***4321` |

---

## 9. Demo Tamper Detection

### Bước 1: Ghi log và tạo signature

```bash
# Chạy app và gửi vài request
python app.py &

curl -X POST http://127.0.0.1:5001/api/validate \
     -H "Content-Type: application/json" \
     -d '{"type": "email", "input": "test@example.com"}'
```

### Bước 2: Kiểm tra integrity (hợp lệ)

```bash
curl http://127.0.0.1:5001/api/integrity
# → {"valid": true, "reason": "Log file toàn vẹn..."}
```

### Bước 3: Sửa thủ công secure.log

```bash
# Thêm dòng giả vào cuối log
echo "TAMPERED DATA" >> secure.log
```

### Bước 4: Kiểm tra lại (phát hiện tamper)

```bash
curl http://127.0.0.1:5001/api/integrity
# → {
#     "valid": false,
#     "reason": "⚠️ CẢNH BÁO: Log file đã bị thay đổi! Hash không khớp.",
#     "stored_hash": "abc123...",
#     "current_hash": "xyz789..."
#   }
```

### Bước 5: Kiểm tra file signature

```bash
cat secure.log.sig
# {
#   "algorithm": "SHA-256",
#   "hash": "abc123def...",
#   "log_file": "secure.log",
#   "updated_at": "2024-01-15T10:30:45Z"
# }
```

---

## 10. Log Rotation

Log tự động rotate khi:
- File `secure.log` vượt **5 MB**
- Giữ tối đa **5** file backup
- File backup được nén bằng **gzip** (`secure.log.1.gz`, `secure.log.2.gz`, ...)

---

## 11. Security Concepts Demonstrated

### 🔐 Secure Logging
- Không log password, token, credential
- PII được mask trước khi ghi
- Log Injection được phòng chống (loại bỏ newline, null byte)

### 🧩 JSON Structured Logging
- Dễ parse, dễ phân tích tự động
- Các field chuẩn: timestamp, level, event, message, source

### 🔒 Tamper Detection
- SHA-256 hash của toàn bộ log file
- Cập nhật sau mỗi lần ghi
- Phát hiện ngay khi có thay đổi trái phép

### ♻️ Log Rotation + Compression
- Giới hạn kích thước file log
- Nén file cũ để tiết kiệm disk
- Giữ lịch sử audit trail

### 🛡️ PII Protection
- Phát hiện tự động: email, IP, CCCD, số điện thoại
- Mask trước khi ghi — không bao giờ lưu PII thô vào log
- Tuân thủ nguyên tắc GDPR / PDP

---

## 12. Lưu ý

- `secure.log` và `secure.log.sig` **KHÔNG ĐƯỢC COMMIT** vào repository
- Thêm vào `.gitignore`:
  ```
  secure.log
  secure.log.sig
  secure.log.*.gz
  ```
- Port mặc định: **5001** (để không xung đột với Lab1 dùng port 5000)
