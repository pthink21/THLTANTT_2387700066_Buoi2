# Lab 1 — SecureValidator

## 1. Mục tiêu

Xây dựng thư viện Python **SecureValidator** để kiểm tra và làm sạch dữ liệu đầu vào, phòng chống các lỗ hổng bảo mật phổ biến:

| Validator | Tấn công phòng chống |
|---|---|
| `validate_email` | Email Injection / Header Injection |
| `validate_url` | SSRF (Server-Side Request Forgery) |
| `validate_filename` | Path Traversal |
| `sanitize_sql_input` | SQL Injection |
| `sanitize_html_input` | XSS (Cross-Site Scripting) |

---

## 2. Cấu trúc project

```
secure-validator-lab/
├── app.py                   # Flask web application demo
├── requirements.txt
├── securevalidator/
│   ├── __init__.py          # Package exports
│   └── core.py              # Các hàm validator chính
├── templates/
│   └── index.html           # Giao diện web demo
└── tests/
    └── test_validators.py   # Unit tests
```

---

## 3. Cài đặt môi trường

### Yêu cầu

- Python 3.10+

### (Khuyến nghị) Tạo virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

---

## 4. Cài dependencies

```bash
pip install -r requirements.txt
```

Các thư viện chính:

| Package | Mục đích |
|---|---|
| `flask` | Web framework cho demo UI |
| `bleach` | Sanitize HTML an toàn (XSS protection) |
| `gunicorn` | Production WSGI server (Render deploy) |

---

## 5. Chạy Unit Test

```bash
# Từ thư mục secure-validator-lab/
python -m unittest discover tests -v
```

Hoặc chạy trực tiếp:

```bash
python tests/test_validators.py
```

### Kết quả mong đợi

```
test_valid_email ... ok
test_invalid_email_no_at ... ok
test_malicious_email_header_injection_newline ... ok
...
Ran 40 tests in 0.05s
OK
```

---

## 6. Chạy Flask App

```bash
python app.py
```

Mở trình duyệt tại: **http://127.0.0.1:5000/**

---

## 7. Cách test từng Validator

### Email Validator

```python
from securevalidator import validate_email

# Hợp lệ
print(validate_email("user@example.com"))
# {'valid': True, 'reason': 'Email hợp lệ.'}

# Không hợp lệ
print(validate_email("not-an-email"))
# {'valid': False, 'reason': 'Định dạng email không hợp lệ.'}
```

### URL Validator

```python
from securevalidator import validate_url

# Hợp lệ
print(validate_url("https://example.com"))

# SSRF - Private IP
print(validate_url("http://192.168.1.1"))
# {'valid': False, 'reason': 'URL trỏ đến địa chỉ IP nội bộ (SSRF prevention).'}
```

### Filename Validator

```python
from securevalidator import validate_filename

# Hợp lệ
print(validate_filename("document.pdf"))

# Path Traversal
print(validate_filename("../../../etc/passwd"))
# {'valid': False, 'reason': 'Tên file chứa path traversal...'}
```

### SQL Sanitizer

```python
from securevalidator import sanitize_sql_input

result = sanitize_sql_input("' OR 1=1 --")
print(result)
# {'sanitized': "'' OR 1=1 ", 'is_suspicious': True, 'warnings': [...]}
```

> ⚠️ **Lưu ý quan trọng**: `sanitize_sql_input` chỉ là lớp bảo vệ bổ sung.  
> **Cách đúng nhất** để phòng SQL Injection là dùng **Parameterized Queries / Prepared Statements**.

### HTML Sanitizer

```python
from securevalidator import sanitize_html_input

result = sanitize_html_input("<script>alert('XSS')</script>")
print(result)
# {'sanitized': "alert('XSS')", 'was_modified': True}
```

---

## 8. Malicious Input Demo

Các input nguy hiểm để test:

### Email Injection (Header Injection)
```
user@example.com\r\nBcc: evil@evil.com
user@example.com\nCc: attacker@evil.com
```

### SSRF URLs
```
http://localhost
http://192.168.1.1
http://10.0.0.1/internal
http://172.16.0.1
http://169.254.169.254/latest/meta-data/
file:///etc/passwd
```

### Path Traversal
```
../../../etc/passwd
..\..\windows\system32
/etc/passwd
C:\Windows\System32
file\x00.txt
```

### SQL Injection Payloads
```sql
' OR 1=1 --
admin'; DROP TABLE users;--
1 UNION SELECT * FROM passwords
1; EXEC xp_cmdshell('dir')
```

### XSS Payloads
```html
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<a href="javascript:alert(1)">click</a>
<div onmouseover="alert(1)">hover</div>
<svg onload=alert(1)>
<iframe src="http://evil.com"></iframe>
```

---

## 9. Kết quả mong đợi

| Input | Kết quả |
|---|---|
| `user@example.com` | ✅ Hợp lệ |
| `user@example.com\r\nBcc:...` | ❌ Bị chặn - Header Injection |
| `https://example.com` | ✅ Hợp lệ |
| `http://192.168.1.1` | ❌ Bị chặn - SSRF |
| `document.pdf` | ✅ Hợp lệ |
| `../../../etc/passwd` | ❌ Bị chặn - Path Traversal |
| `' OR 1=1 --` | ⚠️ Suspicious - SQL Injection detected |
| `<script>alert(1)</script>` | ⚠️ Đã làm sạch - XSS removed |

---

## 10. Security Concepts Demonstrated

### 🔐 Secure by Design
Bảo mật được tích hợp từ đầu trong thiết kế thư viện, không phải thêm vào sau.

### ✅ Input Validation
Mọi input đều được kiểm tra trước khi xử lý — kiểu dữ liệu, độ dài, định dạng.

### 🧹 Sanitization
Loại bỏ / mã hóa ký tự nguy hiểm trước khi sử dụng trong ngữ cảnh cụ thể (HTML, SQL).

### 📋 Whitelist (Allow-list) Approach
- Email: chỉ cho phép ký tự `[a-zA-Z0-9._%+\-]`
- URL: chỉ chấp nhận scheme `http` / `https`
- Filename: chỉ cho phép `[a-zA-Z0-9_\-.]`
- HTML: chỉ cho phép danh sách tags được định nghĩa rõ ràng

### 🛡️ Defense in Depth (Phòng thủ theo chiều sâu)
Kết hợp nhiều lớp kiểm tra: length check → character check → format check → content check.

### 🚫 SSRF Protection
Chặn URL trỏ đến IP nội bộ, localhost, metadata endpoints để ngăn Server-Side Request Forgery.

### 🗂️ Path Traversal Protection
Chuẩn hóa đường dẫn, phát hiện `../` và `..\`, chặn đường dẫn tuyệt đối.

### 💉 SQL Injection Protection
Phát hiện SQL keywords nguy hiểm, escape single quotes, loại bỏ SQL comments.  
**Quan trọng**: Luôn dùng Parameterized Queries là biện pháp chính!

### 🌐 XSS Protection
Dùng thư viện `bleach` với whitelist tags để loại bỏ script, event handlers, và javascript: URLs.
