# Lab 2 — GitSecure Pre-commit Hook

## 1. Mục tiêu

Xây dựng hệ thống **GitSecure** — pre-commit hook tự động quét bảo mật code trước khi `git commit`. Hook sẽ **chặn commit** nếu phát hiện vấn đề bảo mật.

### Các chức năng kiểm tra:

| # | Chức năng | Mô tả |
|---|---|---|
| 1 | Sensitive Info Detection | Phát hiện API key, password, token hard-coded |
| 2 | Hard-coded Identity | Phát hiện username, credential cố định trong code |
| 3 | Bandit Security Scan | Quét lỗ hổng bảo mật Python bằng Bandit |
| 4 | File Permission Check | Phát hiện file world-writable (Unix) |
| 5 | License Compliance | Kiểm tra license GPL/AGPL trong dependencies |

---

## 2. Cấu trúc project

```
gitsecure/
├── .githooks/
│   └── pre-commit          # Script pre-commit hook chính
├── requirements.txt         # Dependency: bandit
├── .gitignore               # Bao gồm gitsecure.log
├── bad.py                   # File demo có vấn đề bảo mật (chỉ để test)
└── README.md
```

---

## 3. Cài đặt

### Bước 1: Cài dependencies

```bash
pip install -r requirements.txt
```

### Bước 2: Gắn hook vào Git

Từ thư mục **root của repository**:

```bash
git config core.hooksPath Bai1/Lab2/gitsecure/.githooks
```

Hoặc nếu đang ở trong thư mục `gitsecure/`:

```bash
git config core.hooksPath .githooks
```

### Bước 3: Cấp quyền thực thi (Linux/macOS/Git Bash)

```bash
chmod +x .githooks/pre-commit
```

> ⚠️ **Windows**: Script `.githooks/pre-commit` là Python script (không phải shell script).  
> Trên Windows cần dùng **Git Bash** hoặc cấu hình Git để chạy qua Python.

**Cấu hình cho Windows (Git Bash):**

```bash
# Mở Git Bash trong thư mục gitsecure
chmod +x .githooks/pre-commit
```

---

## 4. Demo: Chặn commit có vấn đề bảo mật

### Bước 1: Tạo file có secret giả

File `bad.py` đã được chuẩn bị sẵn trong thư mục này với các vấn đề:
- Hard-coded API key (giả)
- Hard-coded password (giả)  
- Hard-coded token (giả)
- `subprocess.run(shell=True)` — Bandit sẽ phát hiện

### Bước 2: Stage file và thử commit

```bash
git add bad.py
git commit -m "add bad file"
```

### Bước 3: Hook phát hiện và chặn commit

Output mong đợi:

```
[GitSecure] 🔍 Đang quét bảo mật...
[GitSecure] Kiểm tra 1 file(s): bad.py
[GitSecure] [1/5] Quét thông tin nhạy cảm...
[GitSecure] [2/5] Kiểm tra hard-coded identity...
[GitSecure] [3/5] Chạy Bandit security scan...
[GitSecure] [4/5] Kiểm tra file permissions...
[GitSecure] [5/5] Kiểm tra license compliance...

[GitSecure] 🚨 Phát hiện 4 vấn đề bảo mật!

============================================================
🔴 HIGH (2):
  File: bad.py
  [SENSITIVE_INFO] API Key detected

  File: bad.py
  [SENSITIVE_INFO] Hard-coded password detected

🟡 MEDIUM (1):
  File: bad.py
  [BANDIT] subprocess_without_shell_equals_true: subprocess call...

============================================================
[GitSecure] Chi tiết được ghi vào: gitsecure.log
[GitSecure] ❌ Commit bị chặn! Sửa các vấn đề trên trước khi commit lại.
============================================================
```

### Bước 4: Xem log

```bash
cat gitsecure.log
```

### Bước 5: Sửa vấn đề và commit lại

```bash
# Sửa bad.py: xóa hard-coded secrets
# Sau đó:
git add bad.py
git commit -m "fix: remove hard-coded secrets"
```

Commit lần này sẽ thành công.

---

## 5. Kiểm tra Bandit độc lập

```bash
# Cài bandit
pip install bandit

# Quét toàn bộ thư mục
bandit -r . -ll

# Quét file cụ thể
bandit bad.py

# Xuất JSON report
bandit -r . -f json -o bandit_report.json
```

---

## 6. Lưu ý quan trọng

### gitsecure.log

Log file **KHÔNG ĐƯỢC commit** vào repository:
- Được thêm vào `.gitignore`
- Chứa thông tin về các vấn đề phát hiện
- Chỉ tồn tại ở local

### Trên Windows

Nếu gặp vấn đề với file permission:
```bash
# Trong Git Bash
chmod +x .githooks/pre-commit

# Nếu bị chặn vì world-writable
chmod 644 <tên-file>
```

### Cập nhật `check_permissions()` cho Windows

Trên Windows, hook tự động bỏ qua kiểm tra permission (vì Windows dùng ACL khác với Unix).

---

## 7. Các pattern phát hiện

### Sensitive Information

| Pattern | Mô tả |
|---|---|
| `api[_-]key = "..."` | API Key |
| `password = "..."` | Hard-coded password |
| `token = "..."` | Auth token |
| `AKIA[A-Z0-9]{16}` | AWS Access Key |
| `-----BEGIN PRIVATE KEY-----` | Private key |
| `ghp_[A-Za-z0-9]{36}` | GitHub Personal Access Token |
| `xox[baprs]-...` | Slack token |

### Bandit Rules (MEDIUM/HIGH)

- `B602`: `subprocess` với `shell=True`
- `B301`: `pickle.loads` (unsafe)
- `B108`: Hard-coded `/tmp` paths
- `B324`: Weak MD5/SHA1 hashing

---

## 8. Security Notes

- Không commit secret thật vào repository
- File `bad.py` chỉ chứa dữ liệu **GIẢ** để demo
- Log `gitsecure.log` có thể chứa thông tin nhạy cảm — không share công khai
- Kết hợp với các tool như **GitLeaks**, **detect-secrets** để bảo vệ tốt hơn
