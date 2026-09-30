# Bài 1 — CryptoToolkit

> **Sinh viên:** Nguyễn Phúc Thinh — MSSV: 2387700066  
> **Môn:** THLTANTT — Lập trình Bảo mật Thông tin

---

## Mô tả

CryptoToolkit là một thư viện mã hóa bảo mật cung cấp ba chức năng chính:

1. **Mã hóa đối xứng (AES-256-GCM)** — Mã hóa và giải mã file bằng AES-256-GCM với key derivation PBKDF2-HMAC-SHA256.
2. **Mã hóa bất đối xứng (RSA-PSS)** — Sinh cặp khóa RSA, chữ ký số và xác thực chữ ký.
3. **Băm mật khẩu (Argon2id)** — Băm và xác thực mật khẩu bằng Argon2id (thuật toán quy vương Password Hashing Competition).

Toolkit cung cấp ba giao diện: **CLI**, **Flask API**, và **GUI (Tkinter)**.

---

## Cài đặt

```bash
pip install -r requirements.txt
```

### Dependencies

| Package | Phiên bản | Mục đích |
|---------|-----------|----------|
| cryptography | >=42.0.0 | AES, RSA, X.509 |
| pycryptodome | >=3.20.0 | Thư viện mã hóa phụ trợ |
| argon2-cffi | >=23.1.0 | Băm mật khẩu Argon2id |
| Flask | >=3.0.0 | Web API |
| Pillow | >=10.0.0 | Screenshot / hình ảnh |
| pytest | >=8.0.0 | Unit testing |

---

## Cấu trúc file

```
Bai1_CryptoToolkit/
├── requirements.txt
├── setup.py
├── .gitignore
├── securecrypto/
│   ├── __init__.py       — xuất khẩu API chính
│   ├── aes_utils.py      — AES-256-GCM encrypt/decrypt
│   ├── hash_utils.py     — Argon2id hash/verify
│   ├── rsa_utils.py      — RSA keygen, sign, verify
│   ├── cli.py            — giao diện dòng lệnh
│   ├── api.py            — Flask REST API
│   └── app_gui.py        — giao diện Tkinter
├── tests/
│   ├── test_aes_utils.py  — 5 tests AES
│   ├── test_hash_utils.py — 5 tests Argon2
│   └── test_rsa_utils.py  — 8 tests RSA
├── files/
│   └── data.txt          — file dữ liệu mẫu
├── screenshots/          — ảnh minh chứng
└── gen_bai1_screenshots.py — script sinh ảnh minh chứng
```

---

## API

### AES — `aes_utils.py`

```python
from securecrypto.aes_utils import encrypt_file_aes, decrypt_file_aes

# Mã hóa file
enc_path = encrypt_file_aes("files/data.txt", "myPassword123")
# → "files/data.txt.enc"

# Giải mã file
dec_path = decrypt_file_aes("files/data.txt.enc", "myPassword123")
# → "files/data.txt"
```

**Định dạng file mã hóa:**
```
[salt: 16 bytes] [nonce: 12 bytes] [ciphertext + GCM tag: remaining]
```

### RSA — `rsa_utils.py`

```python
from securecrypto.rsa_utils import generate_rsa_keypair, sign_data_rsa, verify_signature_rsa

# Sinh cặp khóa RSA 2048-bit
private_key, public_key = generate_rsa_keypair(2048)

# Chữ ký số
data = b"Hello, World!"
signature = sign_data_rsa(data, private_key)

# Xác thực chữ ký
is_valid = verify_signature_rsa(data, signature, public_key)  # → True
```

### Argon2 — `hash_utils.py`

```python
from securecrypto.hash_utils import hash_password_secure, verify_password_hash

# Băm mật khẩu
hashed = hash_password_secure("myPassword123")
# → "$argon2id$v=19$m=65536,t=3,p=4$..."

# Xác thực
is_valid = verify_password_hash(hashed, "myPassword123")  # → True
```

---

## CLI

```bash
# Mã hóa file (AES-256-GCM)
python -m securecrypto.cli encrypt files/data.txt myPassword123

# Giải mã file
python -m securecrypto.cli decrypt files/data.txt.enc myPassword123

# Sinh cặp khóa RSA
python -m securecrypto.cli genkey --size 2048

# Chữ ký số
python -m securecrypto.cli sign files/data.txt --keyfile private_key.pem

# Xác thực chữ ký
python -m securecrypto.cli verify files/data.txt --signature data.sig --keyfile public_key.pem

# Băm mật khẩu (Argon2id)
python -m securecrypto.cli hash myPassword123
```

---

## Flask API

```bash
python securecrypto/api.py
# Server chạy tại http://127.0.0.1:5000
```

| Endpoint | Method | Mô tả |
|----------|--------|-------|
| `/` | GET | Health check |
| `/encrypt` | POST | Mã hóa file (multipart: file + password) |
| `/decrypt` | POST | Giải mã file (multipart: file + password) |
| `/hash` | POST | Băm mật khẩu Argon2id |
| `/keys` | GET | Danh sách public key |
| `/genkey` | POST | Sinh cặp khóa RSA |
| `/sign` | POST | Chữ ký số |
| `/verify` | POST | Xác thực chữ ký |

---

## GUI

```bash
python securecrypto/app_gui.py
```

Giao diện gồm 3 tab:
- **AES-256-GCM:** Encrypt/Decrypt file, xem file, so sánh kích thước
- **RSA-PSS:** Sinh khóa, ký file, xác thực chữ ký
- **Argon2id:** Hash/verify mật khẩu

---

## Unit Tests

```bash
pytest -v
```

**Kết quả:** 18/18 tests PASSED

| Test file | Tests | Mô tả |
|-----------|-------|-------|
| `test_aes_utils.py` | 5 | Encrypt/decrypt roundtrip, wrong password fails, file format |
| `test_hash_utils.py` | 5 | Hash format, verify correct/wrong password, salt uniqueness |
| `test_rsa_utils.py` | 8 | Keygen, sign, verify, tamper detection, save/load |

---

## Screenshots

| # | Tên file | Nội dung |
|---|----------|----------|
| 1 | `01_unit_tests.png` | Kết quả chạy pytest (18/18 PASSED) |
| 2 | `02_aes_encrypt.png` | CLI mã hóa AES-256-GCM |
| 3 | `03_aes_decrypt.png` | CLI giải mã AES-256-GCM |
| 4 | `04_rsa_genkey.png` | CLI sinh cặp khóa RSA |
| 5 | `05_rsa_sign.png` | CLI chữ ký số RSA-PSS |
| 6 | `06_rsa_verify.png` | CLI xác thực chữ ký |
| 7 | `07_argon2_hash.png` | CLI băm mật khẩu Argon2id |
| 8 | `08_flask_api.png` | Flask API test (encrypt, decrypt, hash, genkey, sign, verify) |
| 9 | `09_file_listing.png` | Danh sách file sinh ra |
| 10 | `10_gui_app.png` | Giao diện GUI Tkinter |

---

## Bảo mật

- AES-256-GCM cung cấp **tính toàn vẹn xác thực** (authenticated encryption).
- RSA-PSS với SHA-256 là **chữ ký số mạnh**.
- Argon2id với tham số `m=65536, t=3, p=4` tuân thủ tiêu chuẩn OWASP.
- PBKDF2-HMAC-SHA256 với 100,000 vòng cho key derivation.
- Các private key và file mã hóa được liệt kê trong `.gitignore`.
