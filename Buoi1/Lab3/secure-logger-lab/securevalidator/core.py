"""
SecureValidator - Thư viện kiểm tra và làm sạch dữ liệu đầu vào
Mục tiêu: Phòng chống các lỗ hổng bảo mật phổ biến:
  - Email Injection
  - SSRF (Server-Side Request Forgery)
  - Path Traversal
  - SQL Injection
  - XSS (Cross-Site Scripting)
"""

import re
import os
import ipaddress
from urllib.parse import urlparse

import bleach


# ─────────────────────────────────────────────────────────────
# 1. validate_email
# ─────────────────────────────────────────────────────────────

# Whitelist: chỉ cho phép ký tự hợp lệ trong email
_EMAIL_REGEX = re.compile(
    r'^[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,253}\.[a-zA-Z]{2,10}$'
)

def validate_email(email: str) -> dict:
    """
    Kiểm tra định dạng email hợp lệ và phòng chống Email Injection.

    Returns:
        dict: {"valid": bool, "reason": str}
    """
    if not isinstance(email, str):
        return {"valid": False, "reason": "Input phải là chuỗi ký tự."}

    # Giới hạn độ dài để tránh DoS
    if len(email) > 254:
        return {"valid": False, "reason": "Email quá dài (tối đa 254 ký tự)."}

    # Phát hiện ký tự newline / carriage-return → ngăn Header Injection
    if any(c in email for c in ['\n', '\r', '\x00']):
        return {"valid": False, "reason": "Email chứa ký tự nguy hiểm (newline/null)."}

    # Loại bỏ khoảng trắng hai đầu
    email = email.strip()

    if not _EMAIL_REGEX.match(email):
        return {"valid": False, "reason": "Định dạng email không hợp lệ."}

    return {"valid": True, "reason": "Email hợp lệ."}


# ─────────────────────────────────────────────────────────────
# 2. validate_url
# ─────────────────────────────────────────────────────────────

# SSRF: các dải IP nội bộ / private bị chặn
_PRIVATE_IP_BLOCKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 private
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
]

# Whitelist: chỉ cho phép https và http
_ALLOWED_SCHEMES = {"http", "https"}

# Blacklist hostname nguy hiểm phổ biến (tăng cường)
_BLOCKED_HOSTNAMES = {
    "localhost", "metadata.google.internal",
    "169.254.169.254",  # AWS metadata
    "100.100.100.200",  # Alibaba metadata
}


def _is_private_ip(host: str) -> bool:
    """Kiểm tra host có phải là IP nội bộ không."""
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in block for block in _PRIVATE_IP_BLOCKS)
    except ValueError:
        # host không phải IP → kiểm tra hostname
        return False


def validate_url(url: str) -> dict:
    """
    Kiểm tra tính hợp lệ của URL và phòng chống SSRF.

    Returns:
        dict: {"valid": bool, "reason": str}
    """
    if not isinstance(url, str):
        return {"valid": False, "reason": "Input phải là chuỗi ký tự."}

    url = url.strip()

    if len(url) > 2048:
        return {"valid": False, "reason": "URL quá dài."}

    try:
        parsed = urlparse(url)
    except Exception:
        return {"valid": False, "reason": "URL không thể phân tích được."}

    # Kiểm tra scheme (whitelist)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return {
            "valid": False,
            "reason": f"Scheme '{parsed.scheme}' không được phép. Chỉ chấp nhận http/https."
        }

    # Phải có hostname
    hostname = parsed.hostname or ""
    if not hostname:
        return {"valid": False, "reason": "URL thiếu hostname."}

    # Kiểm tra blocked hostname
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return {"valid": False, "reason": f"Hostname '{hostname}' bị chặn (SSRF prevention)."}

    # Kiểm tra IP nội bộ
    if _is_private_ip(hostname):
        return {"valid": False, "reason": "URL trỏ đến địa chỉ IP nội bộ (SSRF prevention)."}

    # Kiểm tra hostname hợp lệ cơ bản
    hostname_regex = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    )
    # Cho phép hostname dạng IP hợp lệ (đã check private ở trên)
    try:
        ipaddress.ip_address(hostname)
        # là IP hợp lệ, đã qua private check
    except ValueError:
        if not hostname_regex.match(hostname):
            return {"valid": False, "reason": "Hostname không hợp lệ."}

    return {"valid": True, "reason": "URL hợp lệ."}


# ─────────────────────────────────────────────────────────────
# 3. validate_filename
# ─────────────────────────────────────────────────────────────

# Whitelist: chỉ cho phép tên file an toàn
_SAFE_FILENAME_REGEX = re.compile(r'^[a-zA-Z0-9_\-\.]+$')

# Danh sách extension nguy hiểm
_DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".php",
    ".py", ".rb", ".pl", ".cgi", ".jar", ".com",
}


def validate_filename(filename: str) -> dict:
    """
    Kiểm tra tên file và phòng chống Path Traversal.

    Returns:
        dict: {"valid": bool, "reason": str}
    """
    if not isinstance(filename, str):
        return {"valid": False, "reason": "Input phải là chuỗi ký tự."}

    if len(filename) > 255:
        return {"valid": False, "reason": "Tên file quá dài."}

    # Kiểm tra null byte
    if '\x00' in filename:
        return {"valid": False, "reason": "Tên file chứa null byte nguy hiểm."}

    # Chuẩn hóa đường dẫn để phát hiện path traversal
    # Phát hiện ../ và ..\\ (cả forward slash lẫn backslash)
    normalized = filename.replace('\\', '/').replace('//', '/')
    parts = normalized.split('/')
    for part in parts:
        if part in ('..', '.'):
            return {
                "valid": False,
                "reason": "Tên file chứa path traversal (../ hoặc ./). Không được phép."
            }

    # Lấy basename để tránh đường dẫn tuyệt đối
    basename = os.path.basename(filename.replace('\\', '/'))
    if not basename:
        return {"valid": False, "reason": "Tên file rỗng sau khi lấy basename."}

    # Kiểm tra tên file tuyệt đối (bắt đầu bằng / hoặc drive letter)
    if filename.startswith('/') or (len(filename) > 1 and filename[1] == ':'):
        return {"valid": False, "reason": "Không cho phép đường dẫn tuyệt đối."}

    # Whitelist ký tự
    if not _SAFE_FILENAME_REGEX.match(basename):
        return {
            "valid": False,
            "reason": "Tên file chứa ký tự không hợp lệ. Chỉ cho phép: a-z, A-Z, 0-9, _, -, ."
        }

    # Kiểm tra extension nguy hiểm
    _, ext = os.path.splitext(basename.lower())
    if ext in _DANGEROUS_EXTENSIONS:
        return {"valid": False, "reason": f"Extension '{ext}' không được phép vì lý do bảo mật."}

    return {"valid": True, "reason": "Tên file hợp lệ."}


# ─────────────────────────────────────────────────────────────
# 4. sanitize_sql_input
# ─────────────────────────────────────────────────────────────

def sanitize_sql_input(input_str: str) -> dict:
    """
    Làm sạch input để phòng chống SQL Injection.

    QUAN TRỌNG: Hàm này chỉ là lớp bảo vệ bổ sung.
    Cách tốt nhất để phòng SQL Injection là dùng Parameterized Queries /
    Prepared Statements. Không nên phụ thuộc hoàn toàn vào sanitization.

    Returns:
        dict: {"sanitized": str, "is_suspicious": bool, "warnings": list}
    """
    if not isinstance(input_str, str):
        input_str = str(input_str)

    warnings = []
    is_suspicious = False

    # Phát hiện SQL injection keywords phổ biến
    sql_patterns = [
        r"(\bOR\b\s+[\w'\"]+\s*=\s*[\w'\"]+)",        # OR 1=1
        r"(\bAND\b\s+[\w'\"]+\s*=\s*[\w'\"]+)",       # AND 1=1
        r"(--|#|/\*)",                                  # SQL comments
        r"(\bDROP\b|\bTRUNCATE\b|\bDELETE\b|\bINSERT\b|\bUPDATE\b|\bSELECT\b|\bUNION\b)",
        r"(\bEXEC\b|\bEXECUTE\b|\bSP_\b|\bXP_\b)",
        r"(;)",                                          # Multiple statements
        r"(')",                                          # Single quote
    ]

    for pattern in sql_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            is_suspicious = True
            warnings.append(f"Phát hiện SQL injection pattern: {pattern}")

    # Escape single quotes (biện pháp tối thiểu)
    # Lưu ý: Đây KHÔNG phải là đủ; hãy dùng parameterized queries
    sanitized = input_str.replace("'", "''")
    # Loại bỏ comment SQL
    sanitized = re.sub(r'--.*$', '', sanitized, flags=re.MULTILINE)
    sanitized = re.sub(r'/\*.*?\*/', '', sanitized, flags=re.DOTALL)
    # Loại bỏ null byte
    sanitized = sanitized.replace('\x00', '')

    return {
        "sanitized": sanitized,
        "is_suspicious": is_suspicious,
        "warnings": warnings,
    }


# ─────────────────────────────────────────────────────────────
# 5. sanitize_html_input
# ─────────────────────────────────────────────────────────────

# Whitelist tags và attributes được phép
_ALLOWED_TAGS = [
    "a", "b", "blockquote", "br", "code", "em",
    "i", "li", "ol", "p", "pre", "strong", "ul",
]
_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title"],
}


def sanitize_html_input(html_str: str) -> dict:
    """
    Làm sạch HTML để phòng chống XSS.
    Sử dụng thư viện bleach với whitelist tags.

    Returns:
        dict: {"sanitized": str, "was_modified": bool}
    """
    if not isinstance(html_str, str):
        html_str = str(html_str)

    # Dùng bleach.clean với whitelist (safe-by-default)
    sanitized = bleach.clean(
        html_str,
        tags=_ALLOWED_TAGS,
        attributes=_ALLOWED_ATTRIBUTES,
        strip=True,          # Xóa tags không được phép (không escape)
        strip_comments=True, # Xóa HTML comments
    )

    was_modified = sanitized != html_str

    return {
        "sanitized": sanitized,
        "was_modified": was_modified,
    }
