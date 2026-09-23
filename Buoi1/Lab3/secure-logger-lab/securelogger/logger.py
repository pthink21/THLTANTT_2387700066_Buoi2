"""
SecureLogger — Hệ thống ghi nhật ký bảo mật
Các tính năng:
  1. Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
  2. PII masking: email, CCCD/ID, IP address
  3. Log rotation với compression (gzip)
  4. Tamper detection: SHA-256 hash signature
  5. JSON structured logging
  6. Phòng chống Log Injection

Sử dụng thư viện chuẩn Python — không tự chế cryptography.
"""

import os
import re
import json
import gzip
import hashlib
import logging
import datetime
import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────
# PII MASKING
# ─────────────────────────────────────────────────────────────

# Email regex: phát hiện địa chỉ email
_EMAIL_RE = re.compile(
    r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
)

# CCCD/CMND Việt Nam: 9 hoặc 12 chữ số (đứng tách biệt)
_CCCD_RE = re.compile(
    r'\b(\d{9}|\d{12})\b'
)

# IPv4 address
_IPV4_RE = re.compile(
    r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b'
)

# Số điện thoại Việt Nam
_PHONE_VN_RE = re.compile(
    r'\b(0|\+84)(3[2-9]|5[6-9]|7[0-9]|8[1-9]|9[0-9])\d{7}\b'
)


def _mask_email(email: str) -> str:
    """Mask email: user@example.com → u***@example.com"""
    parts = email.split("@", 1)
    if len(parts) != 2:
        return "***@***.***"
    local = parts[0]
    domain = parts[1]
    if len(local) <= 1:
        masked_local = "*"
    else:
        masked_local = local[0] + "***"
    return f"{masked_local}@{domain}"


def _mask_ip(ip: str) -> str:
    """Mask IP: 192.168.1.100 → 192.168.*.*"""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.*.*"
    return "*.*.*.*"


def _mask_cccd(cccd: str) -> str:
    """Mask CCCD: 123456789012 → 123***789012"""
    if len(cccd) >= 4:
        return cccd[:3] + "***" + cccd[-3:]
    return "***"


def _mask_phone(phone: str) -> str:
    """Mask phone: 0987654321 → 098***4321"""
    if len(phone) >= 6:
        return phone[:3] + "***" + phone[-4:]
    return "***"


def mask_pii(text: str) -> str:
    """
    Phát hiện và mask tất cả PII trong chuỗi text.
    Thứ tự: email → IP → CCCD → phone
    """
    if not isinstance(text, str):
        text = str(text)

    # Mask email
    text = _EMAIL_RE.sub(lambda m: _mask_email(m.group(0)), text)

    # Mask IP (trước CCCD vì IP có dạng số)
    text = _IPV4_RE.sub(lambda m: _mask_ip(m.group(0)), text)

    # Mask CCCD/CMND
    text = _CCCD_RE.sub(lambda m: _mask_cccd(m.group(0)), text)

    # Mask số điện thoại
    text = _PHONE_VN_RE.sub(lambda m: _mask_phone(m.group(0)), text)

    return text


# ─────────────────────────────────────────────────────────────
# LOG INJECTION PREVENTION
# ─────────────────────────────────────────────────────────────

def sanitize_log_message(message: str) -> str:
    """
    Phòng chống Log Injection:
    - Loại bỏ ký tự newline, carriage return, null byte
    - Giới hạn độ dài message
    """
    if not isinstance(message, str):
        message = str(message)

    # Loại bỏ ký tự điều khiển nguy hiểm
    message = message.replace('\n', ' ').replace('\r', ' ').replace('\x00', '')
    # Loại bỏ escape sequences nguy hiểm
    message = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', message)  # ANSI codes

    # Giới hạn độ dài
    max_length = 2000
    if len(message) > max_length:
        message = message[:max_length] + "...[truncated]"

    return message


# ─────────────────────────────────────────────────────────────
# TAMPER DETECTION
# ─────────────────────────────────────────────────────────────

class TamperDetector:
    """
    Tạo và kiểm tra chữ ký SHA-256 cho log file.
    
    File log: secure.log
    File chữ ký: secure.log.sig
    
    Hash được tính trên toàn bộ nội dung log file.
    Dùng thư viện hashlib chuẩn (không tự chế cryptography).
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.sig_path = log_path + ".sig"
        self._lock = threading.Lock()

    def compute_hash(self) -> Optional[str]:
        """Tính SHA-256 hash của file log hiện tại."""
        if not os.path.exists(self.log_path):
            return None
        with open(self.log_path, "rb") as f:
            content = f.read()
        return hashlib.sha256(content).hexdigest()

    def update_signature(self) -> str:
        """Cập nhật file .sig với hash mới sau khi ghi log."""
        with self._lock:
            current_hash = self.compute_hash()
            if current_hash is None:
                return ""
            sig_data = {
                "algorithm": "SHA-256",
                "hash": current_hash,
                "log_file": os.path.basename(self.log_path),
                "updated_at": datetime.datetime.utcnow().isoformat() + "Z",
            }
            with open(self.sig_path, "w", encoding="utf-8") as f:
                json.dump(sig_data, f, indent=2)
            return current_hash

    def verify_integrity(self) -> dict:
        """
        Kiểm tra tính toàn vẹn của log file.
        
        Returns:
            dict: {
                "valid": bool,
                "stored_hash": str,
                "current_hash": str,
                "reason": str
            }
        """
        if not os.path.exists(self.sig_path):
            return {
                "valid": False,
                "stored_hash": None,
                "current_hash": self.compute_hash(),
                "reason": "File chữ ký (.sig) không tồn tại.",
            }

        try:
            with open(self.sig_path, "r", encoding="utf-8") as f:
                sig_data = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            return {
                "valid": False,
                "stored_hash": None,
                "current_hash": self.compute_hash(),
                "reason": f"Không đọc được file chữ ký: {e}",
            }

        stored_hash = sig_data.get("hash", "")
        current_hash = self.compute_hash()

        if current_hash is None:
            return {
                "valid": False,
                "stored_hash": stored_hash,
                "current_hash": None,
                "reason": "Log file không tồn tại.",
            }

        if stored_hash == current_hash:
            return {
                "valid": True,
                "stored_hash": stored_hash,
                "current_hash": current_hash,
                "reason": "Log file toàn vẹn — không bị thay đổi.",
            }
        else:
            return {
                "valid": False,
                "stored_hash": stored_hash,
                "current_hash": current_hash,
                "reason": "⚠️  CẢNH BÁO: Log file đã bị thay đổi! Hash không khớp.",
            }


# ─────────────────────────────────────────────────────────────
# JSON LOG HANDLER
# ─────────────────────────────────────────────────────────────

class JsonRotatingHandler(RotatingFileHandler):
    """Custom handler: ghi log dạng JSON, rotation + gzip compression."""

    def rotation_filename(self, default_name: str) -> str:
        """Thêm .gz vào tên file khi rotate."""
        return default_name + ".gz"

    def rotate(self, source: str, dest: str) -> None:
        """Nén file log cũ bằng gzip khi rotate."""
        with open(source, "rb") as f_in:
            with gzip.open(dest, "wb") as f_out:
                f_out.write(f_in.read())
        os.remove(source)


class JsonFormatter(logging.Formatter):
    """Formatter: xuất log record dạng JSON."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.datetime.utcfromtimestamp(record.created).isoformat() + "Z",
            "level": record.levelname,
            "event": getattr(record, "event", "log"),
            "message": record.getMessage(),
            "source": f"{record.module}.{record.funcName}",
        }
        # Thêm extra fields nếu có
        for key in ("user_id", "ip", "action", "validation_type", "validation_result"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)

        return json.dumps(log_entry, ensure_ascii=False)


# ─────────────────────────────────────────────────────────────
# SECURE LOGGER
# ─────────────────────────────────────────────────────────────

class SecureLogger:
    """
    Hệ thống ghi nhật ký bảo mật.
    
    Features:
    - Structured JSON logging
    - PII auto-masking
    - Log Injection prevention
    - Log rotation + gzip compression
    - Tamper detection via SHA-256
    - Thread-safe
    """

    def __init__(self, log_file: str = "secure.log", max_bytes: int = 5 * 1024 * 1024,
                 backup_count: int = 5):
        """
        Args:
            log_file: Tên file log
            max_bytes: Kích thước tối đa trước khi rotate (mặc định 5MB)
            backup_count: Số file backup giữ lại (mặc định 5)
        """
        self.log_file = log_file
        self.tamper_detector = TamperDetector(log_file)
        self._lock = threading.Lock()

        # Tạo logger Python
        self._logger = logging.getLogger(f"secure_logger_{id(self)}")
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False  # Không lan truyền lên root logger

        # Handler: JSON rotating với gzip
        handler = JsonRotatingHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(JsonFormatter())
        handler.setLevel(logging.DEBUG)
        self._logger.addHandler(handler)

    def _log(self, level: int, message: str, event: str = "log", **kwargs) -> None:
        """Internal: xử lý PII masking và log injection trước khi ghi."""
        # 1. Phòng Log Injection
        safe_message = sanitize_log_message(message)
        # 2. Mask PII
        safe_message = mask_pii(safe_message)
        # 3. Mask PII trong kwargs
        safe_kwargs = {}
        for k, v in kwargs.items():
            safe_kwargs[k] = mask_pii(str(v)) if isinstance(v, str) else v

        # Tạo log record với extra fields
        extra = {"event": event, **safe_kwargs}
        self._logger.log(level, safe_message, extra=extra)

        # 4. Cập nhật signature sau mỗi lần ghi
        with self._lock:
            self.tamper_detector.update_signature()

    def debug(self, message: str, **kwargs) -> None:
        self._log(logging.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs) -> None:
        self._log(logging.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs) -> None:
        self._log(logging.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs) -> None:
        self._log(logging.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs) -> None:
        self._log(logging.CRITICAL, message, **kwargs)

    def log_validation(self, validation_type: str, input_value: str,
                       result: dict, source: str = "api") -> None:
        """
        Ghi lại kết quả validation từ SecureValidator.
        PII trong input_value sẽ tự động bị mask.
        
        Args:
            validation_type: Loại validation (email, url, filename, sql, html)
            input_value: Giá trị đầu vào (sẽ được mask PII)
            result: Kết quả validation dict
            source: Nguồn gọi (api, cli, ...)
        """
        # Mask PII trong input trước khi log
        safe_input = mask_pii(sanitize_log_message(input_value))

        # Xác định event và level
        if result.get("valid") is True:
            event = "validation_success"
            log_fn = self.info
        elif result.get("is_suspicious") is True:
            event = "sql_injection_detected"
            log_fn = self.warning
        elif result.get("was_modified") is True:
            event = "html_sanitized"
            log_fn = self.warning
        else:
            event = "validation_failed"
            log_fn = self.warning

        message = f"[{validation_type}] Input: '{safe_input}'"
        log_fn(
            message,
            event=event,
            validation_type=validation_type,
            validation_result=str(result.get("valid", result.get("is_suspicious", "N/A"))),
            source=source,
        )

    def verify_integrity(self) -> dict:
        """Kiểm tra tính toàn vẹn của log file."""
        return self.tamper_detector.verify_integrity()

    def get_log_hash(self) -> Optional[str]:
        """Lấy hash hiện tại của log file."""
        return self.tamper_detector.compute_hash()
