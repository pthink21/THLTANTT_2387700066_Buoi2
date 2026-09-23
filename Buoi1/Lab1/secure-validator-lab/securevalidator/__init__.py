"""
SecureValidator Package
Thư viện xác thực và làm sạch dữ liệu đầu vào bảo mật.
"""

from .core import (
    validate_email,
    validate_url,
    validate_filename,
    sanitize_sql_input,
    sanitize_html_input,
)

__all__ = [
    "validate_email",
    "validate_url",
    "validate_filename",
    "sanitize_sql_input",
    "sanitize_html_input",
]

__version__ = "1.0.0"
