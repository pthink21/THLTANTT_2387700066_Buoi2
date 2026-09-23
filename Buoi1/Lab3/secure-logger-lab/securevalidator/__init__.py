"""
SecureValidator Package — copy từ Lab1
(Tích hợp với SecureLogger để ghi lại tất cả lần validation)
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
