"""
Unit Tests cho SecureValidator
Bao gồm:
  - Dữ liệu hợp lệ (valid)
  - Dữ liệu không hợp lệ (invalid)
  - Malicious input (dữ liệu độc hại)
"""

import sys
import os
import unittest

# Thêm thư mục cha vào sys.path để import securevalidator
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from securevalidator import (
    validate_email,
    validate_url,
    validate_filename,
    sanitize_sql_input,
    sanitize_html_input,
)


# ─────────────────────────────────────────────────────────────
# TEST: validate_email
# ─────────────────────────────────────────────────────────────

class TestValidateEmail(unittest.TestCase):

    def test_valid_email(self):
        """Email hợp lệ phải trả về valid=True."""
        result = validate_email("user@example.com")
        self.assertTrue(result["valid"], result["reason"])

    def test_valid_email_with_dots(self):
        """Email với dots và subdomain phải hợp lệ."""
        result = validate_email("user.name+tag@sub.example.co.uk")
        self.assertTrue(result["valid"], result["reason"])

    def test_invalid_email_no_at(self):
        """Email thiếu @ phải không hợp lệ."""
        result = validate_email("userexample.com")
        self.assertFalse(result["valid"])

    def test_invalid_email_no_domain(self):
        """Email thiếu domain phải không hợp lệ."""
        result = validate_email("user@")
        self.assertFalse(result["valid"])

    def test_invalid_email_too_long(self):
        """Email quá dài phải bị từ chối."""
        long_email = "a" * 250 + "@example.com"
        result = validate_email(long_email)
        self.assertFalse(result["valid"])

    def test_malicious_email_header_injection_newline(self):
        """Email chứa newline (header injection) phải bị chặn."""
        result = validate_email("user@example.com\r\nBcc: evil@evil.com")
        self.assertFalse(result["valid"])

    def test_malicious_email_carriage_return(self):
        """Email chứa carriage return phải bị chặn."""
        result = validate_email("user@example.com\nCc: attacker@evil.com")
        self.assertFalse(result["valid"])

    def test_malicious_email_null_byte(self):
        """Email chứa null byte phải bị chặn."""
        result = validate_email("user\x00@example.com")
        self.assertFalse(result["valid"])

    def test_non_string_input(self):
        """Input không phải chuỗi phải bị từ chối."""
        result = validate_email(12345)
        self.assertFalse(result["valid"])

    def test_empty_email(self):
        """Email rỗng phải không hợp lệ."""
        result = validate_email("")
        self.assertFalse(result["valid"])


# ─────────────────────────────────────────────────────────────
# TEST: validate_url
# ─────────────────────────────────────────────────────────────

class TestValidateUrl(unittest.TestCase):

    def test_valid_https_url(self):
        """URL https hợp lệ phải được chấp nhận."""
        result = validate_url("https://example.com")
        self.assertTrue(result["valid"], result["reason"])

    def test_valid_http_url(self):
        """URL http hợp lệ phải được chấp nhận."""
        result = validate_url("http://www.google.com/path?q=test")
        self.assertTrue(result["valid"], result["reason"])

    def test_invalid_url_no_scheme(self):
        """URL không có scheme phải không hợp lệ."""
        result = validate_url("example.com")
        self.assertFalse(result["valid"])

    def test_invalid_url_ftp_scheme(self):
        """URL với scheme ftp phải không hợp lệ (không trong whitelist)."""
        result = validate_url("ftp://files.example.com")
        self.assertFalse(result["valid"])

    def test_ssrf_localhost(self):
        """URL trỏ đến localhost phải bị chặn (SSRF)."""
        result = validate_url("http://localhost:8080/admin")
        self.assertFalse(result["valid"])

    def test_ssrf_private_ip_192(self):
        """URL trỏ đến 192.168.x.x phải bị chặn (SSRF)."""
        result = validate_url("http://192.168.1.1")
        self.assertFalse(result["valid"])

    def test_ssrf_private_ip_10(self):
        """URL trỏ đến 10.x.x.x phải bị chặn (SSRF)."""
        result = validate_url("http://10.0.0.1/internal")
        self.assertFalse(result["valid"])

    def test_ssrf_private_ip_172(self):
        """URL trỏ đến 172.16-31.x.x phải bị chặn (SSRF)."""
        result = validate_url("http://172.16.0.1")
        self.assertFalse(result["valid"])

    def test_ssrf_aws_metadata(self):
        """URL trỏ đến AWS metadata phải bị chặn."""
        result = validate_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(result["valid"])

    def test_ssrf_file_scheme(self):
        """URL với scheme file:// phải bị chặn."""
        result = validate_url("file:///etc/passwd")
        self.assertFalse(result["valid"])


# ─────────────────────────────────────────────────────────────
# TEST: validate_filename
# ─────────────────────────────────────────────────────────────

class TestValidateFilename(unittest.TestCase):

    def test_valid_filename_simple(self):
        """Tên file đơn giản phải hợp lệ."""
        result = validate_filename("document.pdf")
        self.assertTrue(result["valid"], result["reason"])

    def test_valid_filename_with_underscore(self):
        """Tên file có underscore phải hợp lệ."""
        result = validate_filename("my_file_2024.txt")
        self.assertTrue(result["valid"], result["reason"])

    def test_valid_filename_with_hyphen(self):
        """Tên file có hyphen phải hợp lệ."""
        result = validate_filename("report-final.docx")
        self.assertTrue(result["valid"], result["reason"])

    def test_invalid_path_traversal_forward_slash(self):
        """Filename chứa ../ phải bị chặn."""
        result = validate_filename("../../../etc/passwd")
        self.assertFalse(result["valid"])

    def test_invalid_path_traversal_double_dot(self):
        """Filename chứa .. phải bị chặn."""
        result = validate_filename("../../secret.txt")
        self.assertFalse(result["valid"])

    def test_invalid_path_traversal_backslash(self):
        """Filename chứa ..\\ phải bị chặn."""
        result = validate_filename("..\\..\\windows\\system32")
        self.assertFalse(result["valid"])

    def test_invalid_path_traversal_mixed(self):
        """Filename với path traversal mix phải bị chặn."""
        result = validate_filename("..%2F..%2Fetc%2Fpasswd")
        self.assertFalse(result["valid"])

    def test_invalid_absolute_path_unix(self):
        """Đường dẫn tuyệt đối Unix phải bị từ chối."""
        result = validate_filename("/etc/passwd")
        self.assertFalse(result["valid"])

    def test_invalid_absolute_path_windows(self):
        """Đường dẫn tuyệt đối Windows phải bị từ chối."""
        result = validate_filename("C:\\Windows\\System32")
        self.assertFalse(result["valid"])

    def test_invalid_null_byte(self):
        """Filename chứa null byte phải bị chặn."""
        result = validate_filename("file\x00.txt")
        self.assertFalse(result["valid"])

    def test_invalid_dangerous_extension_exe(self):
        """File .exe phải bị từ chối."""
        result = validate_filename("malware.exe")
        self.assertFalse(result["valid"])

    def test_invalid_dangerous_extension_sh(self):
        """File .sh phải bị từ chối."""
        result = validate_filename("setup.sh")
        self.assertFalse(result["valid"])

    def test_invalid_special_characters(self):
        """Filename chứa ký tự đặc biệt phải bị từ chối."""
        result = validate_filename("file;rm -rf.txt")
        self.assertFalse(result["valid"])


# ─────────────────────────────────────────────────────────────
# TEST: sanitize_sql_input
# ─────────────────────────────────────────────────────────────

class TestSanitizeSqlInput(unittest.TestCase):

    def test_normal_input(self):
        """Input bình thường không nên bị flag là suspicious."""
        result = sanitize_sql_input("John Doe")
        self.assertFalse(result["is_suspicious"])
        self.assertIn("John Doe", result["sanitized"])

    def test_sql_or_injection(self):
        """OR 1=1 phải được phát hiện là suspicious."""
        result = sanitize_sql_input("' OR 1=1 --")
        self.assertTrue(result["is_suspicious"])

    def test_sql_drop_table(self):
        """DROP TABLE phải được phát hiện."""
        result = sanitize_sql_input("admin'; DROP TABLE users;--")
        self.assertTrue(result["is_suspicious"])

    def test_sql_union_select(self):
        """UNION SELECT phải được phát hiện."""
        result = sanitize_sql_input("1 UNION SELECT * FROM passwords")
        self.assertTrue(result["is_suspicious"])

    def test_sql_comment_stripped(self):
        """SQL comment (--) phải bị loại bỏ."""
        result = sanitize_sql_input("value -- some comment")
        self.assertNotIn("-- some comment", result["sanitized"])

    def test_single_quote_escaped(self):
        """Single quote phải được escape thành ''."""
        result = sanitize_sql_input("O'Brien")
        self.assertIn("''", result["sanitized"])

    def test_null_byte_removed(self):
        """Null byte trong input phải bị loại bỏ."""
        result = sanitize_sql_input("value\x00injection")
        self.assertNotIn("\x00", result["sanitized"])

    def test_normal_number(self):
        """Số bình thường không nên bị flag."""
        result = sanitize_sql_input("42")
        self.assertFalse(result["is_suspicious"])


# ─────────────────────────────────────────────────────────────
# TEST: sanitize_html_input
# ─────────────────────────────────────────────────────────────

class TestSanitizeHtmlInput(unittest.TestCase):

    def test_normal_html(self):
        """HTML bình thường với tags được phép phải không bị thay đổi."""
        result = sanitize_html_input("<b>Hello</b> <p>World</p>")
        self.assertFalse(result["was_modified"])
        self.assertIn("<b>Hello</b>", result["sanitized"])

    def test_xss_script_tag(self):
        """Script tag phải bị loại bỏ - tag bị xóa, không còn có thể thực thi."""
        result = sanitize_html_input("<script>alert('XSS')</script>")
        self.assertTrue(result["was_modified"])
        # bleach xóa thẻ <script> và </script>, ngăn thực thi JavaScript
        self.assertNotIn("<script>", result["sanitized"])
        self.assertNotIn("</script>", result["sanitized"])

    def test_xss_img_onerror(self):
        """img onerror XSS phải bị loại bỏ."""
        result = sanitize_html_input("<img src=x onerror=alert(1)>")
        self.assertTrue(result["was_modified"])
        self.assertNotIn("onerror", result["sanitized"])

    def test_xss_javascript_href(self):
        """javascript: trong href phải bị loại bỏ."""
        result = sanitize_html_input('<a href="javascript:alert(1)">click me</a>')
        self.assertTrue(result["was_modified"])
        self.assertNotIn("javascript:", result["sanitized"])

    def test_xss_event_handler(self):
        """Event handlers như onmouseover phải bị loại bỏ."""
        result = sanitize_html_input('<div onmouseover="alert(1)">hover</div>')
        self.assertTrue(result["was_modified"])
        self.assertNotIn("onmouseover", result["sanitized"])

    def test_xss_iframe(self):
        """iframe tag phải bị loại bỏ."""
        result = sanitize_html_input('<iframe src="http://evil.com"></iframe>')
        self.assertTrue(result["was_modified"])
        self.assertNotIn("<iframe>", result["sanitized"])

    def test_html_comment_stripped(self):
        """HTML comment phải bị loại bỏ."""
        result = sanitize_html_input("<!-- comment -->Hello")
        self.assertTrue(result["was_modified"])
        self.assertNotIn("<!--", result["sanitized"])

    def test_xss_svg_onload(self):
        """SVG onload XSS phải bị chặn."""
        result = sanitize_html_input('<svg onload=alert(1)>')
        self.assertTrue(result["was_modified"])
        self.assertNotIn("onload", result["sanitized"])

    def test_plain_text_unchanged(self):
        """Text thuần không có HTML phải không bị thay đổi."""
        result = sanitize_html_input("Hello world, this is plain text!")
        self.assertFalse(result["was_modified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
