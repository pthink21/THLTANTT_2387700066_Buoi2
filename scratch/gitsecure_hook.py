#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GitSecure Pre-commit Hook
Tự động kiểm tra bảo mật code trước khi git commit.

Chức năng:
1. Phát hiện thông tin nhạy cảm (API key, password, token)
2. Phát hiện hard-coded credentials
3. Quét bảo mật bằng Bandit
4. Kiểm tra file permission (world-writable)
5. Kiểm tra license compliance cơ bản
6. Ghi findings vào gitsecure.log

Exit code:
  0 = Tất cả OK, cho phép commit
  1 = Phát hiện vấn đề bảo mật, chặn commit
"""

import os
import re
import sys
import json
import stat
import subprocess
import datetime
import hashlib
from pathlib import Path

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────

LOG_FILE = "gitsecure.log"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)  # thư mục cha của .githooks

# ─────────────────────────────────────────────────────────────
# 1. SENSITIVE INFORMATION PATTERNS (regex whitelist approach)
# ─────────────────────────────────────────────────────────────

SENSITIVE_PATTERNS = [
    # API Keys phổ biến
    (r'(?i)(api[_\-\s]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?',
     "API Key detected"),
    # Password hard-coded
    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']',
     "Hard-coded password detected"),
    # Token
    (r'(?i)(token|auth[_\-]?token|access[_\-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_\-\.]{10,}["\']?',
     "Hard-coded token detected"),
    # Secret key
    (r'(?i)(secret[_\-]?key|secret)\s*[=:]\s*["\'][^"\']{4,}["\']',
     "Hard-coded secret detected"),
    # AWS credentials
    (r'(?i)AKIA[0-9A-Z]{16}',
     "Possible AWS Access Key ID"),
    # Private key header
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
     "Private key detected"),
    # Generic credential pattern
    (r'(?i)(credential|credentials)\s*[=:]\s*["\'][^"\']{4,}["\']',
     "Hard-coded credential detected"),
    # Database connection string with password
    (r'(?i)(mysql|postgresql|mongodb|sqlite)://[^:]+:[^@]+@',
     "Database connection string with credentials"),
    # GitHub token
    (r'ghp_[A-Za-z0-9]{36}',
     "GitHub Personal Access Token detected"),
    # Slack token
    (r'xox[baprs]-[A-Za-z0-9\-]+',
     "Slack token detected"),
]

# ─────────────────────────────────────────────────────────────
# 2. PROBLEMATIC LICENSE PATTERNS
# ─────────────────────────────────────────────────────────────

PROBLEMATIC_LICENSES = [
    r'(?i)GPL\s*v?\s*[23]',    # GPL licenses (copyleft - cần kiểm tra)
    r'(?i)AGPL',                # AGPL (strict copyleft)
    r'(?i)SSPL',                # Server Side Public License
]

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────

def log_finding(category: str, filepath: str, detail: str, severity: str = "HIGH"):
    """Ghi finding vào log file."""
    log_entry = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "severity": severity,
        "category": category,
        "file": filepath,
        "detail": detail,
    }
    log_path = os.path.join(PROJECT_ROOT, LOG_FILE)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")


def log_header(staged_files):
    """Ghi header cho log khi bắt đầu check."""
    log_path = os.path.join(PROJECT_ROOT, LOG_FILE)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"GitSecure Pre-commit Scan\n")
        f.write(f"Time: {datetime.datetime.utcnow().isoformat()}Z\n")
        f.write(f"Files checked: {', '.join(staged_files) if staged_files else 'none'}\n")
        f.write(f"{'='*60}\n")


# ─────────────────────────────────────────────────────────────
# GET STAGED FILES
# ─────────────────────────────────────────────────────────────

def get_staged_files():
    """Lấy danh sách file đang được staged để commit."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True, cwd=PROJECT_ROOT
        )
        if result.returncode != 0:
            return []
        files = [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
        return files
    except FileNotFoundError:
        # git not found
        return []


def get_staged_file_content(filepath: str) -> str:
    """Lấy nội dung file từ staged area (git index)."""
    try:
        result = subprocess.run(
            ["git", "show", f":{filepath}"],
            capture_output=True, text=True, cwd=PROJECT_ROOT
        )
        if result.returncode == 0:
            return result.stdout
        return ""
    except Exception:
        # Fallback: đọc trực tiếp từ đĩa
        full_path = os.path.join(PROJECT_ROOT, filepath)
        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception:
            return ""


# ─────────────────────────────────────────────────────────────
# CHECK 1: Sensitive Information Detection
# ─────────────────────────────────────────────────────────────

def check_sensitive_info(staged_files) -> list:
    """
    Quét staged files để tìm thông tin nhạy cảm.
    Trả về list of findings.
    """
    findings = []
    skip_extensions = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                       ".pdf", ".zip", ".tar", ".gz", ".exe", ".bin"}

    for filepath in staged_files:
        # Bỏ qua file binary
        _, ext = os.path.splitext(filepath.lower())
        if ext in skip_extensions:
            continue

        content = get_staged_file_content(filepath)
        if not content:
            continue

        for pattern, description in SENSITIVE_PATTERNS:
            matches = re.findall(pattern, content)
            if matches:
                finding = {
                    "file": filepath,
                    "category": "SENSITIVE_INFO",
                    "description": description,
                    "severity": "HIGH",
                }
                findings.append(finding)
                log_finding("SENSITIVE_INFO", filepath, description, "HIGH")
                break  # Một lần tìm thấy per file per pattern group là đủ

    return findings


# ─────────────────────────────────────────────────────────────
# CHECK 2: Hard-coded Identity/Credential
# ─────────────────────────────────────────────────────────────

HARDCODED_IDENTITY_PATTERNS = [
    (r'(?i)(username|user_name|login)\s*[=:]\s*["\'](?!placeholder|example|test|demo|user)[^"\']{3,}["\']',
     "Hard-coded username/identity"),
    (r'(?i)(admin|root|superuser)\s*[=:]\s*["\'][^"\']+["\']',
     "Hard-coded admin identity"),
    (r'(?i)ssh[_\-]?(key|private)\s*[=:]\s*["\'][^"\']{10,}["\']',
     "Hard-coded SSH key"),
]


def check_hardcoded_identity(staged_files) -> list:
    """Phát hiện hard-coded identity/credential."""
    findings = []
    skip_extensions = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                       ".pdf", ".zip", ".tar", ".gz"}

    for filepath in staged_files:
        _, ext = os.path.splitext(filepath.lower())
        if ext in skip_extensions:
            continue

        content = get_staged_file_content(filepath)
        if not content:
            continue

        for pattern, description in HARDCODED_IDENTITY_PATTERNS:
            if re.search(pattern, content):
                finding = {
                    "file": filepath,
                    "category": "HARDCODED_IDENTITY",
                    "description": description,
                    "severity": "MEDIUM",
                }
                findings.append(finding)
                log_finding("HARDCODED_IDENTITY", filepath, description, "MEDIUM")


    return findings


# ─────────────────────────────────────────────────────────────
# CHECK 3: Bandit Security Scan
# ─────────────────────────────────────────────────────────────

def check_bandit(staged_files) -> list:
    """
    Chạy Bandit để quét lỗ hổng bảo mật trong Python files.
    Chỉ chạy trên các file .py đang staged.
    """
    findings = []
    py_files = [f for f in staged_files if f.endswith(".py")]

    if not py_files:
        return findings

    try:
        full_paths = [os.path.join(PROJECT_ROOT, f) for f in py_files]
        result = subprocess.run(
            ["python", "-m", "bandit", "-ll", "-q", "--format", "json"] + full_paths,
            capture_output=True, text=True, cwd=PROJECT_ROOT
        )

        if result.stdout:
            try:
                bandit_data = json.loads(result.stdout)
                issues = bandit_data.get("results", [])
                for issue in issues:
                    severity = issue.get("issue_severity", "LOW")
                    if severity in ("HIGH", "MEDIUM"):
                        filepath = issue.get("filename", "")
                        # Convert absolute path to relative
                        try:
                            filepath = os.path.relpath(filepath, PROJECT_ROOT)
                        except ValueError:
                            pass
                        detail = f"{issue.get('test_name', '')}: {issue.get('issue_text', '')}"
                        finding = {
                            "file": filepath,
                            "category": "BANDIT",
                            "description": detail,
                            "severity": severity,
                        }
                        findings.append(finding)
                        log_finding("BANDIT", filepath, detail, severity)
            except json.JSONDecodeError:
                pass

    except FileNotFoundError:
        print("[GitSecure] WARNING: Bandit không tìm thấy. Cài bằng: pip install bandit")

    return findings


# ─────────────────────────────────────────────────────────────
# CHECK 4: File Permission (World-Writable)
# ─────────────────────────────────────────────────────────────

def check_permissions(staged_files) -> list:
    """
    Kiểm tra file permission.
    Trên Unix/Linux: cảnh báo nếu file có quyền world-writable (o+w).
    Trên Windows: bỏ qua vì Windows dùng ACL khác.
    """
    findings = []

    if sys.platform == "win32":
        # Windows dùng ACL, không có Unix permission bits
        # Không cần check trên Windows
        return findings

    for filepath in staged_files:
        full_path = os.path.join(PROJECT_ROOT, filepath)
        if not os.path.exists(full_path):
            continue

        try:
            file_stat = os.stat(full_path)
            mode = file_stat.st_mode
            # Kiểm tra world-writable (o+w)
            if mode & stat.S_IWOTH:
                detail = f"File có quyền world-writable (mode: {oct(mode)}). Chạy: chmod 644 {filepath}"
                finding = {
                    "file": filepath,
                    "category": "FILE_PERMISSION",
                    "description": detail,
                    "severity": "MEDIUM",
                }
                findings.append(finding)
                log_finding("FILE_PERMISSION", filepath, detail, "MEDIUM")
        except OSError:
            pass

    return findings


# ─────────────────────────────────────────────────────────────
# CHECK 5: License Compliance
# ─────────────────────────────────────────────────────────────

def check_license_compliance(staged_files) -> list:
    """
    Kiểm tra license compliance cơ bản.
    Cảnh báo nếu requirements.txt chứa thư viện có license có thể không phù hợp.
    Hoặc nếu trong code có license header gây vấn đề.
    """
    findings = []
    req_files = [f for f in staged_files if "requirements" in f.lower() and f.endswith(".txt")]

    for filepath in req_files:
        content = get_staged_file_content(filepath)
        if not content:
            continue

        for pattern in PROBLEMATIC_LICENSES:
            if re.search(pattern, content):
                detail = f"File có thể chứa thư viện với license hạn chế (GPL/AGPL). Kiểm tra trước khi dùng."
                finding = {
                    "file": filepath,
                    "category": "LICENSE_COMPLIANCE",
                    "description": detail,
                    "severity": "LOW",
                }
                findings.append(finding)
                log_finding("LICENSE_COMPLIANCE", filepath, detail, "LOW")
                break

    # Kiểm tra trong source code files
    for filepath in staged_files:
        if not filepath.endswith(".py"):
            continue
        content = get_staged_file_content(filepath)
        for pattern in PROBLEMATIC_LICENSES:
            if re.search(pattern, content):
                detail = "File có thể chứa code với license hạn chế. Kiểm tra trước khi tích hợp."
                finding = {
                    "file": filepath,
                    "category": "LICENSE_COMPLIANCE",
                    "description": detail,
                    "severity": "LOW",
                }
                findings.append(finding)
                log_finding("LICENSE_COMPLIANCE", filepath, detail, "LOW")
                break

    return findings


# ─────────────────────────────────────────────────────────────
# PRINT RESULTS
# ─────────────────────────────────────────────────────────────

def print_findings(all_findings):
    """In kết quả kiểm tra ra terminal."""
    if not all_findings:
        print("\n[GitSecure] ✅ Không phát hiện vấn đề bảo mật. Cho phép commit.")
        return

    print(f"\n[GitSecure] 🚨 Phát hiện {len(all_findings)} vấn đề bảo mật!\n")
    print("=" * 60)

    high = [f for f in all_findings if f.get("severity") == "HIGH"]
    medium = [f for f in all_findings if f.get("severity") == "MEDIUM"]
    low = [f for f in all_findings if f.get("severity") == "LOW"]

    for severity, items, icon in [("HIGH", high, "🔴"), ("MEDIUM", medium, "🟡"), ("LOW", low, "🔵")]:
        if items:
            print(f"\n{icon} {severity} ({len(items)}):")
            for f in items:
                print(f"  File: {f['file']}")
                print(f"  [{f['category']}] {f['description']}")
                print()

    print("=" * 60)
    print(f"[GitSecure] Chi tiết được ghi vào: {LOG_FILE}")
    print("[GitSecure] ❌ Commit bị chặn! Sửa các vấn đề trên trước khi commit lại.")
    print("=" * 60)


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():
    print("\n[GitSecure] 🔍 Đang quét bảo mật...")

    staged_files = get_staged_staged_files_safe()
    if not staged_files:
        print("[GitSecure] Không có file nào để kiểm tra.")
        sys.exit(0)

    print(f"[GitSecure] Kiểm tra {len(staged_files)} file(s): {', '.join(staged_files[:5])}")
    if len(staged_files) > 5:
        print(f"           ...và {len(staged_files) - 5} file(s) khác")

    log_header(staged_files)

    all_findings = []

    # Check 1: Sensitive information
    print("[GitSecure] [1/5] Quét thông tin nhạy cảm...")
    all_findings.extend(check_sensitive_info(staged_files))

    # Check 2: Hard-coded identity
    print("[GitSecure] [2/5] Kiểm tra hard-coded identity...")
    all_findings.extend(check_hardcoded_identity(staged_files))

    # Check 3: Bandit
    print("[GitSecure] [3/5] Chạy Bandit security scan...")
    all_findings.extend(check_bandit(staged_files))

    # Check 4: File permissions
    print("[GitSecure] [4/5] Kiểm tra file permissions...")
    all_findings.extend(check_permissions(staged_files))

    # Check 5: License compliance
    print("[GitSecure] [5/5] Kiểm tra license compliance...")
    all_findings.extend(check_license_compliance(staged_files))

    # Chỉ chặn commit nếu có HIGH hoặc MEDIUM severity
    blocking_findings = [f for f in all_findings if f.get("severity") in ("HIGH", "MEDIUM")]

    print_findings(all_findings)

    if blocking_findings:
        sys.exit(1)  # Chặn commit
    else:
        if all_findings:
            print(f"\n[GitSecure] ⚠️  {len(all_findings)} low-severity finding(s). Commit được phép tiếp tục.")
        sys.exit(0)  # Cho phép commit


def get_staged_staged_files_safe():
    """Wrapper để lấy staged files, fallback nếu git không có sẵn."""
    files = get_staged_files()
    if not files:
        # Fallback: kiểm tra tất cả Python files trong thư mục hiện tại
        # (dùng khi test hook trực tiếp mà không qua git)
        py_files = []
        for root, dirs, filenames in os.walk(PROJECT_ROOT):
            # Bỏ qua .git và __pycache__
            dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'venv', '.venv', 'node_modules'}]
            for fn in filenames:
                if fn.endswith('.py'):
                    full = os.path.join(root, fn)
                    rel = os.path.relpath(full, PROJECT_ROOT)
                    py_files.append(rel)
        return py_files
    return files


if __name__ == "__main__":
    main()
