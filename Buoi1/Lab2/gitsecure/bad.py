"""
bad.py — File test cố tình chứa vấn đề bảo mật để demo GitSecure

QUAN TRỌNG: File này KHÔNG được commit vào repository thật.
Chỉ dùng để demo khả năng phát hiện của pre-commit hook.

Tất cả thông tin bên dưới đều là DỮ LIỆU GIẢ để demo.
"""

# ❌ Hard-coded API key (GIẢ - chỉ để demo)
api_key = "sk-DEMO_FAKE_KEY_DO_NOT_USE_1234567890abcdef"

# ❌ Hard-coded password (GIẢ - chỉ để demo)
password = "SuperSecret@Demo123"

# ❌ Hard-coded token (GIẢ - chỉ để demo)
auth_token = "demo-token-abcdef1234567890"

# ❌ Database connection string với credentials (GIẢ)
db_url = "postgresql://demouser:demopassword@localhost/demodb"

# ❌ Bandit sẽ phát hiện: dùng subprocess với shell=True (lỗ hổng injection)
import subprocess
def run_command(user_input):
    # KHÔNG LÀM THẾ NÀY trong code thật!
    result = subprocess.run(user_input, shell=True, capture_output=True)
    return result.stdout


def main():
    print("Đây là file demo có vấn đề bảo mật.")
    print("GitSecure pre-commit hook sẽ chặn commit file này!")


if __name__ == "__main__":
    main()
