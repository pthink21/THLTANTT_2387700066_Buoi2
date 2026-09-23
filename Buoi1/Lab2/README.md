# Lab 2 — GitSecure Pre-commit Security Hook

## Mục tiêu

Thiết kế và triển khai hệ thống **GitSecure** — pre-commit hook tự động kiểm tra bảo mật mã nguồn trước khi `git commit`, ngăn chặn các rủi ro bảo mật được đưa vào repository.

## Cấu trúc

```
Lab2/
└── gitsecure/
    ├── .githooks/
    │   └── pre-commit    # Hook script chính
    ├── requirements.txt
    ├── .gitignore         # Bao gồm gitsecure.log
    ├── bad.py             # File demo có vấn đề (chỉ để test)
    └── README.md
```

## Quick Start

```bash
# 1. Cài dependency
pip install -r Bai1/Lab2/gitsecure/requirements.txt

# 2. Gắn hook vào git (từ root repository)
git config core.hooksPath Bai1/Lab2/gitsecure/.githooks

# 3. Cấp quyền (Git Bash / Linux)
chmod +x Bai1/Lab2/gitsecure/.githooks/pre-commit
```

Chi tiết xem: [gitsecure/README.md](gitsecure/README.md)
