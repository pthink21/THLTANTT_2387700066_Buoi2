import re

# Exact pattern from GitSecure pre-commit hook (line 47)
pattern = r"""(?i)(password|passwd|pwd)\s*[=:]\\s*["\\'][^"\\']{4,}["\\']"""
description = "Hard-coded password detected"

files_to_check = [
    "Bai1_CryptoToolkit/securecrypto/app_gui.py",
    "Bai1_CryptoToolkit/tests/test_aes_utils.py",
]

for filepath in files_to_check:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    matches = re.findall(pattern, content)
    if matches:
        print(f"MATCH in {filepath}: {description}")
        print(f"  Matches found: {matches}")
        for i, line in enumerate(content.split("\n"), 1):
            if re.search(pattern, line):
                print(f"  Line {i}: {line.strip()}")
    else:
        print(f"NO MATCH in {filepath}")

# Also test simpler patterns
simple_patterns = [
    (r'(?i)password\s*[=:]\s*["\'][^"\']{4,}["\']',
     "Simple password pattern"),
    (r'(?i)pwd\s*[=:]\s*["\'][^"\']{4,}["\']',
     "Simple pwd pattern"),
]

for filepath in files_to_check:
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    for pat, desc in simple_patterns:
        matches = re.findall(pat, content)
        if matches:
            print(f"\n{desc} MATCH in {filepath}: {matches}")
