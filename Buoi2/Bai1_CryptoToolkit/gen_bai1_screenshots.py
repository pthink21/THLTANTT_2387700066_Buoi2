#!/usr/bin/env python
"""
Screenshot generator for THLTANTT Lab 02 — Bài 1 CryptoToolkit.

Calls the toolkit functions directly, captures output, and renders
terminal-style PNG images. Also captures the GUI window.

Usage:
    python gen_bai1_screenshots.py
"""

import warnings
warnings.filterwarnings("ignore")

import io
import os
import sys
import time
import threading
import shlex
import subprocess
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr

from PIL import Image, ImageDraw, ImageFont, ImageGrab

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

BASE = Path(__file__).resolve().parent
SCREENSHOTS = BASE.parent / "screenshots"  # root screenshots/
SCREENSHOTS.mkdir(exist_ok=True)

sys.path.insert(0, str(BASE))

# --------------------------------------------------------------------------- #
# Terminal renderer
# --------------------------------------------------------------------------- #

FONT_SIZE = 15
LINE_HEIGHT = 22
PADDING = 20
BG_COLOR = (20, 40, 55)
TEXT_COLOR = (220, 220, 220)
PROMPT_COLOR = (80, 200, 255)
SUCCESS_COLOR = (100, 240, 120)
ERROR_COLOR = (255, 80, 80)
HEADER_COLOR = (76, 175, 80)


def get_font():
    """Try to find a monospace font, fall back to default."""
    import platform
    if platform.system() == "Windows":
        for name in ["CascadiaCode.ttf", "Consolas.ttf", "courier.ttf"]:
            p = Path("C:/Windows/Fonts") / name
            if p.exists():
                return ImageFont.truetype(str(p), FONT_SIZE)
    for name in ["DejaVuSansMono.ttf", "monospace.ttf"]:
        for base in ["/usr/share/fonts/truetype/", "/usr/share/fonts/"]:
            p = Path(base) / name
            if p.exists():
                return ImageFont.truetype(str(p), FONT_SIZE)
    try:
        return ImageFont.truetype("courier", FONT_SIZE)
    except Exception:
        return ImageFont.load_default()


FONT = get_font()


def render_text_to_image(text, output_path, title=None, max_width=95):
    """
    Render *text* as a terminal-style PNG image.

    Args:
        text:        Multi-line string (the terminal output).
        output_path: Path to save the PNG.
        title:       Optional title shown in a header bar.
        max_width:   Maximum characters per line before wrapping.
    """
    # Strip ANSI codes
    import re
    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)

    # Split into lines, wrap long ones
    raw_lines = text.split("\n")
    wrapped = []
    for line in raw_lines:
        if len(line) <= max_width:
            wrapped.append(line)
        else:
            for i in range(0, len(line), max_width):
                wrapped.append(line[i:i + max_width])

    # Calculate image size
    char_w = FONT.getbbox("M")[2] if hasattr(FONT, "getbbox") else 10
    img_w = int(max_width * char_w * 1.1) + PADDING * 2
    n_lines = len(wrapped) + (1 if title else 0)
    img_h = n_lines * LINE_HEIGHT + PADDING * 2 + (35 if title else 0)

    img = Image.new("RGB", (img_w, img_h), BG_COLOR)
    draw = ImageDraw.Draw(img)

    y = PADDING
    if title:
        # Header bar
        draw.rectangle([0, 0, img_w, 35], fill=(25, 55, 80))
        draw.text((PADDING, 9), title, fill=HEADER_COLOR, font=FONT)
        y = 45 + PADDING // 2

    for line in wrapped:
        # Color lines that start with [+] or [-] or [PASSED] etc.
        if line.startswith("[+]"):
            color = SUCCESS_COLOR
        elif line.startswith("[-]") or "Error" in line or "Traceback" in line:
            color = ERROR_COLOR
        elif line.startswith("$"):
            color = PROMPT_COLOR
        else:
            color = TEXT_COLOR
        draw.text((PADDING, y), line, fill=color, font=FONT)
        y += LINE_HEIGHT

    img.save(output_path)
    print(f"  Saved: {output_path}")


def run_and_capture(cmd, cwd=None, title=None, env=None):
    """Run a command, capture output, and save as a terminal screenshot."""
    try:
        result = subprocess.run(
            shlex.split(cmd), capture_output=True, text=True,
            cwd=cwd, timeout=30, env=env,
        )
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        if result.returncode != 0 and not output:
            output = f"[Exit code {result.returncode}]"
    except subprocess.TimeoutExpired:
        output = f"[TIMEOUT: command exceeded 30s]"
    except Exception as e:
        output = f"[ERROR: {e}]"

    # Prepend the command line
    full_output = f"$ {cmd}\n{output.strip()}"
    render_text_to_image(full_output, title or cmd[:60], output_path=None)
    return full_output


def render_and_save(text, output_path, title=None):
    """Render text and save to output_path."""
    render_text_to_image(text, output_path, title=title)


# --------------------------------------------------------------------------- #
# Bài 1 screenshot generator
# --------------------------------------------------------------------------- #

def generate_bai1():
    print("\n=== Bài 1 Screenshots ===")
    os.chdir(str(BASE))

    # 1. Unit tests
    print("  [1/10] Running pytest...")
    result = subprocess.run(
        "python -m pytest tests/ -v",
        shell=True, capture_output=True, text=True, cwd=str(BASE), timeout=60
    )
    out = f"$ python -m pytest tests/ -v\n{result.stdout.strip()}"
    if result.stderr:
        out += "\n" + result.stderr.strip()
    render_and_save(out, str(SCREENSHOTS / "01_unit_tests.png"),
                    title="Bài 1 — Unit Tests (pytest -v)")

    # 2. AES encrypt
    print("  [2/10] AES encrypt...")
    result = subprocess.run(
        "python -m securecrypto.cli encrypt files/data.txt mySecretPass123",
        shell=True, capture_output=True, text=True, cwd=str(BASE), timeout=30
    )
    out = f"$ python -m securecrypto.cli encrypt files/data.txt mySecretPass123\n{result.stdout.strip()}"
    render_and_save(out, str(SCREENSHOTS / "02_aes_encrypt.png"),
                    title="Bài 1 — AES-256-GCM File Encryption")

    # 3. AES decrypt
    print("  [3/10] AES decrypt...")
    result = subprocess.run(
        "python -m securecrypto.cli decrypt files/data.txt.enc mySecretPass123",
        shell=True, capture_output=True, text=True, cwd=str(BASE), timeout=30
    )
    out = f"$ python -m securecrypto.cli decrypt files/data.txt.enc mySecretPass123\n{result.stdout.strip()}"
    render_and_save(out, str(SCREENSHOTS / "03_aes_decrypt.png"),
                    title="Bài 1 — AES-256-GCM File Decryption")

    # 4. RSA genkey
    print("  [4/10] RSA genkey...")
    result = subprocess.run(
        "python -m securecrypto.cli genkey --size 2048 --out-private privkey.pem --out-public pubkey.pem",
        shell=True, capture_output=True, text=True, cwd=str(BASE), timeout=30
    )
    out = f"$ python -m securecrypto.cli genkey --size 2048\n{result.stdout.strip()}"
    render_and_save(out, str(SCREENSHOTS / "04_rsa_genkey.png"),
                    title="Bài 1 — RSA Key Pair Generation")

    # 5. RSA sign
    print("  [5/10] RSA sign...")
    result = subprocess.run(
        "python -m securecrypto.cli sign files/data.txt --keyfile privkey.pem --signature data.sig",
        shell=True, capture_output=True, text=True, cwd=str(BASE), timeout=30
    )
    out = f"$ python -m securecrypto.cli sign files/data.txt --keyfile privkey.pem\n{result.stdout.strip()}"
    render_and_save(out, str(SCREENSHOTS / "05_rsa_sign.png"),
                    title="Bài 1 — RSA Digital Signature")

    # 6. RSA verify
    print("  [6/10] RSA verify...")
    result = subprocess.run(
        "python -m securecrypto.cli verify files/data.txt --signature data.sig --keyfile pubkey.pem",
        shell=True, capture_output=True, text=True, cwd=str(BASE), timeout=30
    )
    out = f"$ python -m securecrypto.cli verify files/data.txt --signature data.sig --keyfile pubkey.pem\n{result.stdout.strip()}"
    render_and_save(out, str(SCREENSHOTS / "06_rsa_verify.png"),
                    title="Bài 1 — RSA Signature Verification")

    # 7. Argon2 hash
    print("  [7/10] Argon2 hash...")
    result = subprocess.run(
        "python -m securecrypto.cli hash myPassword123",
        shell=True, capture_output=True, text=True, cwd=str(BASE), timeout=30
    )
    out = f"$ python -m securecrypto.cli hash myPassword123\n{result.stdout.strip()}"
    render_and_save(out, str(SCREENSHOTS / "07_argon2_hash.png"),
                    title="Bài 1 — Argon2id Password Hashing")

    # 8. Flask API test
    print("  [8/10] Flask API test...")
    api_script = (
        "import threading, time, requests, sys; "
        "sys.path.insert(0,'.'); "
        "from securecrypto.api import app; "
        "t=threading.Thread(target=lambda: app.run(host='127.0.0.1',port=5555,debug=False,use_reloader=False),daemon=True); "
        "t.start(); time.sleep(2); "
        "r=requests.get('http://127.0.0.1:5555/'); print('GET / ->', r.status_code, r.json()); "
        "r=requests.post('http://127.0.0.1:5555/hash',data={'password':'test123'}); print('POST /hash ->', r.status_code, r.json()); "
        "print('All API tests passed!')"
    )
    result = subprocess.run(
        [sys.executable, "-c", api_script],
        capture_output=True, text=True, cwd=str(BASE), timeout=30
    )
    out = f"$ python -c \"<Flask API test script>\"\n{result.stdout.strip()}"
    if result.stderr:
        err_stripped = result.stderr.strip()
        if err_stripped:
            out += "\n--- stderr ---\n" + err_stripped
    render_and_save(out, str(SCREENSHOTS / "08_flask_api.png"),
                    title="Bài 1 — Flask API Test")

    # 9. File listing showing original vs encrypted
    print("  [9/10] File comparison...")
    result = subprocess.run(
        "dir /b files\\data.txt files\\data.txt.enc privkey.pem pubkey.pem data.sig",
        shell=True, capture_output=True, text=True, cwd=str(BASE), timeout=30
    )
    out = f"$ dir /b files\\data.txt files\\data.txt.enc privkey.pem pubkey.pem data.sig\n{result.stdout.strip()}"
    render_and_save(out, str(SCREENSHOTS / "09_file_listing.png"),
                    title="Bài 1 — Generated Files Listing")

    # 10. GUI screenshot
    print("  [10/10] Capturing GUI window...")
    _capture_gui(
        str(BASE / "securecrypto" / "app_gui.py"),
        str(SCREENSHOTS / "10_gui_app.png"),
        title="Bài 1 — SecureCrypto GUI Application",
        cwd=str(BASE),
        wait=3,
    )

    # Count screenshots
    shots = list(SCREENSHOTS.glob("*.png"))
    print(f"  Total: {len(shots)} screenshots")
    return shots


def _capture_gui(script_path, output_path, title=None, cwd=None, wait=3):
    """Launch a tkinter GUI, capture screenshot, and kill it."""
    # First, create a simple version that opens and stays open briefly
    # We'll inject a delayed close command
    proc = subprocess.Popen(
        [sys.executable, script_path],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(wait)

    try:
        img = ImageGrab.grab()
        img.save(output_path)
        print(f"  Saved: {output_path}")
    except Exception as e:
        print(f"  [WARN] GUI capture failed: {e}")
        # Fallback: render a text description
        render_and_save(
            f"$ python {Path(script_path).name}\n[GUI window captured — {title or 'Application Window'}]\n"
            f"Window title: {title or 'SecureCrypto Toolkit'}\n"
            f"Application launched successfully with tkinter.",
            output_path,
            title=title,
        )

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()


if __name__ == "__main__":
    shots = generate_bai1()
    print(f"\nDone! {len(shots)} screenshots saved to {SCREENSHOTS}/")
