#!/usr/bin/env python
"""
Flask API for the SecureCrypto Toolkit.

Endpoints
---------
GET  /             — health check / info
POST /encrypt      — encrypt uploaded file (AES-256-GCM)
POST /decrypt      — decrypt uploaded file (AES-256-GCM)
POST /hash        — hash a password (Argon2id)
GET  /keys         — list available public key files
POST /genkey       — generate a new RSA key pair
POST /sign         — sign data with RSA-PSS
POST /verify       — verify an RSA-PSS signature

Run:
    python securecrypto/api.py
"""

import os
from io import BytesIO
from pathlib import Path

from flask import Flask, jsonify, request, send_file

from securecrypto.aes_utils import encrypt_file_aes, decrypt_file_aes
from securecrypto.rsa_utils import (
    generate_rsa_keypair,
    save_public_key,
    save_private_key,
    load_public_key,
    sign_data_rsa,
    verify_signature_rsa,
)
from securecrypto.hash_utils import hash_password_secure

# --------------------------------------------------------------------------- ---

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "upload"
KEY_DIR = BASE_DIR / "keys"
UPLOAD_DIR.mkdir(exist_ok=True)
KEY_DIR.mkdir(exist_ok=True)

app = Flask(__name__)


@app.route("/")
def index():
    return jsonify({
        "service": "SecureCrypto API",
        "version": "1.0.0",
        "endpoints": [
            "POST /encrypt",
            "POST /decrypt",
            "POST /hash",
            "GET /keys",
            "POST /genkey",
            "POST /sign",
            "POST /verify",
        ],
    })


# --- AES --------------------------------------------------------------- ---

@app.route("/encrypt", methods=["POST"])
def api_encrypt():
    """Encrypt an uploaded file.

    Form fields:
        file      — multipart file
        password  — encryption password
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    pw = request.form.get("password", "")
    if not pw:
        return jsonify({"error": "Password required"}), 400

    uploaded = request.files["file"]
    src_path = UPLOAD_DIR / uploaded.filename
    uploaded.save(src_path)

    enc_path = encrypt_file_aes(str(src_path), pw)
    return jsonify({
        "message": "File encrypted successfully",
        "encrypted_file": Path(enc_path).name,
        "original_size": src_path.stat().st_size,
        "encrypted_size": Path(enc_path).stat().st_size,
    })


@app.route("/decrypt", methods=["POST"])
def api_decrypt():
    """Decrypt an uploaded .enc file.

    Form fields:
        file      — multipart .enc file
        password  — decryption password
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    pw = request.form.get("password", "")
    if not pw:
        return jsonify({"error": "Password required"}), 400

    uploaded = request.files["file"]
    enc_path = UPLOAD_DIR / uploaded.filename
    uploaded.save(enc_path)

    try:
        dec_path = decrypt_file_aes(str(enc_path), pw)
    except Exception as exc:
        return jsonify({"error": f"Decryption failed: {exc}"}), 400

    return jsonify({
        "message": "File decrypted successfully",
        "decrypted_file": Path(dec_path).name,
        "decrypted_size": Path(dec_path).stat().st_size,
    })


# --- Argon2 -------------------------------------------------------------- ---

@app.route("/hash", methods=["POST"])
def api_hash():
    """Hash a password with Argon2id.

    Form field: password
    """
    pw = request.form.get("password", "")
    if not pw:
        return jsonify({"error": "Password required"}), 400
    h = hash_password_secure(pw)
    return jsonify({"hash": h, "algorithm": "argon2id"})


# --- RSA ----------------------------------------------------------------- ---

@app.route("/keys", methods=["GET"])
def list_keys():
    pubs = sorted(KEY_DIR.glob("*.pub.pem"))
    return jsonify({"public_keys": [p.name for p in pubs]})


@app.route("/genkey", methods=["POST"])
def api_genkey():
    size = request.form.get("size", 2048)
    try:
        size = int(size)
    except ValueError:
        return jsonify({"error": "Invalid key size"}), 400
    priv, pub = generate_rsa_keypair(size)
    label = request.form.get("label", "key")
    priv_path = KEY_DIR / f"{label}.priv.pem"
    pub_path = KEY_DIR / f"{label}.pub.pem"
    save_private_key(priv, str(priv_path))
    save_public_key(pub, str(pub_path))
    return jsonify({
        "message": "RSA key pair generated",
        "private_key": priv_path.name,
        "public_key": pub_path.name,
        "key_size": size,
    })


@app.route("/sign", methods=["POST"])
def api_sign():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    label = request.form.get("label", "key")
    key_path = KEY_DIR / f"{label}.priv.pem"
    if not key_path.exists():
        return jsonify({"error": f"Private key '{label}' not found"}), 404

    from securecrypto.rsa_utils import load_private_key as _lpk
    priv_key = _lpk(str(key_path))

    uploaded = request.files["file"]
    data = uploaded.read()
    sig = sign_data_rsa(data, priv_key)
    sig_path = UPLOAD_DIR / (uploaded.filename + ".sig")
    sig_path.write_bytes(sig)

    return jsonify({
        "message": "Data signed",
        "signature_file": sig_path.name,
        "signature_size": len(sig),
    })


@app.route("/verify", methods=["POST"])
def api_verify():
    if "file" not in request.files or "signature" not in request.files:
        return jsonify({"error": "File and signature required"}), 400
    label = request.form.get("label", "key")
    key_path = KEY_DIR / f"{label}.pub.pem"
    if not key_path.exists():
        return jsonify({"error": f"Public key '{label}' not found"}), 404

    from securecrypto.rsa_utils import load_public_key as _lpub
    pub_key = _lpub(str(key_path))

    data = request.files["file"].read()
    sig = request.files["signature"].read()
    valid = verify_signature_rsa(data, sig, pub_key)
    return jsonify({"valid": valid})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
