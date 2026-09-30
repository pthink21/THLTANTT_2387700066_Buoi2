#!/usr/bin/env python
"""
Command-line interface for the SecureCrypto Toolkit.

Usage examples
--------------
Encrypt a file:
    python -m securecrypto.cli encrypt files/data.txt mypassword

Decrypt a file:
    python -m securecrypto.cli decrypt files/data.txt.enc mypassword

Generate an RSA key pair:
    python -m securecrypto.cli genkey --size 2048

Sign a file:
    python -m securecrypto.cli sign secret.key.enc data.txt

Verify a signature:
    python -m securecrypto.cli verify data.txt data.sig pubkey.pem

Hash a password:
    python -m securecrypto.cli hash myPassword123
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

from securecrypto.aes_utils import encrypt_file_aes, decrypt_file_aes
from securecrypto.rsa_utils import (
    generate_rsa_keypair,
    sign_data_rsa,
    verify_signature_rsa,
    save_private_key,
    save_public_key,
    load_private_key,
)
from securecrypto.hash_utils import hash_password_secure, verify_password_hash


def _cmd_encrypt(args):
    enc_path = encrypt_file_aes(args.filepath, args.password)
    print(f"[+] File encrypted: {enc_path}")
    print(f"    Original size : {Path(args.filepath).stat().st_size} bytes")
    print(f"    Encrypted size: {Path(enc_path).stat().st_size} bytes")


def _cmd_decrypt(args):
    dec_path = decrypt_file_aes(args.filepath, args.password)
    print(f"[+] File decrypted: {dec_path}")
    print(f"    Decrypted size: {Path(dec_path).stat().st_size} bytes")


def _cmd_genkey(args):
    priv_key, pub_key = generate_rsa_keypair(args.size)
    priv_file = args.out_private or "private_key.pem"
    pub_file = args.out_public or "public_key.pem"
    save_private_key(priv_key, priv_file)
    save_public_key(pub_key, pub_file)
    print(f"[+] RSA key pair generated ({args.size} bits)")
    print(f"    Private key: {priv_file}")
    print(f"    Public key : {pub_file}")


def _cmd_sign(args):
    private_key = load_private_key(args.keyfile)
    data = Path(args.filepath).read_bytes()
    signature = sign_data_rsa(data, private_key)
    sig_file = args.signature or (Path(args.filepath).stem + ".sig")
    Path(sig_file).write_bytes(signature)
    print(f"[+] Data signed: {sig_file}")
    print(f"    Signature size: {len(signature)} bytes")


def _cmd_verify(args):
    # Try loading as private key first, fall back to public key
    try:
        key = load_private_key(args.keyfile)
        public_key = key.public_key()
    except ValueError:
        from securecrypto.rsa_utils import load_public_key
        public_key = load_public_key(args.keyfile)
    data = Path(args.filepath).read_bytes()
    signature = Path(args.signature).read_bytes()
    if verify_signature_rsa(data, signature, public_key):
        print("[+] Signature VERIFIED — data is authentic and unmodified.")
        return 0
    else:
        print("[-] Signature INVALID — data may have been tampered with.")
        return 1


def _cmd_hash(args):
    hashed = hash_password_secure(args.password)
    print(f"[+] Argon2id hash: {hashed}")
    # Quick round-trip verification
    if verify_password_hash(hashed, args.password):
        print("[+] Password verification: SUCCESS")
    else:
        print("[-] Password verification: FAILED")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="securecrypto",
        description="CryptoToolkit — AES-256-GCM, RSA-PSS, Argon2id",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- encrypt ---
    p_enc = sub.add_parser("encrypt", help="Encrypt a file with AES-256-GCM")
    p_enc.add_argument("filepath")
    p_enc.add_argument("password")
    p_enc.set_defaults(func=_cmd_encrypt)

    # --- decrypt ---
    p_dec = sub.add_parser("decrypt", help="Decrypt an AES-256-GCM encrypted file")
    p_dec.add_argument("filepath")
    p_dec.add_argument("password")
    p_dec.set_defaults(func=_cmd_decrypt)

    # --- genkey ---
    p_gen = sub.add_parser("genkey", help="Generate an RSA key pair")
    p_gen.add_argument("--size", type=int, default=2048, help="Key size in bits (default 2048)")
    p_gen.add_argument("--out-private", default=None)
    p_gen.add_argument("--out-public", default=None)
    p_gen.set_defaults(func=_cmd_genkey)

    # --- sign ---
    p_sig = sub.add_parser("sign", help="Sign a file with RSA-PSS (SHA-256)")
    p_sig.add_argument("filepath", help="File to sign")
    p_sig.add_argument("--keyfile", required=True, help="Private key PEM file")
    p_sig.add_argument("--signature", default=None)
    p_sig.set_defaults(func=_cmd_sign)

    # --- verify ---
    p_ver = sub.add_parser("verify", help="Verify an RSA-PSS signature")
    p_ver.add_argument("filepath", help="Original file")
    p_ver.add_argument("--signature", required=True)
    p_ver.add_argument("--keyfile", required=True, help="Public or private key PEM file")
    p_ver.set_defaults(func=_cmd_verify)

    # --- hash ---
    p_hash = sub.add_parser("hash", help="Hash a password with Argon2id")
    p_hash.add_argument("password")
    p_hash.set_defaults(func=_cmd_hash)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
