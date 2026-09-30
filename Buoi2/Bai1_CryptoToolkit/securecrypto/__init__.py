"""
SecureCrypto Toolkit - A cryptography toolkit implementing
AES-256-GCM encryption, RSA signature, and Argon2 password hashing.

Author: Nguyen Phuc Thinh (MSSV: 2387700066)
Course: THLTANTT - Practical Information Security Programming
"""

from securecrypto.aes_utils import encrypt_file_aes, decrypt_file_aes
from securecrypto.rsa_utils import (
    generate_rsa_keypair,
    sign_data_rsa,
    verify_signature_rsa,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
)
from securecrypto.hash_utils import hash_password_secure, verify_password_hash

__all__ = [
    "encrypt_file_aes",
    "decrypt_file_aes",
    "generate_rsa_keypair",
    "sign_data_rsa",
    "verify_signature_rsa",
    "save_private_key",
    "save_public_key",
    "load_private_key",
    "load_public_key",
    "hash_password_secure",
    "verify_password_hash",
]

__version__ = "1.0.0"
