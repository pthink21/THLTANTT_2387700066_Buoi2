"""
AES-256-GCM encryption and decryption utilities.

Uses PBKDF2-HMAC-SHA256 for key derivation from a password,
then AES-256-GCM for authenticated encryption.

Encrypted file format:
    [salt: 16 bytes] [nonce: 12 bytes] [ciphertext: remaining]
"""

import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# --- Constants ---------------------------------------------------------------

SALT_SIZE = 16       # bytes — for PBKDF2
NONCE_SIZE = 12      # bytes — for AES-GCM (96 bits is recommended)
KEY_SIZE = 32        # bytes — 256 bits for AES-256
PBKDF2_ITERATIONS = 100_000


# --- Internal helpers --------------------------------------------------------

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from *password* and *salt* via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


# --- Public API --------------------------------------------------------------

def encrypt_file_aes(filepath: str, password: str) -> str:
    """
    Encrypt a file using AES-256-GCM.

    The key is derived from *password* with PBKDF2-HMAC-SHA256
    (100 000 iterations, random 16-byte salt).

    Args:
        filepath:  Path to the plaintext file.
        password:  User-supplied password.

    Returns:
        Path to the encrypted file (``filepath + '.enc'``).
    """
    plaintext = Path(filepath).read_bytes()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_path = str(Path(filepath) .with_suffix(Path(filepath).suffix + ".enc"))
    blob = salt + nonce + ciphertext
    Path(encrypted_path).write_bytes(blob)

    return encrypted_path


def decrypt_file_aes(encrypted_file: str, password: str) -> str:
    """
    Decrypt a file previously encrypted with :func:`encrypt_file_aes`.

    Args:
        encrypted_file: Path to the ``.enc`` file.
        password:       Password used for encryption.

    Returns:
        Path to the decrypted file (``encrypted_file`` with ``.enc`` stripped).
    """
    blob = Path(encrypted_file).read_bytes()

    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext = blob[SALT_SIZE + NONCE_SIZE:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    # Build decrypted path — strip trailing '.enc' if present
    src = Path(encrypted_file)
    if src.suffix == ".enc":
        decrypted_path = str(src.with_suffix(""))
    else:
        decrypted_path = str(src.with_suffix(src.suffix + ".dec"))

    Path(decrypted_path).write_bytes(plaintext)
    return decrypted_path
