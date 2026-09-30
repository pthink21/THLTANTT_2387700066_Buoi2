"""
Unit tests for AES-256-GCM encrypt/decrypt.

Run:  pytest -v
"""

import os
import secrets
import tempfile
from pathlib import Path

import pytest

from securecrypto.aes_utils import encrypt_file_aes, decrypt_file_aes


@pytest.fixture
def sample_file(tmp_path):
    """Create a temporary plaintext file for testing."""
    data = b"Hello, AES-256-GCM! This is a test message for encryption.\n" * 100
    f = tmp_path / "test_data.txt"
    f.write_bytes(data)
    return f, data


@pytest.fixture
def encrypted_file(sample_file):
    """Encrypt the sample file and return (enc_path, password, original_data)."""
    f, data = sample_file
    password = secrets.token_urlsafe(16)
    enc_path = encrypt_file_aes(str(f), password)
    return enc_path, password, data


class TestAESEncryptDecrypt:
    """Tests for AES encrypt_file_aes and decrypt_file_aes."""

    def test_encrypt_creates_file(self, encrypted_file):
        """Encryption must produce a .enc file that exists on disk."""
        enc_path, _, _ = encrypted_file
        assert Path(enc_path).exists()

    def test_encrypt_increases_size(self, sample_file, encrypted_file):
        """Encrypted file must be larger than the original (metadata overhead)."""
        f, _ = sample_file
        enc_path, _, _ = encrypted_file
        assert Path(enc_path).stat().st_size > f.stat().st_size

    def test_decrypt_roundtrip(self, encrypted_file):
        """Decrypt( encrypt( data ) ) == data."""
        enc_path, password, original = encrypted_file
        dec_path = decrypt_file_aes(enc_path, password)
        decrypted = Path(dec_path).read_bytes()
        assert decrypted == original

    def test_decrypt_wrong_password_fails(self, encrypted_file):
        """Decryption with wrong password must raise an exception."""
        enc_path, _, _ = encrypted_file
        with pytest.raises(Exception):
            decrypt_file_aes(enc_path, "wrong_pin_789")

    def test_encrypt_output_format(self, sample_file, encrypted_file):
        """Encrypted blob must contain salt (16) + nonce (12) + ciphertext."""
        enc_path, _, _ = encrypted_file
        blob = Path(enc_path).read_bytes()
        # salt=16, nonce=12 → at least 28 bytes overhead
        assert len(blob) >= 28
