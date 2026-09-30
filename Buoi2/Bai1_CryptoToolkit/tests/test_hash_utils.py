"""
Unit tests for Argon2id password hashing.

Run:  pytest -v
"""

import pytest

from securecrypto.hash_utils import hash_password_secure, verify_password_hash


class TestArgon2Hash:
    """Tests for hash_password_secure and verify_password_hash."""

    def test_hash_returns_string(self):
        """hash_password_secure must return a non-empty string."""
        result = hash_password_secure("mySecretPass123")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_hash_contains_argon2_prefix(self):
        """Hash must start with $argon2id (or $argon2)."""
        result = hash_password_secure("testpassword")
        assert result.startswith("$argon2")

    def test_verify_correct_password(self):
        """verify_password_hash must return True for correct password."""
        h = hash_password_secure("correctPassword")
        assert verify_password_hash(h, "correctPassword") is True

    def test_verify_wrong_password(self):
        """verify_password_hash must return False for wrong password."""
        h = hash_password_secure("correctPassword")
        assert verify_password_hash(h, "wrongPassword") is False

    def test_hash_has_salt(self):
        """Same password must produce different hashes (random salt)."""
        h1 = hash_password_secure("samePassword")
        h2 = hash_password_secure("samePassword")
        assert h1 != h2
