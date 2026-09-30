"""
Unit tests for RSA key generation, signing, and verification.

Run:  pytest -v
"""

import pytest

from securecrypto.rsa_utils import (
    generate_rsa_keypair,
    sign_data_rsa,
    verify_signature_rsa,
    save_private_key,
    save_public_key,
    load_private_key,
    load_public_key,
)


class TestRSA:
    """Tests for RSA key generation, sign, and verify."""

    @pytest.fixture
    def keypair(self):
        return generate_rsa_keypair(2048)

    @pytest.fixture
    def signature(self, keypair):
        priv, _ = keypair
        data = b"Important data to sign"
        return sign_data_rsa(data, priv), data

    def test_generate_keypair(self, keypair):
        """Key pair generation must return both keys."""
        priv, pub = keypair
        assert priv is not None
        assert pub is not None

    def test_key_size(self, keypair):
        """Default key size must be 2048 bits."""
        priv, _ = keypair
        assert priv.key_size == 2048

    def test_sign_returns_bytes(self, signature):
        """Signature must be bytes."""
        sig, _ = signature
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_verify_valid_signature(self, keypair, signature):
        """Verification must succeed for a valid signature."""
        _, pub = keypair
        sig, data = signature
        assert verify_signature_rsa(data, sig, pub) is True

    def test_verify_tampered_data_fails(self, keypair, signature):
        """Verification must FAIL if data is modified after signing."""
        _, pub = keypair
        sig, _ = signature
        modified = b"Important data to sign!"  # tampered
        assert verify_signature_rsa(modified, sig, pub) is False

    def test_verify_wrong_signature_fails(self, keypair):
        """Verification must fail with a completely wrong signature."""
        _, pub = keypair
        data = b"Original data"
        fake_sig = b"\x00" * 256
        assert verify_signature_rsa(data, fake_sig, pub) is False

    def test_save_load_private_key(self, keypair, tmp_path):
        """Saved private key must be loadable and usable."""
        priv, _ = keypair
        path = tmp_path / "priv.pem"
        save_private_key(priv, str(path))
        loaded = load_private_key(str(path))
        assert loaded is not None

    def test_save_load_public_key(self, keypair, tmp_path):
        """Saved public key must be loadable and usable."""
        _, pub = keypair
        path = tmp_path / "pub.pem"
        save_public_key(pub, str(path))
        loaded = load_public_key(str(path))
        assert loaded is not None
