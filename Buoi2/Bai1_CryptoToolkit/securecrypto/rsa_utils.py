"""
RSA key-pair generation, signing, and verification utilities.

Uses the ``cryptography`` library (PyCA) with RSA-PSS (SHA-256)
for secure digital signatures.
"""

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# --- Key generation ----------------------------------------------------------

def generate_rsa_keypair(key_size: int = 2048):
    """
    Generate an RSA key pair.

    Args:
        key_size: RSA modulus size in bits (default 2048).

    Returns:
        Tuple ``(private_key, public_key)``.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


# --- Key serialization -------------------------------------------------------

def save_private_key(private_key, filepath: str) -> str:
    """Save an RSA private key to *filepath* in PEM format (unencrypted)."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(filepath).write_bytes(pem)
    return filepath


def save_public_key(public_key, filepath: str) -> str:
    """Save an RSA public key to *filepath* in PEM format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    Path(filepath).write_bytes(pem)
    return filepath


def load_private_key(filepath: str):
    """Load an RSA private key from a PEM file."""
    pem = Path(filepath).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def load_public_key(filepath: str):
    """Load an RSA public key from a PEM file."""
    pem = Path(filepath).read_bytes()
    return serialization.load_pem_public_key(pem)


# --- Signing / verification --------------------------------------------------

def sign_data_rsa(data: bytes, private_key) -> bytes:
    """
    Sign *data* using RSA-PSS with SHA-256.

    Args:
        data:        Message bytes to sign.
        private_key: RSA private key object.

    Returns:
        Signature bytes.
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature_rsa(data: bytes, signature: bytes, public_key) -> bool:
    """
    Verify an RSA-PSS signature.

    Args:
        data:        Original message bytes.
        signature:   Signature bytes.
        public_key:  RSA public key object.

    Returns:
        ``True`` if valid, ``False`` otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False
