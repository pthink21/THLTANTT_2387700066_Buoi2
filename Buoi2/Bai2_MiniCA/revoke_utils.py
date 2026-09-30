"""
Revocation utilities for Mini CA.

Implements:
    - load_cert(filepath)              — load X.509 certificate from PEM
    - load_key(filepath)               — load private key from PEM
    - create_empty_crl(issuer_cert, issuer_key) — create an empty CRL
    - revoke_certificate(cert_file, issuer_cert_file, issuer_key_file, reason)
    - check_revocation_status(cert_file) — check if a cert is revoked

Author: Nguyen Phuc Thinh (MSSV: 2387700066)
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
CERTS_DIR.mkdir(exist_ok=True)

CRL_FILE = CERTS_DIR / "ca_crl.pem"

# Mapping of reason strings to x509.ReasonFlags
REASON_MAP = {
    "key_compromise": x509.ReasonFlags.key_compromise,
    "ca_compromise": x509.ReasonFlags.ca_compromise,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "certificate_hold": x509.ReasonFlags.certificate_hold,
    "remove_from_crl": x509.ReasonFlags.remove_from_crl,
    "privilege_withdrawn": x509.ReasonFlags.privilege_withdrawn,
    "aa_compromise": x509.ReasonFlags.aa_compromise,
}


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_cert(filepath):
    """
    Load an X.509 certificate from a PEM file.

    Args:
        filepath: Path to the PEM certificate file.

    Returns:
        cryptography Certificate object.
    """
    pem = Path(filepath).read_bytes()
    return x509.load_pem_x509_certificate(pem)


def load_key(filepath):
    """
    Load a private key from a PEM file (no password).

    Args:
        filepath: Path to the PEM private key file.

    Returns:
        cryptography private key object.
    """
    pem = Path(filepath).read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


# ---------------------------------------------------------------------------
# CRL management
# ---------------------------------------------------------------------------

def create_empty_crl(issuer_cert, issuer_key):
    """
    Create an empty Certificate Revocation List (CRL) signed by *issuer_key*.

    The CRL is valid for 7 days and saved to ``certs/ca_crl.pem``.

    Args:
        issuer_cert: The CA certificate (used for issuer name + SKI).
        issuer_key:  The CA private key (used to sign the CRL).

    Returns:
        The generated x509.CertificateRevocationList object.
    """
    now = datetime.datetime.utcnow()

    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
        .add_extension(
            x509.CRLNumber(1),
            critical=False,
        )
    )

    # Add Authority Key Identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    )

    crl = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

    # Save the CRL
    CRL_FILE.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return crl


def revoke_certificate(cert_file, issuer_cert_file, issuer_key_file, reason="key_compromise"):
    """
    Revoke a certificate by adding its serial number to the CRL.

    If the CRL does not yet exist, an empty CRL is created first.

    Args:
        cert_file:        Path to the certificate to revoke.
        issuer_cert_file: Path to the issuing CA certificate.
        issuer_key_file:  Path to the issuing CA private key.
        reason:           Revocation reason string (e.g. ``"key_compromise"``).

    Returns:
        The updated x509.CertificateRevocationList object.
    """
    cert = load_cert(cert_file)
    issuer_key = load_key(issuer_key_file)
    issuer_cert = load_cert(issuer_cert_file)

    reason_flag = REASON_MAP.get(reason, x509.ReasonFlags.key_compromise)

    # Load existing CRL (PEM format) or create a new one
    if CRL_FILE.exists():
        crl = x509.load_pem_x509_crl(CRL_FILE.read_bytes())
    else:
        crl = create_empty_crl(issuer_cert, issuer_key)

    # Build a new CRL with the revoked cert added
    now = datetime.datetime.utcnow()

    revoked_cert = (
        x509.RevokedCertificateBuilder()
        .serial_number(cert.serial_number)
        .revocation_date(now)
        .add_extension(
            x509.CRLReason(reason_flag),
            critical=True,
        )
        .build()
    )

    # Rebuild CRL
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(crl.issuer)
        .last_update(now)
        .next_update(now + datetime.timedelta(days=7))
        .add_extension(
            x509.CRLNumber(crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number + 1),
            critical=False,
        )
    )

    # Copy existing revoked certs
    for rc in crl:
        builder = builder.add_revoked_certificate(rc)

    # Add the new revoked cert
    builder = builder.add_revoked_certificate(revoked_cert)

    # Add Authority Key Identifier
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False,
    )

    crl = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())

    CRL_FILE.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return crl


def check_revocation_status(cert_file):
    """
    Check whether a certificate is listed in the CRL.

    Args:
        cert_file: Path to the certificate to check.

    Returns:
        ``True`` if the certificate is revoked, ``False`` otherwise.
    """
    cert = load_cert(cert_file)

    if not CRL_FILE.exists():
        return False

    crl = x509.load_pem_x509_crl(CRL_FILE.read_bytes())

    for revoked in crl:
        if revoked.serial_number == cert.serial_number:
            return True

    return False
