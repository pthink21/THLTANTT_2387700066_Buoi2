"""
Certificate Authority (CA) utilities for Mini CA.

Implements:
    - generate_key()          — generate an RSA key pair
    - save_key() / load_key() — persist/load private keys as PEM
    - save_cert() / load_cert() — persist/load X.509 certificates as PEM
    - create_root_ca()        — create and self-sign a Root CA
    - create_intermediate_ca()— create an Intermediate CA signed by Root CA
    - issue_certificate()     — issue an end-entity certificate
    - verify_certificate_chain()— verify a certificate against a CA chain

Author: Nguyen Phuc Thinh (MSSV: 2387700066)
"""

import datetime
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
CERTS_DIR = BASE_DIR / "certs"
CERTS_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_key():
    """
    Generate an RSA key pair (2048-bit, public exponent 65537).

    Returns:
        cryptography RSA private key object.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key


def save_key(key, filename):
    """
    Save a private key to ``certs/<filename>`` in PEM format (unencrypted).

    Args:
        key:      RSA private key object.
        filename: Output filename (e.g. ``root_ca_key.pem``).

    Returns:
        Full path to the saved key file.
    """
    filepath = CERTS_DIR / filename
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    filepath.write_bytes(pem)
    return str(filepath)


def load_key(filename):
    """
    Load a private key from ``certs/<filename>``.

    Args:
        filename: PEM filename.

    Returns:
        cryptography RSA private key object.
    """
    filepath = CERTS_DIR / filename
    pem = filepath.read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


# ---------------------------------------------------------------------------
# Certificate management
# ---------------------------------------------------------------------------

def save_cert(cert, filename):
    """
    Save an X.509 certificate to ``certs/<filename>`` in PEM format.

    Args:
        cert:     cryptography Certificate object.
        filename: Output filename (e.g. ``root_ca_cert.pem``).

    Returns:
        Full path to the saved certificate file.
    """
    filepath = CERTS_DIR / filename
    pem = cert.public_bytes(serialization.Encoding.PEM)
    filepath.write_bytes(pem)
    return str(filepath)


def load_cert(filepath):
    """
    Load an X.509 certificate from a PEM file path.

    Args:
        filepath: Path to the PEM certificate file.

    Returns:
        cryptography Certificate object.
    """
    pem = Path(filepath).read_bytes()
    return x509.load_pem_x509_certificate(pem)


# ---------------------------------------------------------------------------
# Certificate Authority operations
# ---------------------------------------------------------------------------

def _build_name(cn, o=None, c=None):
    """Build an x509.Name from common attributes."""
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if o:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, o))
    if c:
        attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, c))
    return x509.Name(attrs)


def create_root_ca():
    """
    Create and self-sign a Root Certificate Authority.

    - Subject == Issuer (self-signed)
    - Validity: 10 years
    - BasicConstraints: CA=True, path_length=1
    - KeyUsage: key_cert_sign + crl_sign
    - SubjectKeyIdentifier + AuthorityKeyIdentifier extensions

    Returns:
        Tuple ``(private_key, certificate)``.
    """
    private_key = generate_key()
    subject = issuer = _build_name(
        "Nguyen Phuc Thinh Root CA",
        o="THLTANTT Security Labs",
        c="VN",
    )

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.5.29.32.8"),  # anyPolicy
                    []
                )
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    save_key(private_key, "root_ca_key.pem")
    save_cert(cert, "root_ca_cert.pem")
    return private_key, cert


def create_intermediate_ca(root_key, root_cert):
    """
    Create an Intermediate CA signed by the Root CA.

    - Issuer = Root CA subject
    - Validity: 5 years
    - BasicConstraints: CA=True, path_length=0
    - KeyUsage: key_cert_sign + crl_sign

    Args:
        root_key:  Root CA private key object.
        root_cert: Root CA certificate object.

    Returns:
        Tuple ``(intermediate_key, intermediate_cert)``.
    """
    private_key = generate_key()
    subject = _build_name(
        "Nguyen Phuc Thinh Intermediate CA",
        o="THLTANTT Security Labs",
        c="VN",
    )

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1825))  # 5 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.CRLNumber(1),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )

    save_key(private_key, "intermediate_key.pem")
    save_cert(cert, "intermediate_cert.pem")
    return private_key, cert


def issue_certificate(ca_key, ca_cert, subject_info):
    """
    Issue an end-entity certificate signed by the Intermediate CA.

    Args:
        ca_key:      Intermediate CA private key.
        ca_cert:     Intermediate CA certificate.
        subject_info: dict with keys 'common_name', 'organization',
                      'country' (and optionally 'email').

    Returns:
        Tuple ``(end_entity_key, end_entity_cert)``.
    """
    end_key = generate_key()
    subject = _build_name(
        subject_info["common_name"],
        o=subject_info.get("organization"),
        c=subject_info.get("country"),
    )

    # Build SANs
    san_builder = x509.SubjectAlternativeName([
        x509.DNSName(subject_info["common_name"]),
    ])
    if "email" in subject_info:
        san_builder = x509.SubjectAlternativeName([
            x509.DNSName(subject_info["common_name"]),
            x509.RFC822Name(subject_info["email"]),
        ])

    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(end_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(san_builder, critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(end_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_name = subject_info["common_name"].replace(" ", "_").lower()
    save_key(end_key, f"{key_name}_key.pem")
    save_cert(cert, f"{key_name}_cert.pem")
    return end_key, cert


def verify_certificate_chain(cert_to_verify, chain):
    """
    Verify a certificate against a chain of CA certificates.

    The *chain* should be ordered from the issuing CA to the Root CA
    (i.e. [intermediate_cert, root_cert]).

    Args:
        cert_to_verify: The end-entity certificate to verify.
        chain:          List of CA certificates (intermediate first, root last).

    Returns:
        ``True`` if the chain is valid, ``False`` otherwise.
    """
    # Manual chain verification — walk from leaf through each CA in the chain
    current = cert_to_verify

    for i, ca_cert in enumerate(chain):
        # Verify the current certificate's signature against the CA's public key
        ca_public_key = ca_cert.public_key()

        # Determine the signature algorithm
        sig_algo = current.signature_hash_algorithm
        if sig_algo is None:
            return False

        try:
            ca_public_key.verify(
                current.signature,
                current.tbs_certificate_bytes,
                padding.PKCS1v15(),
                sig_algo,
            )
        except Exception:
            return False

        # Validate time window
        now = datetime.datetime.now(datetime.timezone.utc)
        if now < current.not_valid_before_utc or now > current.not_valid_after_utc:
            return False

        # Check issuer/subject linkage
        if current.issuer != ca_cert.subject:
            return False

        # Check BasicConstraints for CA certs
        try:
            bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints)
            if not bc.value.ca:
                return False
        except x509.ExtensionNotFound:
            return False

        # Move up the chain
        current = ca_cert

    return True
