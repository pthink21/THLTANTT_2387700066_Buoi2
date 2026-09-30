#!/usr/bin/env python
"""
Mini CA Demo — Certificate Authority demonstration.

Demonstrates:
    1. Root CA creation
    2. Intermediate CA creation (signed by Root)
    3. End-entity certificate issuance (signed by Intermediate CA)
       for "Nguyen Phuc Thinh"
    4. Certificate chain verification
    5. Certificate revocation (CRL)
    6. Revocation status check

Author: Nguyen Phuc Thinh (MSSV: 2387700066)
"""

import warnings
warnings.filterwarnings("ignore")

import sys
import json
from pathlib import Path

# Ensure parent dirs are importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ca_utils import (
    create_root_ca,
    create_intermediate_ca,
    issue_certificate,
    verify_certificate_chain,
    load_cert,
    CERTS_DIR,
)
from revoke_utils import (
    create_empty_crl,
    revoke_certificate,
    check_revocation_status,
    CRL_FILE,
)


def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_info(msg):
    print(f"  [INFO] {msg}")


def print_success(msg):
    print(f"  [+]  {msg}")


def print_error(msg):
    print(f"  [-]  {msg}")


def demo():
    """Run the full Mini CA demonstration."""
    results = {}

    # ------------------------------------------------------------------
    # Step 1: Create Root CA
    # ------------------------------------------------------------------
    print_header("BƯỚC 1: Tạo Root CA")
    root_key, root_cert = create_root_ca()
    print_success(f"Root CA đã được tạo thành công")
    print_info(f"  Subject: {root_cert.subject.rfc4514_string()}")
    print_info(f"  Issuer:  {root_cert.issuer.rfc4514_string()}")
    print_info(f"  Serial:  {root_cert.serial_number}")
    print_info(f"  Validity: {root_cert.not_valid_before} → {root_cert.not_valid_after}")
    print_info(f"  File:    {CERTS_DIR / 'root_ca_cert.pem'}")
    results["root_ca"] = "SUCCESS"

    # ------------------------------------------------------------------
    # Step 2: Create Intermediate CA
    # ------------------------------------------------------------------
    print_header("BƯỚC 2: Tạo Intermediate CA (ký bởi Root CA)")
    inter_key, inter_cert = create_intermediate_ca(root_key, root_cert)
    print_success(f"Intermediate CA đã được tạo thành công")
    print_info(f"  Subject: {inter_cert.subject.rfc4514_string()}")
    print_info(f"  Issuer:  {inter_cert.issuer.rfc4514_string()}")
    print_info(f"  Serial:  {inter_cert.serial_number}")
    print_info(f"  Validity: {inter_cert.not_valid_before} → {inter_cert.not_valid_after}")
    print_info(f"  File:    {CERTS_DIR / 'intermediate_cert.pem'}")
    results["intermediate_ca"] = "SUCCESS"

    # ------------------------------------------------------------------
    # Step 3: Issue End-Entity Certificate
    # ------------------------------------------------------------------
    print_header("BƯỚC 3: Phát hành Certificate cho Nguyen Phuc Thinh")
    subject_info = {
        "common_name": "Nguyen Phuc Thinh",
        "organization": "THLTANTT Security Labs",
        "country": "VN",
        "email": "2387700066@student.university.edu.vn",
    }
    end_key, end_cert = issue_certificate(inter_key, inter_cert, subject_info)
    print_success(f"Certificate end-entity đã được phát hành thành công")
    print_info(f"  Subject: {end_cert.subject.rfc4514_string()}")
    print_info(f"  Issuer:  {end_cert.issuer.rfc4514_string()}")
    print_info(f"  Serial:  {end_cert.serial_number}")
    print_info(f"  Validity: {end_cert.not_valid_before} → {end_cert.not_valid_after}")
    print_info(f"  File:    {CERTS_DIR / 'nguyen_phuc_thinh_cert.pem'}")
    print_info(f"  Key:     {CERTS_DIR / 'nguyen_phuc_thinh_key.pem'}")
    results["certificate_issued"] = "SUCCESS"

    # ------------------------------------------------------------------
    # Step 4: Verify Certificate Chain
    # ------------------------------------------------------------------
    print_header("BƯỚC 4: Xác thực Certificate Chain")
    # Chain: Intermediate CA → Root CA
    chain = [inter_cert, root_cert]
    if verify_certificate_chain(end_cert, chain):
        print_success("Certificate chain hợp lệ — xác minh thành công!")
        results["chain_valid"] = "VALID"
    else:
        print_error("Certificate chain KHÔNG hợp lệ!")
        results["chain_valid"] = "INVALID"

    # ------------------------------------------------------------------
    # Step 5: Create Empty CRL
    # ------------------------------------------------------------------
    print_header("BƯỚC 5: Tạo CRL (Certificate Revocation List)")
    crl = create_empty_crl(inter_cert, inter_key)
    print_success(f"CRL đã được tạo thành công")
    print_info(f"  Issuer:  {crl.issuer.rfc4514_string()}")
    print_info(f"  Last Update: {crl.last_update}")
    print_info(f"  Next Update: {crl.next_update}")
    print_info(f"  Revoked certs: {len(crl)}")
    print_info(f"  File:    {CRL_FILE}")
    results["crl_created"] = "SUCCESS"

    # ------------------------------------------------------------------
    # Step 6: Check revocation status (before revoke)
    # ------------------------------------------------------------------
    print_header("BƯỚC 6: Kiểm tra trạng thái certificate (TRƯỚC revoke)")
    cert_path = CERTS_DIR / "nguyen_phuc_thinh_cert.pem"
    if check_revocation_status(str(cert_path)):
        print_info("  Certificate đã bị thu hồi")
        results["pre_revoke_status"] = "REVOKED"
    else:
        print_success("Certificate chưa bị thu hồi — hợp lệ")
        results["pre_revoke_status"] = "VALID"

    # ------------------------------------------------------------------
    # Step 7: Revoke Certificate
    # ------------------------------------------------------------------
    print_header("BƯỚC 7: Thu hồi Certificate")
    crl = revoke_certificate(
        str(cert_path),
        str(CERTS_DIR / "intermediate_cert.pem"),
        str(CERTS_DIR / "intermediate_key.pem"),
        reason="key_compromise",
    )
    print_success(f"Certificate đã được thu hồi thành công")
    print_info(f"  Serial bị thu hồi: {end_cert.serial_number}")
    print_info(f"  Lý do: key_compromise")
    print_info(f"  Số chứng chỉ trong CRL: {len(crl)}")
    print_info(f"  File:    {CRL_FILE}")
    results["certificate_revoked"] = "SUCCESS"

    # ------------------------------------------------------------------
    # Step 8: Check revocation status (after revoke)
    # ------------------------------------------------------------------
    print_header("BƯỚC 8: Kiểm tra trạng thái certificate (SAU revoke)")
    if check_revocation_status(str(cert_path)):
        print_success("Certificate đã nằm trong CRL — xác nhận thu hồi")
        results["post_revoke_status"] = "REVOKED"
    else:
        print_error("Certificate KHÔNG nằm trong CRL!")
        results["post_revoke_status"] = "NOT_REVOKED"

    # ------------------------------------------------------------------
    # Step 9: Print final certificate list
    # ------------------------------------------------------------------
    print_header("DANH SÁCH FILE TRONG THƯ MỤC certs/")
    for f in sorted(CERTS_DIR.iterdir()):
        print_info(f"  {f.name} ({f.stat().st_size} bytes)")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print_header("TÓM TẤT KẾT DEMO")
    for step, status in results.items():
        print_info(f"  {step}: {status}")

    print("\n" + "=" * 60)
    print("  DEMO HOÀN TẤT — toàn bộ bước đã thực hiện thành công")
    print("=" * 60)

    return results


def check_ocsp_status(cert_serial):
    """
    Simulate OCSP status check for a certificate serial number.

    In a real deployment this would query an OCSP responder.  For this
    lab we perform a local CRL-based check and report the result.

    Args:
        cert_serial: Certificate serial number.

    Returns:
        ``True`` if the certificate is good (not revoked), ``False`` if revoked.
    """
    if not CRL_FILE.exists():
        return True

    from cryptography import x509
    crl = x509.load_pem_x509_crl(CRL_FILE.read_bytes())
    for revoked in crl:
        if revoked.serial_number == cert_serial:
            return False
    return True


if __name__ == "__main__":
    demo()
