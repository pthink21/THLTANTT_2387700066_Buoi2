#!/usr/bin/env python
"""
Mini CA GUI — Tkinter interface for Certificate Authority operations.

Features:
    - Create Root CA / Intermediate CA
    - Issue end-entity certificates
    - Verify certificate chain
    - Revoke certificates (CRL)
    - Check revocation status
    - View all generated certificates

Author: Nguyen Phuc Thinh (MSSV: 2387700066)
"""

import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

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


class MiniCAGUI:
    PAD_X = 8
    PAD_Y = 5

    def __init__(self, root):
        self.root = root
        self.root.title("Mini CA — Certificate Authority")
        self.root.geometry("820x640")
        self.root.resizable(False, False)

        self._setup_ui()
        self.root_key = None
        self.root_cert = None
        self.inter_key = None
        self.inter_cert = None

    def _setup_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # --- CA tab ---
        self.tab_ca = ttk.Frame(notebook)
        notebook.add(self.tab_ca, text="CA Management")
        self._build_ca_tab()

        # --- Certificates tab ---
        self.tab_certs = ttk.Frame(notebook)
        notebook.add(self.tab_certs, text="Certificates")
        self._build_certs_tab()

        # --- Revocation tab ---
        self.tab_revoke = ttk.Frame(notebook)
        notebook.add(self.tab_revoke, text="Revocation (CRL)")
        self._build_revoke_tab()

        # --- Output ---
        self.tab_output = ttk.Frame(notebook)
        notebook.add(self.tab_output, text="Output")
        self._build_output_tab()

    # ---- CA tab ----

    def _build_ca_tab(self):
        f = self.tab_ca

        ttk.Label(f, text="CA Password (not used — keys are unencrypted):",
                  foreground="gray").pack(anchor=tk.W, padx=self.PAD_X, pady=self.PAD_Y)

        btn_frame = ttk.Frame(f)
        btn_frame.pack(fill=tk.X, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Button(btn_frame, text="1. Create Root CA",
                   command=self._create_root_ca).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="2. Create Intermediate CA",
                   command=self._create_intermediate_ca).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="3. Issue Certificate",
                   command=self._issue_certificate).pack(fill=tk.X, pady=2)
        ttk.Button(btn_frame, text="4. Verify Certificate Chain",
                   command=self._verify_chain).pack(fill=tk.X, pady=2)

        ttk.Separator(f, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)

        ttk.Label(f, text="Subject Information").pack(anchor=tk.W, padx=self.PAD_X)
        info_frame = ttk.LabelFrame(f, text="End-Entity Details")
        info_frame.pack(fill=tk.X, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Label(info_frame, text="Common Name:*").grid(
            row=0, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.cn_var = tk.StringVar()
        ttk.Entry(info_frame, textvariable=self.cn_var, width=40).grid(
            row=0, column=1, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Label(info_frame, text="Organization:").grid(
            row=1, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.org_var = tk.StringVar()
        ttk.Entry(info_frame, textvariable=self.org_var, width=40).grid(
            row=1, column=1, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Label(info_frame, text="Country (2-letter):").grid(
            row=2, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.country_var = tk.StringVar(value="VN")
        ttk.Entry(info_frame, textvariable=self.country_var, width=10).grid(
            row=2, column=1, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Label(info_frame, text="Email:").grid(
            row=3, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.email_var = tk.StringVar()
        ttk.Entry(info_frame, textvariable=self.email_var, width=40).grid(
            row=3, column=1, padx=self.PAD_X, pady=self.PAD_Y)

    # ---- Certificates tab ----

    def _build_certs_tab(self):
        f = self.tab_certs

        ttk.Button(f, text="Refresh Certificate List",
                   command=self._refresh_cert_list).pack(
            padx=self.PAD_X, pady=self.PAD_Y)

        self.cert_tree = ttk.Treeview(f, columns=("Subject", "Issuer", "Serial"),
                                       show="tree headings", height=12)
        self.cert_tree.heading("#0", text="File")
        self.cert_tree.heading("Subject", text="Subject")
        self.cert_tree.heading("Issuer", text="Issuer")
        self.cert_tree.heading("Serial", text="Serial")
        self.cert_tree.column("#0", width=200)
        self.cert_tree.column("Subject", width=250)
        self.cert_tree.column("Issuer", width=250)
        self.cert_tree.column("Serial", width=100)
        self.cert_tree.pack(fill=tk.BOTH, expand=True, padx=self.PAD_X, pady=self.PAD_Y)

        # View details button
        ttk.Button(f, text="View Details",
                   command=self._view_cert_details).pack(
            padx=self.PAD_X, pady=self.PAD_Y)

    # ---- Revocation tab ----

    def _build_revoke_tab(self):
        f = self.tab_revoke

        ttk.Label(f, text="Certificate to Revoke:").grid(
            row=0, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.revoke_cert_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.revoke_cert_var, width=50).grid(
            row=0, column=1, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Browse",
                   command=lambda: self.revoke_cert_var.set(
                       filedialog.askopenfilename(
                           filetypes=[("PEM certs", "*.pem")]))).grid(
            row=0, column=2, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Label(f, text="Reason:").grid(
            row=1, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.reason_var = tk.StringVar(value="key_compromise")
        ttk.Combobox(f, textvariable=self.reason_var, width=25,
                     values=["key_compromise", "ca_compromise",
                             "affiliation_changed", "superseded",
                             "cessation_of_operation", "privilege_withdrawn"]).grid(
            row=1, column=1, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Button(f, text="Create CRL", command=self._create_crl).grid(
            row=2, column=0, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Revoke Certificate", command=self._do_revoke).grid(
            row=2, column=1, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Check Revocation Status",
                   command=self._check_status).grid(
            row=2, column=2, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)

    # ---- Output tab ----

    def _build_output_tab(self):
        f = self.tab_output
        self.txt_output = tk.Text(f, height=25, width=100)
        self.txt_output.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # ---- CA operations ----

    def _create_root_ca(self):
        try:
            self.root_key, self.root_cert = create_root_ca()
            self._log(f"[+] Root CA created successfully")
            self._log(f"    Subject: {self.root_cert.subject.rfc4514_string()}")
            self._log(f"    Validity: {self.root_cert.not_valid_before} → {self.root_cert.not_valid_after}")
        except Exception as exc:
            self._log(f"[ERROR] {exc}")

    def _create_intermediate_ca(self):
        if self.root_key is None or self.root_cert is None:
            messagebox.showerror("Error", "Please create Root CA first.")
            return
        try:
            self.inter_key, self.inter_cert = create_intermediate_ca(
                self.root_key, self.root_cert)
            self._log(f"[+] Intermediate CA created successfully")
            self._log(f"    Subject: {self.inter_cert.subject.rfc4514_string()}")
        except Exception as exc:
            self._log(f"[ERROR] {exc}")

    def _issue_certificate(self):
        if self.inter_key is None or self.inter_cert is None:
            messagebox.showerror("Error", "Please create Intermediate CA first.")
            return
        cn = self.cn_var.get()
        if not cn:
            messagebox.showerror("Error", "Please enter Common Name.")
            return
        info = {
            "common_name": cn,
            "organization": self.org_var.get(),
            "country": self.country_var.get(),
            "email": self.email_var.get(),
        }
        try:
            key, cert = issue_certificate(self.inter_key, self.inter_cert, info)
            self._log(f"[+] Certificate issued for: {cn}")
            self._log(f"    Subject: {cert.subject.rfc4514_string()}")
            self._log(f"    Serial:  {cert.serial_number}")
            self._log(f"    Validity: {cert.not_valid_before} → {cert.not_valid_after}")
        except Exception as exc:
            self._log(f"[ERROR] {exc}")

    def _verify_chain(self):
        try:
            cert_file = filedialog.askopenfilename(
                title="Select end-entity certificate",
                filetypes=[("PEM certs", "*.pem")])
            if not cert_file:
                return
            end_cert = load_cert(cert_file)
            chain = [self.inter_cert, self.root_cert]
            valid = verify_certificate_chain(end_cert, chain)
            if valid:
                self._log("[+] Certificate chain is VALID")
            else:
                self._log("[-] Certificate chain is INVALID")
        except Exception as exc:
            self._log(f"[ERROR] {exc}")

    # ---- Certificate list ----

    def _refresh_cert_list(self):
        for item in self.cert_tree.get_children():
            self.cert_tree.delete(item)
        for f in sorted(CERTS_DIR.glob("*.pem")):
            try:
                cert = load_cert(str(f))
                self.cert_tree.insert("", tk.END,
                                       text=f.name,
                                       values=(
                                           cert.subject.rfc4514_string(),
                                           cert.issuer.rfc4514_string(),
                                           str(cert.serial_number),
                                       ))
            except Exception:
                pass

    def _view_cert_details(self):
        selected = self.cert_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a certificate.")
            return
        filename = self.cert_tree.item(selected[0], "text")
        try:
            cert = load_cert(str(CERTS_DIR / filename))
            details = (
                f"Subject: {cert.subject.rfc4514_string()}\n"
                f"Issuer:  {cert.issuer.rfc4514_string()}\n"
                f"Serial:  {cert.serial_number}\n"
                f"Valid:   {cert.not_valid_before} → {cert.not_valid_after}\n"
                f"Version: {cert.version}\n"
            )
            messagebox.showinfo(f"Certificate: {filename}", details)
        except Exception as exc:
            self._log(f"[ERROR] {exc}")

    # ---- Revocation ----

    def _create_crl(self):
        try:
            cert_file = filedialog.askopenfilename(
                title="Select issuer certificate",
                filetypes=[("PEM certs", "*.pem")])
            if not cert_file:
                return
            key_file = filedialog.askopenfilename(
                title="Select issuer private key",
                filetypes=[("PEM keys", "*.pem")])
            if not key_file:
                return
            issuer_cert = load_cert(cert_file)
            from cryptography.hazmat.primitives.serialization import (
                load_pem_private_key,
            )
            issuer_key = load_pem_private_key(
                Path(key_file).read_bytes(), password=None)
            crl = create_empty_crl(issuer_cert, issuer_key)
            self._log(f"[+] CRL created: {len(crl)} revoked certificates")
        except Exception as exc:
            self._log(f"[ERROR] {exc}")

    def _do_revoke(self):
        cert_file = self.revoke_cert_var.get()
        if not cert_file:
            messagebox.showerror("Error", "Please select a certificate to revoke.")
            return
        try:
            # Use intermediate CA to revoke
            revoke_cert_file = str(CERTS_DIR / "intermediate_cert.pem")
            revoke_key_file = str(CERTS_DIR / "intermediate_key.pem")
            crl = revoke_certificate(
                cert_file,
                revoke_cert_file,
                revoke_key_file,
                reason=self.reason_var.get(),
            )
            self._log(f"[+] Certificate revoked")
            self._log(f"    Revoked certificates in CRL: {len(crl)}")
        except Exception as exc:
            self._log(f"[ERROR] {exc}")

    def _check_status(self):
        cert_file = self.revoke_cert_var.get()
        if not cert_file:
            messagebox.showerror("Error", "Please select a certificate file.")
            return
        try:
            revoked = check_revocation_status(cert_file)
            if revoked:
                self._log("[-] Certificate IS REVOKED (found in CRL)")
            else:
                self._log("[+] Certificate is NOT revoked (not in CRL)")
        except Exception as exc:
            self._log(f"[ERROR] {exc}")

    # ---- Output helper ----

    def _log(self, msg):
        self.txt_output.insert(tk.END, msg + "\n")
        self.txt_output.see(tk.END)


def main():
    root = tk.Tk()
    app = MiniCAGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
