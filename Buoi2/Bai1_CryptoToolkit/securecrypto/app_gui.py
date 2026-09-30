#!/usr/bin/env python
"""
Tkinter GUI for the SecureCrypto Toolkit.

Features:
    - AES-256-GCM file encrypt / decrypt
    - RSA key-pair generation / signing / verification
    - Argon2id password hashing / verification
    - Built-in text viewer for encrypted files

Run:
    python securecrypto/app_gui.py
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# Ensure the package is importable when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from securecrypto.aes_utils import encrypt_file_aes, decrypt_file_aes
from securecrypto.rsa_utils import (
    generate_rsa_keypair,
    sign_data_rsa,
    verify_signature_rsa,
    save_private_key,
    save_public_key,
    load_private_key,
)
from securecrypto.hash_utils import hash_password_secure, verify_password_hash


class CryptoToolkitGUI:
    PAD_X = 8
    PAD_Y = 6

    def __init__(self, root):
        self.root = root
        self.root.title("SecureCrypto Toolkit v1.0")
        self.root.geometry("760x560")
        self.root.resizable(False, False)

        self._setup_styles()
        self._create_widgets()
        self._key_path = None
        self._hash_cache = None

    # --- styling ----------------------------------------------------------

    def _setup_styles(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

    # --- layout -----------------------------------------------------------

    def _create_widgets(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        self.tab_aes = ttk.Frame(notebook)
        self.tab_rsa = ttk.Frame(notebook)
        self.tab_hash = ttk.Frame(notebook)
        notebook.add(self.tab_aes, text="AES-256-GCM")
        notebook.add(self.tab_rsa, text="RSA-PSS")
        notebook.add(self.tab_hash, text="Argon2id")

        self._build_aes_tab()
        self._build_rsa_tab()
        self._build_hash_tab()

    # --- AES tab ----------------------------------------------------------

    def _build_aes_tab(self):
        f = self.tab_aes

        ttk.Label(f, text="File Path:").grid(row=0, column=0, sticky=tk.W,
                                              padx=self.PAD_X, pady=self.PAD_Y)
        self.enc_path_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.enc_path_var, width=50).grid(
            row=0, column=1, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Browse",
                   command=lambda: self.enc_path_var.set(
                       filedialog.askopenfilename())).grid(
            row=0, column=2, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Label(f, text="Mật khẩu:").grid(row=1, column=0, sticky=tk.W,
                                             padx=self.PAD_X, pady=self.PAD_Y)
        self.enc_pw_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.enc_pw_var, show="*",
                  width=50).grid(row=1, column=1, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Button(f, text="Encrypt", command=self._do_encrypt).grid(
            row=2, column=0, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Decrypt", command=self._do_decrypt).grid(
            row=2, column=1, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Separator(f, orient=tk.HORIZONTAL).grid(
            row=3, column=0, columnspan=3, sticky=tk.EW, pady=8)

        ttk.Button(f, text="Open Text File", command=self._open_text_file).grid(
            row=4, column=0, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Compare Files", command=self._compare_files).grid(
            row=4, column=1, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)

        self.txt_output = tk.Text(f, height=14, width=85)
        self.txt_output.grid(row=5, column=0, columnspan=3,
                             padx=self.PAD_X, pady=self.PAD_Y)

    # --- RSA tab ----------------------------------------------------------

    def _build_rsa_tab(self):
        f = self.tab_rsa

        ttk.Label(f, text="Key Size:").grid(row=0, column=0, sticky=tk.W,
                                             padx=self.PAD_X, pady=self.PAD_Y)
        self.keysize_var = tk.IntVar(value=2048)
        ttk.Spinbox(f, from_=1024, to=4096, increment=512,
                    textvariable=self.keysize_var, width=8).grid(
            row=0, column=1, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Button(f, text="Generate RSA Key Pair",
                   command=self._do_genkey).grid(
            row=0, column=2, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Separator(f, orient=tk.HORIZONTAL).grid(
            row=1, column=0, columnspan=3, sticky=tk.EW, pady=8)

        ttk.Label(f, text="Private Key:").grid(
            row=2, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.key_path_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.key_path_var, width=45).grid(
            row=2, column=1, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Browse",
                   command=lambda: self.key_path_var.set(
                       filedialog.askopenfilename(
                           filetypes=[("PEM files", "*.pem")]))).grid(
            row=2, column=2, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Label(f, text="File to Sign:").grid(
            row=3, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.sign_path_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.sign_path_var, width=45).grid(
            row=3, column=1, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Browse",
                   command=lambda: self.sign_path_var.set(
                       filedialog.askopenfilename())).grid(
            row=3, column=2, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Button(f, text="Sign File", command=self._do_sign).grid(
            row=4, column=0, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Separator(f, orient=tk.HORIZONTAL).grid(
            row=5, column=0, columnspan=3, sticky=tk.EW, pady=8)

        ttk.Label(f, text="Original File:").grid(
            row=6, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.ver_file_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.ver_file_var, width=45).grid(
            row=6, column=1, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Browse",
                   command=lambda: self.ver_file_var.set(
                       filedialog.askopenfilename())).grid(
            row=6, column=2, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Label(f, text="Signature File:").grid(
            row=7, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.sig_path_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.sig_path_var, width=45).grid(
            row=7, column=1, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Browse",
                   command=lambda: self.sig_path_var.set(
                       filedialog.askopenfilename(
                           filetypes=[("SIG files", "*.sig"),
                                      ("All files", "*.*")]))).grid(
            row=7, column=2, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Button(f, text="Verify Signature",
                   command=self._do_verify).grid(
            row=8, column=0, padx=self.PAD_X, pady=self.PAD_Y)

    # --- Hash tab ---------------------------------------------------------

    def _build_hash_tab(self):
        f = self.tab_hash

        ttk.Label(f, text="Mật khẩu:").grid(
            row=0, column=0, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)
        self.hash_pw_var = tk.StringVar()
        ttk.Entry(f, textvariable=self.hash_pw_var, show="*",
                  width=50).grid(row=0, column=1, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Button(f, text="Hash Password", command=self._do_hash).grid(
            row=1, column=0, padx=self.PAD_X, pady=self.PAD_Y)
        ttk.Button(f, text="Verify Password", command=self._do_verify_hash).grid(
            row=1, column=1, sticky=tk.W, padx=self.PAD_X, pady=self.PAD_Y)

        ttk.Separator(f, orient=tk.HORIZONTAL).grid(
            row=2, column=0, columnspan=2, sticky=tk.EW, pady=8)

        ttk.Label(f, text="Stored Hash:").grid(
            row=3, column=0, sticky=tk.NW, padx=self.PAD_X, pady=self.PAD_Y)
        self.hash_text = tk.Text(f, height=8, width=70)
        self.hash_text.grid(row=3, column=1, padx=self.PAD_X, pady=self.PAD_Y)

    # --- AES callbacks ----------------------------------------------------

    def _do_encrypt(self):
        path = self.enc_path_var.get()
        pw = self.enc_pw_var.get()
        if not path or not pw:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return
        try:
            enc = encrypt_file_aes(path, pw)
            self._log_output(f"[+] Encrypted: {enc}")
        except Exception as exc:
            self._log_error(str(exc))

    def _do_decrypt(self):
        path = self.enc_path_var.get()
        pw = self.enc_pw_var.get()
        if not path or not pw:
            messagebox.showerror("Error", "Please select a file and enter a password.")
            return
        try:
            dec = decrypt_file_aes(path, pw)
            self._log_output(f"[+] Decrypted: {dec}")
        except Exception as exc:
            self._log_error(str(exc))

    def _open_text_file(self):
        path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            content = Path(path).read_text(errors="replace")
            self.txt_output.delete(1.0, tk.END)
            self.txt_output.insert(tk.END, content)
            self._log_output(f"[+] Opened: {path}")

    def _compare_files(self):
        orig = filedialog.askopenfilename(title="Select original file")
        if not orig:
            return
        enc = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("ENC files", "*.enc"), ("All files", "*.*")])
        if not enc:
            return
        orig_size = Path(orig).stat().st_size
        enc_size = Path(enc).stat().st_size
        self._log_output(f"Original file: {orig} ({orig_size} bytes)\n"
                         f"Encrypted file: {enc} ({enc_size} bytes)\n"
                         f"Difference: {abs(enc_size - orig_size)} bytes")

    # --- RSA callbacks ----------------------------------------------------

    def _do_genkey(self):
        size = self.keysize_var.get()
        try:
            priv, pub = generate_rsa_keypair(size)
            dpath = f"private_key_{size}.pem"
            ppath = f"public_key_{size}.pem"
            save_private_key(priv, dpath)
            save_public_key(pub, ppath)
            self._log_output(f"[+] RSA key pair generated ({size} bits)\n"
                             f"    Private: {dpath}\n    Public: {ppath}")
        except Exception as exc:
            self._log_error(str(exc))

    def _do_sign(self):
        key_path = self.key_path_var.get()
        file_path = self.sign_path_var.get()
        if not key_path or not file_path:
            messagebox.showerror("Error", "Please select a key and a file.")
            return
        try:
            priv_key = load_private_key(key_path)
            data = Path(file_path).read_bytes()
            sig = sign_data_rsa(data, priv_key)
            sig_path = file_path + ".sig"
            Path(sig_path).write_bytes(sig)
            self._log_output(f"[+] Signed: {sig_path} ({len(sig)} bytes)")
        except Exception as exc:
            self._log_error(str(exc))

    def _do_verify(self):
        file_path = self.ver_file_var.get()
        sig_path = self.sig_path_var.get()
        key_path = self.key_path_var.get()
        if not all([file_path, sig_path, key_path]):
            messagebox.showerror("Error", "Please select original file, signature, and key.")
            return
        try:
            priv_key = load_private_key(key_path)
            pub_key = priv_key.public_key()
            data = Path(file_path).read_bytes()
            sig = Path(sig_path).read_bytes()
            if verify_signature_rsa(data, sig, pub_key):
                self._log_output("[+] Signature VERIFIED — file is authentic.")
            else:
                self._log_output("[-] Signature INVALID — file may be tampered.")
        except Exception as exc:
            self._log_error(str(exc))

    # --- Hash callbacks ---------------------------------------------------

    def _do_hash(self):
        pw = self.hash_pw_var.get()
        if not pw:
            messagebox.showerror("Error", "Please enter a password.")
            return
        hashed = hash_password_secure(pw)
        self._hash_cache = hashed
        self.hash_text.delete(1.0, tk.END)
        self.hash_text.insert(tk.END, hashed)
        self._log_output("[+] Password hashed with Argon2id and displayed above.")

    def _do_verify_hash(self):
        pw = self.hash_pw_var.get()
        stored = self.hash_text.get(1.0, tk.END).strip()
        if not pw or not stored:
            messagebox.showerror("Error", "Please enter password and hash.")
            return
        if verify_password_hash(stored, pw):
            self._log_output("[+] Password VERIFIED — matches the hash.")
        else:
            self._log_output("[-] Password INVALID — does not match the hash.")

    # --- Output helpers ---------------------------------------------------

    def _log_output(self, msg):
        self.txt_output.insert(tk.END, msg + "\n")
        self.txt_output.see(tk.END)

    def _log_error(self, msg):
        self.txt_output.insert(tk.END, f"[ERROR] {msg}\n")
        self.txt_output.see(tk.END)


def main():
    root = tk.Tk()
    app = CryptoToolkitGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
