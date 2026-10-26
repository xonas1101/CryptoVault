# CryptoVault

Share files without letting them escape. A web app where you lock files with **hybrid
encryption**, share them **by email** as view-only or downloadable, with optional expiry,
and keep control afterwards.

- **Pick your protection per file**: server key (RSA-3072), password (scrypt), double encryption (ChaCha20-Poly1305 inside AES-256-GCM), lockdown (view-only for everyone). Password-only for quick locks, all four for confidential data.
- **AES-256-GCM** (STREAM construction) encrypts every file under its own random key, and **RSA-3072-OAEP** wraps that key with a system key only the server holds
- Recipients never receive a key. **Downloads are locked `.cvault` copies** that open only inside CryptoVault, only for people the owner *currently* allows. Revoke someone and the copies they took stop working.
- **Watermarked previews**: every image and PDF page is rendered with the viewer's email burned in
- **Tamper-evident activity log** (HMAC hash chain), including denied attempts
- Access lists live *inside* the encryption, so nobody can grant themselves access by editing disk
- **scrypt** for passwords and the master key, **HKDF** key separation, strict web security headers

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m unittest -v           # 35 tests
python -m cryptovault --demo    # then open http://127.0.0.1:8000
```

Demo logins: `alice@gmail.com` / `alice-password`, `bob@gmail.com` / `bob-password`, `eve@gmail.com` / `eve-password`.
Demo file passwords: `launch-plan.txt` / `launch-password`, `contract.pdf` / `contract-password`.

**Read [GUIDE.md](GUIDE.md) for everything:** design, file format, the key-holding
trade-off, threat model, and a presentation script.
