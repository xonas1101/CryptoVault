# CryptoVault

Secure multi-user file storage using **hybrid encryption**.

- **AES-256-GCM** in the STREAM construction encrypts file contents, in segments, so files of any size work
- **RSA-3072-OAEP** wraps each file's random key separately for every recipient
- **Ed25519** signatures prove who stored a file
- **scrypt** protects private keys with a password
- **HKDF** gives each derived key exactly one job

Features: encrypted filenames, sharing without re-encryption, real revocation by
re-keying, tamper, truncation and reorder detection, and no release of unverified plaintext.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m unittest -v      # 20 security tests
./demo.sh                  # live walkthrough
```

```bash
python -m cryptovault adduser alice
python -m cryptovault put report.pdf -u alice --share bob
python -m cryptovault ls -u bob
python -m cryptovault get <id> -u bob
```

**Read [GUIDE.md](GUIDE.md) for the full explanation:** design, file format, threat model and presentation notes.
