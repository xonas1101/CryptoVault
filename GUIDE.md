# CryptoVault: The Everything Guide

The one file to read to understand the whole project: what it does, every cryptographic
decision and why it was made, how the code fits together, what the tests prove, what the
system honestly can't do, and how to present it.

---

## Contents
1. [What CryptoVault is](#1-what-cryptovault-is)
2. [Running it](#2-running-it)
3. [Project layout](#3-project-layout)
4. [The key hierarchy (hybrid encryption)](#4-the-key-hierarchy-hybrid-encryption)
5. [Every algorithm, and why](#5-every-algorithm-and-why)
6. [The .cvault file format](#6-the-cvault-file-format)
7. [How each feature works](#7-how-each-feature-works)
8. [Web security](#8-web-security)
9. [Security properties and the tests that prove them](#9-security-properties-and-the-tests-that-prove-them)
10. [The big design decision: who holds the keys?](#10-the-big-design-decision-who-holds-the-keys)
11. [Threat model and honest limitations](#11-threat-model-and-honest-limitations)
12. [Presenting it](#12-presenting-it)
13. [Possible extensions](#13-possible-extensions)
14. [Glossary](#14-glossary)

---

## 1. What CryptoVault is

A file-sharing system where **files can't escape**:

- You **lock** (upload) a file. It is encrypted with hybrid encryption the moment it arrives.
- You **share** it with other people **by email address**, as **view only** or **view + download**, optionally with an **expiry date**.
- Recipients see a **preview with their own email watermarked** across it.
- If someone downloads, they get a **locked `.cvault` copy**. It opens only inside CryptoVault, only for people the owner *currently* allows. Forward it to someone else and it's useless. Revoke someone and the copy they already downloaded stops working.
- **Only the system holds the key.** Users never receive a file key, so they have nothing to leak except what they can see on screen.
- Every view, download, share and **denied attempt** is recorded in a **tamper-evident log** the owner can read.

Everything is built from standard, well-reviewed primitives in the Python
[`cryptography`](https://cryptography.io) library (OpenSSL-backed). **No cryptographic
algorithm is implemented by hand.** The project is about combining primitives correctly,
which is where real systems usually go wrong.

---

## 2. Running it

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m unittest -v              # 30 tests: crypto, tampering, access control, web
python -m cryptovault --demo       # start the server with demo accounts and files
```

Open **http://127.0.0.1:8000**.

- **First start:** you choose a **master passphrase** (12+ characters). It unlocks the system key. Without it, nothing in the vault can be decrypted, not even by the server.
- **Later starts:** you type the same passphrase. A wrong passphrase means the server refuses to start.
- **`--demo`** (only into an empty vault) creates `alice@gmail.com`, `bob@gmail.com` and `eve@gmail.com` (passwords `alice-password` etc.). Alice owns a text file, an image and a 3-page PDF, shared with Bob in different ways. Eve has nothing.

Other options: `--vault DIR` (default `./vault`), `--port`, `--host`.
`CRYPTOVAULT_MASTER_PASSWORD` skips the passphrase prompt **for scripted demos only**
(environment variables can leak through `/proc` and shell history).

---

## 3. Project layout

| File | Role |
|---|---|
| `cryptovault/crypto.py` | **All cryptography** in one reviewable place: AEAD, STREAM, RSA-OAEP wrapping, HKDF, scrypt (passwords and the sealed master key), HMAC. Never touches the filesystem. |
| `cryptovault/vault.py` | The system key, users, the `.cvault` container, access control (owner / download / view / expiry), sharing, revoking, locked copies. **Every security decision is made here.** |
| `cryptovault/audit.py` | The tamper-evident access log (HMAC hash chain). |
| `cryptovault/preview.py` | Watermarked previews: images and PDF pages rendered to PNG with the viewer's email burned in. |
| `cryptovault/web.py` | Flask web app: turns HTTP requests into vault calls. No security logic of its own beyond sessions and headers. |
| `cryptovault/cli.py` | Starts the server: master passphrase prompt, `--demo` seeding. |
| `cryptovault/templates/` | HTML pages: login, dashboard, file page. |
| `tests/test_vault.py` | 24 tests: encryption, every tampering attack, access control, expiry, locked copies, users table, audit log. |
| `tests/test_web.py` | 6 tests: the full share → view-only → locked copy → forward → revoke story through the web UI, watermarks, XSS, permissions. |

The vault on disk (git-ignored):

```
vault/
  system.pub.pem      system RSA public key (not secret)
  system.key.json     system RSA private key + MAC key, sealed with the master passphrase
  users.json          email -> scrypt password hash, protected by an HMAC
  audit.log           tamper-evident access log
  files/<id>.cvault   encrypted files, named by random 128-bit ids
```

---

## 4. The key hierarchy (hybrid encryption)

```
 master passphrase (typed at server start, never stored)
        │ scrypt
        ▼
 key-encryption key ──AES-256-GCM──► system.key.json = { RSA-3072 private key, MAC key }
                                                │                    │
                                                │                    │ HKDF
                         RSA-OAEP unwrap ◄──────┘                    ├──► users-table HMAC key
                                │                                    └──► audit-log HMAC key
                                ▼
   per-file random 256-bit key K  (one per file, never reused, never given to users)
                                │ HKDF (salt = file id)
                     ┌──────────┴──────────┐
                     ▼                     ▼
                 data key              metadata key
            AES-256-GCM STREAM       AES-256-GCM (name, owner, access list)
```

**Why hybrid?** RSA can only encrypt ~318 bytes and is slow. AES is fast and works on any
size but needs its key protected. So **AES encrypts the file and RSA encrypts the AES key**.
That's the same pattern used by PGP, TLS and cloud "envelope encryption" (AWS KMS, Google Cloud KMS).

Hybrid design pays off three times here:
- **Uploading uses only the public key.** `Vault.store` never touches the private key, so the upload path could run on a machine that can never decrypt anything.
- **Sharing and revoking are cheap.** They change the access list in the small metadata block. The (possibly huge) encrypted data is never re-encrypted.
- **Changing the master passphrase** would only re-seal one small file. No file would change.

---

## 5. Every algorithm, and why

### 5.1 AES-256-GCM: confidentiality + integrity
- **AEAD** (Authenticated Encryption with Associated Data). Every encryption outputs a 16-byte **tag**. If any bit changes, decryption fails instead of returning garbage.
- **AAD:** the file header is authenticated (but not encrypted) as associated data, so it can't be altered either.
- **Nonce rule:** reusing a (key, nonce) pair breaks GCM catastrophically. Every file has its own random key. Within a file, STREAM nonces are unique by construction. When metadata is re-sealed after sharing, it gets a fresh random 96-bit nonce.
- *Why not AES-CBC + HMAC?* That's correct if done perfectly, but easy to get wrong (padding oracles, MAC-then-encrypt). GCM removes that whole class of mistakes.

### 5.2 RSA-3072-OAEP-SHA256: key wrapping
- **3072-bit** ≈ 128-bit security (NIST SP 800-57). 2048-bit is only ≈ 112-bit.
- **OAEP** is randomized padding with a security proof. Never use textbook RSA (deterministic, malleable) or PKCS#1 v1.5 encryption padding (Bleichenbacher's attack).
- On every start, the server checks that `system.pub.pem` matches the private key. Otherwise someone could swap in their own public key, and every new upload would be encrypted to them (test: `test_system_public_key_swap_detected`).

### 5.3 STREAM: encrypting large files in segments
Files are split into 64 KiB segments, each encrypted separately. Done naively, an attacker
could **reorder, drop, duplicate or truncate** segments and each would still verify on its own.
STREAM (Hoang, Reyhanitabar, Rogaway, Vizár, CRYPTO 2015; used by Google Tink and `age`)
builds each nonce from the segment's position:

```
nonce (12 bytes) = random prefix (7) | segment counter (4) | is-last-segment flag (1)
```
- Swap segments 0 and 1 → each is decrypted with the wrong counter → tag fails.
- Cut off the end → the new final segment was encrypted with flag 0 but is now checked with flag 1 → tag fails.

### 5.4 HKDF-SHA256: key separation
One secret → many independent keys, **one per job**. File key K → data key + metadata key.
MAC key → users-table key + audit-log key. Key separation guarantees that a mistake or
attack involving one use can never spill over into another.

### 5.5 scrypt: two different jobs
| Job | Input | Output | Stored? |
|---|---|---|---|
| **Seal the master key** | master passphrase + salt | AES key that encrypts `system.key.json` | no, re-derived at each start |
| **Hash user passwords** | user password + per-user salt | 32-byte hash | yes, in `users.json` |

scrypt is **memory-hard** (32 MiB per guess here), which blunts GPU/ASIC cracking far more
than SHA-256 or PBKDF2. Salts defeat rainbow tables. Password checks use **constant-time
comparison**, and unknown emails are checked against a dummy hash so **response time doesn't
reveal which emails have accounts**.

### 5.6 HMAC-SHA256: integrity for things that aren't encrypted
- **`users.json`**: without a MAC, an attacker with disk access could add an account or copy a password hash. With it, any change is detected (test: `test_users_table_tamper_detected`).
- **The audit log**: an **HMAC hash chain**. Each entry contains the previous entry's MAC and its own MAC over all its fields. Edit, delete, insert or reorder any entry and the chain breaks from that point on (test: `test_audit_log_tamper_detected`, which tries to frame Bob for Eve's denied attempt).

### 5.7 Randomness
Every key, nonce, salt, file id and session token comes from the OS CSPRNG (`os.urandom` /
`secrets`). Python's `random` module must never be used for cryptography.

---

## 6. The `.cvault` file format

```
┌───────┬─────┬───────────────────────┬─────┬───────────────────────┬────────────────────────────┐
│CVLT3  │ len │ header (JSON, public) │ len │ sealed metadata       │ segment 0 │ segment 1 │ …  │
│5 bytes│ u32 │ AAD for everything    │ u32 │ nonce|AES-GCM|tag     │ 64 KiB + 16-byte tag each  │
└───────┴─────┴───────────────────────┴─────┴───────────────────────┴────────────────────────────┘
```

**Header** (readable, but authenticated as AAD):
```json
{ "file_id": "65b39ea49d87782e06f5a92bae0d0bfc",
  "nonce_prefix": "LoivrzlEDw==",
  "wrapped_key": "<RSA-OAEP(system public key, K)>" }
```

**Metadata** (encrypted and authenticated):
```json
{ "name": "contract.pdf", "size": 65123, "sha256": "…", "type": "application/pdf",
  "owner": "alice@gmail.com", "created": 1793030400,
  "shares": { "bob@gmail.com": { "perm": "download", "until": null } } }
```

**The access list is inside the encryption.** Someone with full disk access can't read who
has access, and can't grant themselves access, because any edit fails the GCM tag
(test: `test_sealed_metadata_tamper_detected`). Copying one `.cvault` over another is caught
because the `file_id` in the header must match the file name (test: `test_swapping_two_files_detected`).

Open any file in the UI and expand **"Under the hood"** to see the real header and ciphertext.

---

## 7. How each feature works

**Lock (upload).** Generate K and a file id → wrap K with the system **public** key →
derive the data and metadata keys → encrypt the metadata → STREAM-encrypt the data → write
to a temp file and atomically rename it (a crash never leaves a half-written file).

**View.** Check the permission (owner / download / view, and not expired) → unwrap K →
decrypt and verify every segment → check SHA-256 → render a preview:
- **text**: shown in the page with a tiled watermark overlay; text selection is disabled
- **images and PDFs**: rendered on the server into PNGs with the viewer's email and the time **burned into the pixels** (the browser never receives the original file)
- **other types**: no preview; view-only users have to ask for download permission

**Download original.** Only the owner, or recipients granted *view + download*. Sent as
`application/octet-stream` with `Cache-Control: no-store`.

**Download locked copy.** Anyone with access gets the `.cvault` container itself. It
contains only ciphertext, and K is wrapped with a key that only the server holds.

**Open a locked file.** The uploaded copy is treated like a **ticket**: the server reads its
file id and opens the **vault's current copy**, applying the **current** access list. So:
- forwarded to Eve → she isn't on the list → denied (and logged)
- Bob is revoked → his own downloaded copy stops working
- the owner deletes the file → every copy anywhere becomes permanently unopenable

**Share / revoke / expiry.** The owner edits the access list. The metadata is re-sealed under
a fresh nonce and the data segments are copied byte for byte (test:
`test_share_reseals_metadata_but_never_touches_data`). Revocation needs **no re-encryption**:
users never held K, so there is nothing to take back. Expiry is checked on every access
against the server clock.

**Activity log.** Every upload, view, download, locked-copy download, open, share, revoke,
delete, login and **denial** is appended to the HMAC chain. The owner sees each file's
history and a ✓ / ⚠ badge for whether the whole chain verifies.

---

## 8. Web security

| Threat | Defence |
|---|---|
| Stolen session cookie used after logout | Sessions are random 256-bit tokens in a server-side table. Logout deletes the token; 15 minutes idle expires it. |
| Session fixation | A fresh token is issued on every login. |
| CSRF (another site submitting forms to CryptoVault) | `SameSite=Strict` cookie: the browser never sends it on cross-site requests. |
| XSS through file names | Jinja auto-escaping (test: `test_filenames_are_html_escaped`) plus a strict Content-Security-Policy that allows **no scripts at all**. |
| Malicious SVG / HTML uploads | SVG is never previewed; downloads are forced to `application/octet-stream` + `nosniff`. |
| Decrypted data left in browser or proxy caches | `Cache-Control: no-store` on every response. |
| Clickjacking | `X-Frame-Options: DENY`. |
| Probing which emails have accounts | Identical error message and constant-time password checks with a dummy hash. |
| Huge uploads / decompression bombs | 100 MB upload cap; Pillow refuses decompression-bomb images. |

The server binds to `127.0.0.1` by default. Serving to other machines without HTTPS would
send passwords in the clear, and the server warns about that.

---

## 9. Security properties and the tests that prove them

| Property | Mechanism | Test |
|---|---|---|
| Contents confidential at rest | AES-256-GCM | `test_round_trip_all_sizes` |
| Name, owner and access list confidential at rest | sealed metadata | `test_name_owner_and_access_list_not_visible_on_disk` |
| Same file → different ciphertext | fresh K, random nonces | `test_same_plaintext_encrypts_differently` |
| Data tampering detected | GCM tag per segment | `test_bit_flip_in_data_detected` |
| Truncation / reordering detected | STREAM | `test_truncation_detected`, `test_segment_reordering_detected` |
| Header, wrapped-key and file-swap tampering detected | header is AAD; id check | `test_header_tamper_detected`, `test_wrapped_key_swap_detected`, `test_swapping_two_files_detected` |
| Can't grant yourself access by editing disk | access list inside GCM | `test_sealed_metadata_tamper_detected` |
| Damaged files are reported | listing verifies metadata | `test_broken_files_are_reported` |
| View / download / revoke enforced | access check on every request | `test_permissions` |
| Expiring access | `until` checked on every request | `test_expiry` |
| Only the owner manages a file | `need="owner"` | `test_only_owner_can_manage` |
| Sharing never re-encrypts data | metadata re-sealed only | `test_share_reseals_metadata_but_never_touches_data` |
| Locked copies obey the *current* access list | ticket model | `test_locked_copy_obeys_current_access_list` |
| Denied attempts are logged | audit on `AccessDenied` | `test_denials_are_logged` |
| Audit log tampering detected | HMAC chain | `test_audit_log_tamper_detected` |
| User table tampering detected | HMAC | `test_users_table_tamper_detected` |
| Passwords never stored | scrypt hashes | `test_passwords_stored_only_as_hashes`, `test_authentication` |
| Wrong master passphrase can't unlock | sealed keystore | `test_wrong_master_passphrase` |
| Public-key substitution detected | key-pair check on start | `test_system_public_key_swap_detected` |
| The whole story through the UI | – | `test_view_only_share_full_story` |
| Previews are watermarked | Pillow rendering | `test_image_and_pdf_previews_are_watermarked` |

---

## 10. The big design decision: who holds the keys?

This is the most important thing to understand, and to be able to defend.

| | **End-to-end** (each user holds their own keys) | **System-held key** (this project) |
|---|---|---|
| Who can decrypt | only users with the key | the server, on behalf of permitted users |
| Server operator can read files | **no** | **yes** (with the master passphrase) |
| "View only" possible | no: the recipient has the key and can decrypt anything | **yes**: the recipient never gets the key |
| Revoke a downloaded copy | no: they keep the key | **yes**: copies are tickets checked against the current list |
| Revocation cost | re-encrypt the whole file | edit the access list |
| Real-world examples | Signal, `age`, PGP | Google Drive, Microsoft 365 rights management, AWS KMS |

CryptoVault picks **system-held keys** because the goal is *controlling what recipients
can do*, and that's only possible if recipients never hold the key. The price is that you
**must trust the server** (and whoever knows the master passphrase). Stating this trade-off
clearly is a strength in a presentation, not a weakness.

> The project's git history contains an earlier end-to-end version
> (commit `1225545`: per-user RSA + Ed25519 keys, sign-then-encrypt, revocation by re-keying).
> It makes a good "alternative design we considered" slide.

---

## 11. Threat model and honest limitations

**Protects against:** someone who copies or steals the vault folder (stolen laptop,
leaked backup, curious cloud host); someone who modifies files, the user table or the log
on disk; recipients forwarding locked copies; recipients keeping access after revocation
or expiry; users opening files not shared with them.

**Does NOT protect against:**
- **The "analog hole".** Anyone who can *see* a file can photograph or screenshot it, or retype it. No system can stop this. Google, Microsoft and Netflix included, they all only deter. Watermarking turns a leak into **evidence of who leaked it**.
- **A malicious or compromised server.** The server holds the key by design (section 10).
- **Unverified email addresses.** Anyone can register as `bob@gmail.com` if Bob hasn't yet, and receive files shared with that address. Fix: real "Sign in with Google" (OAuth). See extensions.
- **Rollback.** An attacker with disk write access could put back an *older* valid copy of a `.cvault` file (e.g. one from before a revocation) or of `users.json`. Fix: store a version counter in a trusted place.
- **Log truncation.** Deleting entries from the **end** of the audit log leaves a valid, shorter chain. Fix: periodically publish the latest MAC somewhere outside the server.
- **Plain HTTP beyond localhost.** Put it behind HTTPS before using it across a network.
- **Metadata that still leaks:** approximate file size, number of files, and timing patterns in the log (the log records actors and file ids in the clear).
- **Secure deletion.** Deleting unlinks the file. SSDs and backups may keep the bytes, though they stay encrypted.
- **Quantum computers** would break RSA (Shor's algorithm). AES-256 stays safe.

---

## 12. Presenting it

Start: `python -m cryptovault --demo`, then open two browser windows (one private) so you can be Alice and Bob at once.

**Suggested 10-minute flow:**
1. **The problem** (1 min): "I want to share a document but control what happens to it."
2. **Hybrid encryption** (2 min): the key-hierarchy diagram in section 4.
3. **Live demo** (5 min):
   1. *Alice* uploads a file, shares it with Bob as **view only** with an **expiry date**.
   2. *Bob* opens it: the preview is **watermarked with his email**. There's no "download original" button.
   3. *Bob* downloads the **locked copy** and opens it in a text editor: just ciphertext.
   4. *Eve* uploads Bob's locked copy via "Open a locked file" → **denied**.
   5. *Alice's* activity log shows Bob's views and **Eve's denied attempt**.
   6. *Alice* **revokes** Bob → Bob re-uploads his own locked copy → denied.
   7. Expand **"Under the hood"** → the real header, wrapped key and ciphertext.
   8. Optional: edit a line in `vault/audit.log` and refresh → **⚠ log tampered**.
4. **Design trade-off** (1 min): section 10's table.
5. **Limitations** (1 min): the analog hole. "We can't stop a camera, so we make sure every leak is traceable."

**Likely questions:**
- *Why not just encrypt files with RSA?* Size limit (~318 bytes) and speed.
- *Why do you need STREAM?* Encrypting segments independently allows reordering and truncation attacks.
- *What stops Bob from sending the file?* He can send the locked copy, but it's useless. He can't get the key, because he never has it. He *can* photograph the screen, which is why there's a watermark.
- *Can the admin read files?* Yes, by design: that's the price of view-only control (section 10).
- *Why scrypt?* It's memory-hard, which makes GPU cracking expensive. SHA-256 is designed to be fast, which is the opposite of what you want for passwords.
- *What if someone edits the access list on disk?* It's inside AES-GCM, so the tag fails and the file is reported as damaged.
- *What if someone edits the log?* The HMAC chain breaks, and they can't recompute it without the MAC key, which is sealed under the master passphrase.

---

## 13. Possible extensions

- **Real Google sign-in (OAuth 2.0 / OpenID Connect):** proves email ownership. Needs a free OAuth client ID from Google Cloud Console.
- **HSM / cloud KMS** for the system key, so even the server's memory never holds the RSA private key.
- **HTTPS** with a reverse proxy (Caddy or nginx), and rate limiting on login.
- **Encrypt the audit log** entries too, and anchor its head externally (fixes log truncation).
- **Rollback protection:** a monotonic version per file, kept in an HMAC-protected index.
- **Post-quantum hybrid:** wrap K with both RSA/X25519 and **ML-KEM (Kyber, FIPS 203)**.
- **Shamir secret sharing** of the master passphrase (k of n admins must agree to start the server).
- **Invisible watermarking** (steganography) that survives cropping.

---

## 14. Glossary

| Term | Meaning |
|---|---|
| Hybrid encryption | Fast symmetric cipher for the data, public-key cipher for the symmetric key |
| AEAD | Authenticated encryption with associated data: encrypts *and* detects tampering (AES-GCM) |
| AAD | Data that is authenticated but not encrypted (our header) |
| Nonce | "Number used once": must never repeat under the same key |
| Tag | GCM's 16-byte authenticator |
| Key wrapping | Encrypting a key with another key |
| KEK / DEK | Key-encryption key (the system RSA key) / data-encryption key (K) |
| Envelope encryption | The industry name for this KEK/DEK pattern (AWS KMS, Google Cloud KMS) |
| OAEP | Secure randomized padding for RSA encryption |
| STREAM | Segmented AEAD where nonces encode position and finality |
| HKDF | Derives several independent keys from one secret |
| scrypt | Slow, memory-hard function for passwords |
| Salt | Random per-item value that defeats precomputed tables |
| HMAC | Keyed hash: proves data wasn't changed by someone without the key |
| Hash chain | Each entry commits to the previous one, so history can't be quietly rewritten |
| Watermark | Visible mark identifying the viewer, for attribution after a leak |
| Analog hole | Anything displayed can be re-captured (camera or screenshot), so no DRM is airtight |
| Kerckhoffs's principle | A system must stay secure even if everything except the key is public |
