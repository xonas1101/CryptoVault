# CryptoVault: The Everything Guide

This is the one file to read to understand the whole project: what it does, every
cryptographic decision and why it was made, how the code is laid out, what the tests
prove, and what the system does **not** protect against.

---

## Contents
1. [What CryptoVault is](#1-what-cryptovault-is)
2. [Setup and usage](#2-setup-and-usage)
3. [Project layout](#3-project-layout)
4. [Core idea: hybrid encryption](#4-core-idea-hybrid-encryption)
5. [Every algorithm, and why](#5-every-algorithm-and-why)
6. [The .cvault file format](#6-the-cvault-file-format)
7. [How each operation works](#7-how-each-operation-works)
8. [Security properties and the tests that prove them](#8-security-properties-and-the-tests-that-prove-them)
9. [Threat model and limitations](#9-threat-model-and-limitations)
10. [Presenting it](#10-presenting-it)
11. [Possible extensions](#11-possible-extensions)
12. [Glossary](#12-glossary)

---

## 1. What CryptoVault is

A multi-user encrypted file store. Users can:

- **store** files encrypted (contents *and* filenames are hidden),
- **share** a file with other users without re-encrypting it,
- **revoke** someone's access cryptographically (not just by deleting a permission),
- **verify** a file wasn't modified and was really stored by who it claims.

Everything is built from standard, well-reviewed primitives in the Python
[`cryptography`](https://cryptography.io) library (backed by OpenSSL). **No cryptographic
algorithm is implemented by hand.** That's deliberate: the project is about combining
primitives correctly, which is where real systems usually go wrong.

---

## 2. Setup and usage

Requires Python 3.11+.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m unittest -v       # 20 security tests
./demo.sh                   # scripted live demo (PAUSE=1 ./demo.sh to step through)
```

### Commands

```bash
python -m cryptovault adduser alice                  # create a user (asks for a password)
python -m cryptovault adduser bob
python -m cryptovault users                          # list users + key fingerprints

python -m cryptovault put report.pdf -u alice --share bob    # encrypt into the vault, prints an id
python -m cryptovault ls -u bob                      # list files bob can open
python -m cryptovault get 3fa9c1 -u bob              # decrypt (an id prefix is enough, like git)
python -m cryptovault get 3fa9c1 -u bob -o copy.pdf  # choose the output path
python -m cryptovault verify 3fa9c1 -u bob           # check integrity + signature, write nothing

python -m cryptovault share 3fa9c1 -u alice --with carol     # give carol access
python -m cryptovault revoke 3fa9c1 -u alice --from bob      # take bob's access away (re-encrypts)
python -m cryptovault rm 3fa9c1 -u alice             # delete (owner only)
python -m cryptovault passwd -u alice                # change password
```

Environment shortcuts: `CRYPTOVAULT_DIR` (vault location, default `./vault`) and
`CRYPTOVAULT_USER` (so you can skip `-u`). `CRYPTOVAULT_PASSWORD` exists **only for
the demo script and tests**. Never use it for real, because environment variables
can leak through `/proc` and shell history.

---

## 3. Project layout

| File | Lines | Role |
|---|---|---|
| `cryptovault/crypto.py` | ~180 | **All cryptography** in one reviewable place: keystore, key wrapping, HKDF, streaming AEAD, signatures. Never touches the filesystem. |
| `cryptovault/vault.py` | ~310 | Users, the `.cvault` container format, and the operations (put/get/ls/share/revoke/rm). Calls `crypto.py` for every crypto operation. |
| `cryptovault/cli.py` | ~115 | Command-line interface (argparse). Contains no security logic. |
| `cryptovault/__main__.py` | 3 | Makes `python -m cryptovault` work. |
| `tests/test_vault.py` | ~200 | 20 tests: correctness, every tampering attack, access control, forgery, revocation. |
| `demo.sh` | ~80 | Presentation demo using a throwaway vault. |

Vault on disk (created on first `adduser`, git-ignored):

```
vault/
  users/alice.pub.json   public keys (RSA + Ed25519, PEM). Not secret.
  users/alice.key.json   private keys, encrypted with alice's password (permissions 600)
  files/<32-hex-id>.cvault
```

Files are stored under **random ids**, not their names, so a directory listing reveals nothing.

---

## 4. Core idea: hybrid encryption

| | Symmetric (AES) | Asymmetric (RSA) |
|---|---|---|
| Keys | one shared secret | public key encrypts, private key decrypts |
| Speed | very fast, any size | slow; RSA-3072-OAEP can encrypt at most **318 bytes** |
| Weakness | how do you get the key to the right people? | can't encrypt a real file |

**Hybrid encryption combines them:**

```
                 fresh random 256-bit file key K
                              │
   file ──► AES-256-GCM(K) ──►│──► ciphertext                 (fast, any size)
                              │
         K ──► RSA-OAEP(alice's public key) ──► wrapped K for alice   (32 bytes, fits easily)
         K ──► RSA-OAEP(bob's public key)   ──► wrapped K for bob
```

Each recipient unwraps K with their private key, then decrypts the file. PGP, S/MIME,
age, TLS and cloud "envelope encryption" (AWS/GCP KMS) all use this pattern.

**Why it's more than a speed trick (and the demo shows each point):**
- **Sharing is cheap:** to add a user, wrap K once more. The gigabytes of ciphertext don't change (`share`).
- **Password change is cheap:** only the keystore holding the RSA key is re-encrypted. No file is touched (`passwd`).
- **Writing needs no secret about recipients:** you only need their *public* keys.

---

## 5. Every algorithm, and why

### 5.1 AES-256-GCM (file contents and metadata)
- **AEAD** (Authenticated Encryption with Associated Data): gives confidentiality **and**
  integrity in one primitive. Each encryption outputs a 16-byte **tag**. Change any bit
  and decryption fails rather than returning garbage.
- **Associated data (AAD):** data that is authenticated but not encrypted. We use the
  file header, so the header can't be altered either.
- **Nonce rule:** GCM is catastrophically broken if a (key, nonce) pair repeats (it
  leaks the XOR of plaintexts and allows tag forgery). We never reuse a key across
  files, and within a file every segment's nonce is unique by construction (see 5.3).
- *Why not AES-CBC + HMAC?* It's correct if done perfectly, but it's easy to get wrong
  (MAC-then-encrypt, padding oracles). GCM removes that whole class of mistakes.

### 5.2 RSA-3072 with OAEP-SHA256 (key wrapping)
- **3072-bit** ≈ 128-bit security, matching AES-128's security level (NIST SP 800-57). 2048-bit ≈ 112-bit.
- **OAEP** is randomized padding with a security proof. *Never* use textbook RSA
  (deterministic and malleable) or PKCS#1 v1.5 encryption padding (Bleichenbacher's
  1998 attack, still turning up as ROBOT in 2017).
- Public exponent **65537**: the standard choice.

### 5.3 STREAM construction (large files)
A single GCM call over a 4 GB file would need the entire file in memory. So the file
is split into **64 KiB segments**, each encrypted separately. Done naively, that is
**insecure**: an attacker could reorder, drop, duplicate or truncate segments and each
one would still verify individually.

STREAM (Hoang, Reyhanitabar, Rogaway, Vizár, CRYPTO 2015; used by Google Tink and `age`)
fixes this by building each segment's nonce from its position:

```
nonce (12 bytes) = random prefix (7) | segment counter (4, big-endian) | last-segment flag (1)
```
- **Reorder** segment 0 and 1 → segment 1's ciphertext is decrypted with counter 0 → tag fails.
- **Truncate** (drop the end) → the new final segment was encrypted with flag 0, but is now decrypted with flag 1 → fails.
- **Splice in a segment from another file** → different key/prefix → fails.

Implemented in `crypto.encrypt_stream` / `decrypt_stream`. Tests:
`test_truncation_detected`, `test_segment_reordering_detected`.

### 5.4 HKDF-SHA256 (key separation)
The random file key K is never used directly. HKDF derives two independent keys:
`data_key` (for the STREAM segments) and `meta_key` (for the metadata). **Key separation**
means each key has exactly one job, so nonces from the two uses can never collide.
The file id is the HKDF salt.

### 5.5 Ed25519 (signatures, i.e. authenticity)
This is the subtle part, and a good one to explain in a presentation.

With multiple recipients, **every recipient knows K**. GCM only proves "someone who
knows K made this". So Bob could take a file Alice shared with him, change the contents,
re-encrypt with the same K, and Carol (also a recipient) couldn't tell. **Encryption
alone does not provide authenticity in a multi-user setting.**

Fix: the owner signs `{name, size, sha256 of contents, owner, created, file_id}` with
their **Ed25519** private key. Recipients verify against the owner's public key. Only the
owner has that key, so only the owner can produce valid metadata. Including `file_id`
ties the signature to this particular file.

The signature sits *inside* the encrypted metadata (**sign-then-encrypt**), so an
outsider can't even see who signed. Test: `test_forged_owner_rejected` (Eve forges an
invoice "from Alice").

*Why a second key pair instead of signing with RSA?* Using one key for both encryption
and signing is a classic mistake: the two uses can interact badly, and they often need
different lifetimes. Ed25519 is fast, has small 64-byte signatures, and is deterministic
(no per-signature randomness to get wrong, unlike ECDSA).

### 5.6 scrypt + AES-GCM keystore (protecting private keys with a password)
Passwords are low-entropy, so they need a **key derivation function** that makes each
guess expensive:

```
password ──► scrypt(salt, N=2^15, r=8, p=1) ──► 256-bit key ──► AES-GCM ──► {RSA private key, Ed25519 private key}
```
- **scrypt is memory-hard** (32 MiB per guess here), which blunts GPU/ASIC cracking far
  more than plain hashing or PBKDF2.
- A random 16-byte **salt** per user stops precomputed (rainbow table) attacks.
- The KDF parameters are the GCM **AAD**, so tampering with them (e.g. lowering N) is detected.
- A wrong password simply fails the GCM tag check, so there's no separate password hash to steal.

### 5.7 Randomness
All keys, nonces, salts and ids come from `os.urandom`, the OS CSPRNG. Python's
`random` module must never be used for cryptography.

---

## 6. The `.cvault` file format

```
┌───────┬─────┬──────────────────┬─────┬────────────────────┬──────────────────────────────┐
│CVLT2  │ len │ header (JSON)    │ len │ metadata ciphertext│ segment 0 │ segment 1 │ ...  │
│5 bytes│ u32 │ public, in AAD*  │ u32 │ AES-GCM(meta_key)  │ 64 KiB + 16 B tag each       │
└───────┴─────┴──────────────────┴─────┴────────────────────┴──────────────────────────────┘
```

**Header** (readable, so the right user can find their wrapped key):
```json
{
  "file_id":      "d6xiTXBvYJ+/kOYKF6yhLQ==",          // 16 random bytes, also HKDF salt
  "nonce_prefix": "LoivrzlEDw==",                       // 7 random bytes for STREAM
  "meta_nonce":   "tUYEOVquj0Xh5m7+",                   // 12 random bytes
  "recipients":   {"alice": "<RSA-OAEP(K)>", "bob": "<RSA-OAEP(K)>"}
}
```
\*Everything **except `recipients`** is the AAD for every GCM operation. `recipients` is
excluded on purpose, so `share` can add a wrapped key without re-encrypting anything.
Is that safe? An attacker editing `recipients` can only (a) delete entries (denial of
service, which they could do by deleting the file anyway) or (b) add a wrapped key for
a *different* K, which then fails to decrypt the metadata. They can't learn or change the real K.

**Metadata** (encrypted): `{name, size, sha256, owner, created, file_id, signature}`.
Hiding the filename matters: `divorce-lawyer-letter.pdf` leaks plenty on its own.

---

## 7. How each operation works

**`adduser`**: generate RSA-3072 and Ed25519 key pairs → write public keys to
`users/<name>.pub.json` → seal private keys with scrypt + AES-GCM into `<name>.key.json` (mode 600).

**`put`**
1. Unlock the owner's keystore (needed for the signing key).
2. Hash the file (SHA-256).
3. Generate K and file_id; derive `data_key`, `meta_key` with HKDF.
4. Wrap K with each recipient's RSA public key.
5. Sign the metadata with Ed25519, then encrypt it with `meta_key`.
6. Stream-encrypt the file with `data_key`.
7. Write to a temp file, then atomically rename it (a crash never leaves a half-written file).

**`get`**
1. Unlock the user's keystore; find the file by id prefix.
2. Not in `recipients` → *access denied*.
3. Unwrap K → derive sub-keys → decrypt metadata → **verify the owner's signature**.
4. Stream-decrypt every segment, hashing as it goes.
5. Check the size and SHA-256 against the signed metadata.
6. Only if *everything* passed is the temp output renamed into place. **Unverified
   plaintext is never released.** Many real systems get this wrong (it's what the EFAIL
   attack on PGP email exploited).

**`share`**: open the file as an existing recipient → wrap K for the new users → rewrite
only the header. The ciphertext bytes are identical before and after (tested).

**`revoke`**: deleting Bob's wrapped key isn't enough, because Bob may have saved K
earlier. So revoke **re-keys**: decrypt, then re-encrypt under a fresh K and a new
file_id, wrapping only for the remaining users, and delete the old file. Only the owner
can do this, because the new metadata must be re-signed with the owner's key. This is
enforced cryptographically, not by an `if` statement. The test
`test_revoke_rekeys_so_old_wrapped_key_is_useless` has Bob splice his old wrapped
key back into the new file and confirms it opens nothing.

**`passwd`**: re-seal the same private keys under a new password. No file changes.

---

## 8. Security properties and the tests that prove them

| Property | Mechanism | Test(s) |
|---|---|---|
| Confidentiality of contents | AES-256-GCM | `test_round_trip_all_sizes` |
| Confidentiality of filenames | name stored in encrypted metadata, random ids on disk | `test_filename_is_not_visible_on_disk` |
| Same file → different ciphertext | fresh K, random nonces, randomized OAEP | `test_same_plaintext_encrypts_differently` |
| Integrity of data | GCM tag per segment | `test_bit_flip_in_data_detected` |
| No truncation | STREAM last-segment flag | `test_truncation_detected` |
| No reordering | STREAM counter | `test_segment_reordering_detected` |
| Integrity of header and metadata | header is AAD; metadata is GCM | `test_header_tamper_detected`, `test_metadata_tamper_detected` |
| No unverified plaintext released | temp file + atomic rename | checked inside every rejection test |
| Authenticity of owner | Ed25519 signature | `test_forged_owner_rejected` |
| Access control | RSA wrapping per recipient | `test_non_recipient_denied_and_file_hidden`, `test_outsider_cannot_share` |
| Sharing without re-encryption | re-wrap K only | `test_share_adds_access_without_reencrypting` |
| Real revocation | re-keying | `test_revoke_rekeys_so_old_wrapped_key_is_useless` |
| Owner-only revoke/delete | re-signing needs the owner's key | `test_only_owner_can_revoke_or_delete` |
| Private keys protected at rest | scrypt + AES-GCM, mode 600 | `test_private_keys_not_stored_in_clear`, `test_wrong_password_rejected` |
| Password change without re-encrypting files | key hierarchy | `test_password_change` |
| No path traversal via user names | strict regex `[a-z0-9_-]{1,32}` | `test_bad_user_names_rejected` |

---

## 9. Threat model and limitations

**Protects against:** someone who steals or copies the vault directory (a stolen
laptop, a leaked backup, a curious cloud provider), someone who modifies files in it,
and users of the vault trying to read files not shared with them or to impersonate
another user.

**Does NOT protect against (be upfront about these, examiners love it):**
- **Public-key substitution.** Anyone who can write to `vault/users/` could replace
  Bob's public key with their own, and Alice would then encrypt to the attacker. Mitigation
  in this project: `users` shows **fingerprints** to compare in person (like SSH or Signal
  safety numbers). Real fix: a PKI or certificates, or pinning keys on first use.
- **Weak passwords.** If `alice.key.json` is stolen, it can be attacked offline. scrypt
  slows this down but can't save "password123".
- **Malware on the user's machine** can read the password or the decrypted file.
- **Metadata that is still visible:** approximate file size, number of files, recipient
  *user names* (in the header), and modification times.
- **Revocation doesn't reach the past.** Bob may already have downloaded the plaintext. No crypto can undo that.
- **Deletion isn't secure erasure.** `rm` unlinks the file. SSDs and backups may keep the bytes.
- **No forward secrecy.** Compromising a private key plus its password exposes every file wrapped to it.
- **Not quantum-safe.** A large quantum computer would break RSA (Shor's algorithm).
  AES-256 stays fine (Grover only halves the effective key length, so 128-bit security remains).
- `put` reads the file twice (to hash it, then to encrypt it). If the file changes in
  between, `get` will report a hash mismatch (detected, not silent).

---

## 10. Presenting it

Suggested 10-minute flow:
1. **Problem** (1 min): store files on untrusted storage, share them with some people.
2. **Hybrid encryption** (2 min): the table and diagram in section 4.
3. **Live demo** (4 min): `PAUSE=1 ./demo.sh`. It shows users and fingerprints, the raw file
   (no filename visible), decrypting, Eve denied, a one-bit flip caught, a forged
   signature caught, and revocation by re-keying.
4. **Three "aha" design points** (2 min):
   - Why chunking needs STREAM (reordering and truncation attacks).
   - Why encryption ≠ authenticity with multiple recipients (hence Ed25519).
   - Why revocation must re-key.
5. **Limitations** (1 min): section 9. Showing you know the limits is a strength.

Likely questions:
- *Why not encrypt the file with RSA directly?* Size limit (318 bytes) and speed.
- *Why GCM over CBC?* Built-in integrity, no padding oracle.
- *What if two files get the same nonce?* Each file has its own random key, so it doesn't matter.
- *Why scrypt over SHA-256(password)?* A plain hash allows billions of guesses per second on a GPU. scrypt's memory cost prevents that.
- *Can Bob (a recipient) modify the file?* He can re-encrypt it with K, but he can't produce Alice's signature, so the change is detected.

---

## 11. Possible extensions

- **X25519 + HKDF (ECIES/HPKE, RFC 9180)** instead of RSA: smaller keys, faster, modern.
- **Post-quantum hybrid:** wrap K with both X25519 and **ML-KEM (Kyber, FIPS 203)**.
- **Trust on first use:** remember each user's fingerprint and warn if it changes.
- **Hide recipients:** store anonymous wrapped keys and have users try each one.
- **Pad file sizes** to buckets to hide exact lengths.
- **Secret sharing (Shamir)** for recovery when a password is forgotten (k of n trustees).
- **A GUI or web front end** on top of `vault.py`. The CLI has no security logic, so this is straightforward.

---

## 12. Glossary

| Term | Meaning |
|---|---|
| AEAD | Authenticated encryption with associated data: encrypts *and* detects tampering (e.g. AES-GCM) |
| AAD | Data that is authenticated but not encrypted |
| Nonce | "Number used once": must never repeat under the same key |
| Tag | GCM's 16-byte authenticator |
| Key wrapping | Encrypting a key with another key |
| KEK / DEK | Key-encryption key (RSA here) / data-encryption key (K) |
| OAEP | Secure randomized padding for RSA encryption |
| HKDF | Derives several independent keys from one secret |
| KDF (password) | Slow, salted function that turns a password into a key (scrypt) |
| Salt | Random per-user value that defeats precomputed tables |
| STREAM | Segmented AEAD where nonces encode position and finality |
| Ed25519 | Fast, deterministic elliptic-curve signature scheme |
| Fingerprint | Short hash of a public key, for verification by eye |
| Re-keying | Re-encrypting under a fresh key to cut off old key holders |
| Forward secrecy | A later key compromise doesn't expose past data (not provided here) |
