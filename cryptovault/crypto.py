"""Cryptographic primitives for CryptoVault.

Every security-critical operation lives in this one module so it can be reviewed
in one place. Nothing here touches the filesystem.

  sealed secrets   scrypt (master passphrase -> key) + AES-256-GCM protects the system's keys
  password hashes  scrypt with a per-user salt, compared in constant time
  key wrapping     RSA-3072-OAEP-SHA256 encrypts each file's random key (the "hybrid" part)
  key separation   HKDF-SHA256 derives independent keys from one secret
  streaming AEAD   AES-256-GCM in the STREAM construction, for files of any size
  cascade          optional inner ChaCha20-Poly1305 layer, so one broken cipher isn't enough
  integrity tags   HMAC-SHA256 for the user table and the audit log hash chain
  signatures       Ed25519: each user signs what they upload
  sealed boxes     X25519 + HKDF + AES-GCM: encrypt to one user's public key
  secret sharing   Shamir k-of-n over GF(2^521 - 1), for the approval-quorum layer
"""
import base64
import hashlib
import hmac
import json
import os
import struct
from secrets import randbelow

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

RSA_BITS = 3072                      # ~128-bit security (NIST SP 800-57)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
SCRYPT = {"n": 2**15, "r": 8, "p": 1}  # 32 MiB of memory per guess
CHUNK = 64 * 1024                    # plaintext bytes per STREAM segment
TAG = 16                             # GCM authentication tag size
PREFIX = 7                           # STREAM nonce = prefix(7) | counter(4) | last-flag(1)


class CryptoError(Exception):
    """A cryptographic check failed. Messages say what failed, never anything secret."""


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError):
        raise CryptoError("malformed base64 field") from None


def canon(obj) -> bytes:
    """Canonical JSON: the same object always gives the same bytes (required before MACing or using as AAD)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------- single-shot AEAD ----------

def seal(key: bytes, plaintext: bytes, aad: bytes, aead=AESGCM) -> bytes:
    """AES-256-GCM (or ChaCha20-Poly1305) with a fresh random nonce, returned as nonce || ciphertext || tag."""
    nonce = os.urandom(12)
    return nonce + aead(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, sealed: bytes, aad: bytes, what: str, aead=AESGCM) -> bytes:
    try:
        return aead(key).decrypt(sealed[:12], sealed[12:], aad)
    except (InvalidTag, ValueError):
        raise CryptoError(f"{what} failed authentication (tampered or wrong key)") from None


# ---------- passwords ----------

def new_kdf() -> dict:
    return {"salt": b64e(os.urandom(16)), **SCRYPT}


def password_key(password: str, kdf: dict) -> bytes:
    """scrypt: password -> 32-byte key. Slow and memory-hard, so every guess is expensive."""
    return Scrypt(salt=b64d(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(password.encode())


def hash_password(password: str) -> dict:
    """Slow, salted, memory-hard hash. The server stores this, never the password."""
    kdf = new_kdf()
    return {"kdf": kdf, "hash": b64e(password_key(password, kdf))}


DUMMY_HASH = hash_password("timing-equaliser")


def check_password(record: dict | None, password: str) -> bool:
    # Unknown users are checked against a dummy hash, so response time doesn't reveal which emails have accounts.
    record = record or DUMMY_HASH
    return hmac.compare_digest(password_key(password, record["kdf"]), b64d(record["hash"])) and record is not DUMMY_HASH


def seal_secrets(secrets: dict, passphrase: str) -> dict:
    """Encrypt a dict of byte strings under a passphrase. The KDF parameters are the AAD, so they can't be quietly weakened."""
    kdf = new_kdf()
    body = canon({k: b64e(v) for k, v in secrets.items()})
    return {"kdf": kdf, "sealed": b64e(seal(password_key(passphrase, kdf), body, canon(kdf)))}


def open_secrets(store: dict, passphrase: str) -> dict:
    body = unseal(password_key(passphrase, store["kdf"]), b64d(store["sealed"]), canon(store["kdf"]), "master key (wrong passphrase?)")
    return {k: b64d(v) for k, v in json.loads(body).items()}


# ---------- the system key pair ----------

def new_system_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def private_der(key) -> bytes:
    return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_private_der(der: bytes):
    return serialization.load_der_private_key(der, password=None)


def public_pem(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public_pem(pem: bytes):
    return serialization.load_pem_public_key(pem)


# ---------- hybrid encryption: key wrapping and key separation ----------

def wrap_key(file_key: bytes, public_key) -> bytes:
    return public_key.encrypt(file_key, OAEP)


def unwrap_key(wrapped: bytes, private_key) -> bytes:
    try:
        return private_key.decrypt(wrapped, OAEP)
    except ValueError:
        raise CryptoError("could not unwrap the file key") from None


def derive(secret: bytes, label: str, salt: bytes | None = None) -> bytes:
    """HKDF: one secret -> many independent keys, one per purpose (key separation)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"CryptoVault v3 " + label.encode()).derive(secret)


def mac(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def mac_ok(key: bytes, data: bytes, tag: str) -> bool:
    return hmac.compare_digest(mac(key, data), tag)


# ---------- streaming authenticated encryption (STREAM, Hoang et al. 2015) ----------

def _stream_nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= 2**32:
        raise CryptoError("file too large for the 32-bit segment counter")
    return prefix + struct.pack(">IB", counter, last)


def encrypt_stream(key: bytes, prefix: bytes, aad: bytes, chunks):
    """Yield one ciphertext segment per CHUNK of plaintext. Each nonce encodes the segment's
    position and whether it is the final one, so segments cannot be reordered, dropped,
    duplicated or truncated without detection."""
    aead, chunks = AESGCM(key), iter(chunks)
    counter, chunk = 0, next(chunks, b"")
    while True:
        nxt = next(chunks, None)
        last = nxt is None
        if not last and len(chunk) != CHUNK:
            raise ValueError("every segment except the last must be exactly CHUNK bytes")
        yield aead.encrypt(_stream_nonce(prefix, counter, last), chunk, aad)
        if last:
            return
        counter, chunk = counter + 1, nxt


def decrypt_stream(key: bytes, prefix: bytes, aad: bytes, src):
    """Yield verified plaintext segments read from the file object `src`."""
    aead = AESGCM(key)
    counter, seg = 0, src.read(CHUNK + TAG)
    while True:
        nxt = src.read(CHUNK + TAG)
        try:
            plaintext = aead.decrypt(_stream_nonce(prefix, counter, not nxt), seg, aad)
        except InvalidTag:
            raise CryptoError(f"segment {counter} failed authentication (tampered, reordered or truncated)") from None
        yield plaintext
        if not nxt:
            return
        counter, seg = counter + 1, nxt


# ---------- user key pairs: Ed25519 signatures and X25519 sealed boxes ----------

def new_user_keys() -> dict:
    """Raw 32-byte private keys: "sign" (Ed25519) and "box" (X25519, for receiving sealed boxes)."""
    return {"sign": ed25519.Ed25519PrivateKey.generate().private_bytes_raw(),
            "box": x25519.X25519PrivateKey.generate().private_bytes_raw()}


def public_keys(keys: dict) -> dict:
    return {"sign": b64e(ed25519.Ed25519PrivateKey.from_private_bytes(keys["sign"]).public_key().public_bytes_raw()),
            "box": b64e(x25519.X25519PrivateKey.from_private_bytes(keys["box"]).public_key().public_bytes_raw())}


def sign(private: bytes, data: bytes) -> str:
    return b64e(ed25519.Ed25519PrivateKey.from_private_bytes(private).sign(data))


def verify(public: str, data: bytes, signature: str) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(b64d(public)).verify(b64d(signature), data)
        return True
    except InvalidSignature:
        return False


def fingerprint(public: str) -> str:
    """Short, human-comparable form of a public key."""
    h = hashlib.sha256(b64d(public)).hexdigest()[:20]
    return " ".join(h[i:i + 4] for i in range(0, 20, 4))


def _box_key(shared: bytes, eph: bytes, recipient: bytes) -> bytes:
    return derive(shared, "sealed box", eph + recipient)  # both public keys as salt bind the key to this exchange


def seal_to(public: str, plaintext: bytes, aad: bytes) -> dict:
    """Sealed box (ECIES): a fresh ephemeral X25519 key agrees a secret with the recipient's
    public key, HKDF turns it into an AES key. Only the recipient's private key can open it."""
    eph, recipient = x25519.X25519PrivateKey.generate(), b64d(public)
    eph_pub = eph.public_key().public_bytes_raw()
    key = _box_key(eph.exchange(x25519.X25519PublicKey.from_public_bytes(recipient)), eph_pub, recipient)
    return {"eph": b64e(eph_pub), "box": b64e(seal(key, plaintext, aad))}


def open_box(private: bytes, box: dict, aad: bytes) -> bytes:
    me, eph = x25519.X25519PrivateKey.from_private_bytes(private), b64d(box["eph"])
    key = _box_key(me.exchange(x25519.X25519PublicKey.from_public_bytes(eph)), eph, me.public_key().public_bytes_raw())
    return unseal(key, b64d(box["box"]), aad, "sealed box")


# ---------- Shamir secret sharing ----------

SHAMIR_P = 2**521 - 1  # a Mersenne prime, comfortably larger than a 256-bit secret


def split(secret: bytes, k: int, n: int) -> list:
    """Hide the secret in f(0) of a random polynomial of degree k-1; share x is (x, f(x)).
    Any k points fix the polynomial. Any k-1 points fit EVERY possible secret equally well,
    so they reveal nothing at all (information-theoretic, not just computationally hard)."""
    coeffs = [int.from_bytes(secret, "big")] + [randbelow(SHAMIR_P) for _ in range(k - 1)]
    return [(x, sum(c * pow(x, i, SHAMIR_P) for i, c in enumerate(coeffs)) % SHAMIR_P) for x in range(1, n + 1)]


def combine(shares) -> bytes:
    """Lagrange interpolation at x = 0 recovers f(0)."""
    secret = 0
    for xi, yi in shares:
        num = den = 1
        for xj, _ in shares:
            if xj != xi:
                num = num * -xj % SHAMIR_P
                den = den * (xi - xj) % SHAMIR_P
        secret = (secret + yi * num * pow(den, -1, SHAMIR_P)) % SHAMIR_P
    if secret.bit_length() > 256:
        raise CryptoError("shares don't combine to a valid secret (too few, or wrong ones)")
    return secret.to_bytes(32, "big")
