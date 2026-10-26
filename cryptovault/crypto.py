"""Cryptographic primitives for CryptoVault.

Every security-critical operation lives in this one module so it can be reviewed
in one place. Nothing here touches the filesystem.

  keystore        scrypt (password -> key) + AES-256-GCM protects a user's private keys
  key wrapping    RSA-3072-OAEP-SHA256 encrypts a per-file key for each recipient
  key separation  HKDF-SHA256 splits the file key into independent sub-keys
  streaming       AES-256-GCM in the STREAM construction, for files of any size
  signatures      Ed25519 proves who stored a file
"""
import base64
import hashlib
import json
import os
import struct

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

RSA_BITS = 3072                      # ~128-bit security (NIST SP 800-57)
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
SCRYPT = {"n": 2**15, "r": 8, "p": 1}  # 32 MiB of memory per password guess
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
    """Canonical JSON: the same object always gives the same bytes (required before signing or using as AAD)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------- single-shot AEAD ----------

def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes, what: str) -> bytes:
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except (InvalidTag, ValueError):
        raise CryptoError(f"{what} failed authentication (tampered or wrong key)") from None


# ---------- identities and the password-protected keystore ----------

def new_identity():
    """Each user gets two key pairs: RSA for encryption, Ed25519 for signing.
    Using one key for both jobs is a classic mistake, since the two uses can interfere."""
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS), ed25519.Ed25519PrivateKey.generate()


def public_pems(enc_key, sign_key) -> dict:
    def pem(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return {"enc": pem(enc_key), "sign": pem(sign_key)}


def load_public(pems: dict):
    return (serialization.load_pem_public_key(pems["enc"].encode()),
            serialization.load_pem_public_key(pems["sign"].encode()))


def fingerprint(pems: dict) -> str:
    """Short hash of a user's public keys. Compare it out-of-band to detect a swapped key (like SSH fingerprints)."""
    digest = hashlib.sha256(canon(pems)).hexdigest()[:32]
    return ":".join(digest[i:i + 4] for i in range(0, 32, 4))


def _password_key(password: bytes, kdf: dict) -> bytes:
    return Scrypt(salt=b64d(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(password)


def seal_keystore(enc_key, sign_key, password: bytes) -> dict:
    """Encrypt both private keys under a key derived from the password.
    The KDF parameters are the AAD, so nobody can quietly weaken them."""
    def der(key):
        return key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    kdf = {"name": "scrypt", "salt": b64e(os.urandom(16)), **SCRYPT}
    nonce = os.urandom(12)
    secret = canon({"enc": b64e(der(enc_key)), "sign": b64e(der(sign_key))})
    ct = seal(_password_key(password, kdf), nonce, secret, canon(kdf))
    return {"kdf": kdf, "nonce": b64e(nonce), "ciphertext": b64e(ct)}


def open_keystore(store: dict, password: bytes):
    kdf = store["kdf"]
    secret = json.loads(unseal(_password_key(password, kdf), b64d(store["nonce"]),
                               b64d(store["ciphertext"]), canon(kdf), "keystore (wrong password?)"))
    return tuple(serialization.load_der_private_key(b64d(secret[k]), password=None) for k in ("enc", "sign"))


# ---------- hybrid encryption: key wrapping and key separation ----------

def wrap_key(file_key: bytes, enc_public) -> bytes:
    return enc_public.encrypt(file_key, OAEP)


def unwrap_key(wrapped: bytes, enc_private) -> bytes:
    try:
        return enc_private.decrypt(wrapped, OAEP)
    except ValueError:
        raise CryptoError("could not unwrap the file key") from None


def subkeys(file_key: bytes, file_id: bytes) -> tuple[bytes, bytes]:
    """HKDF turns one random file key into independent keys for the data and for the metadata,
    so the two never share a (key, nonce) space."""
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=file_id, info=b"CryptoVault v2 data|meta").derive(file_key)
    return okm[:32], okm[32:]


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


# ---------- signatures ----------

def verify(sign_public, signature: bytes, data: bytes):
    try:
        sign_public.verify(signature, data)
    except InvalidSignature:
        raise CryptoError("signature invalid: this file was not stored by its claimed owner") from None
