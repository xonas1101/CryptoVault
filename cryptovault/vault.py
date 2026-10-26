"""The on-disk vault: users, the .cvault container format, and file operations.

    vault/
      users/<name>.pub.json   public keys (encryption + signing); not secret
      users/<name>.key.json   private keys, sealed with the user's password
      files/<id>.cvault       encrypted files

.cvault layout:
    "CVLT2" | u32 len | header (JSON) | u32 len | metadata ciphertext | STREAM segments...

    header   = {file_id, nonce_prefix, meta_nonce, recipients: {user: RSA-OAEP(file_key)}}
    metadata = {name, size, sha256, owner, created, file_id, signature}   (AES-GCM, meta key)

Everything in the header except `recipients` is the AAD for every AES-GCM call, so it
cannot be changed. `recipients` is left out of the AAD so that files can be shared
by adding a wrapped key without re-encrypting the data.
"""
import hashlib
import json
import os
import re
import struct
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import chain
from pathlib import Path

from . import crypto
from .crypto import CHUNK, CryptoError, b64d, b64e, canon

MAGIC = b"CVLT2"
NAME_RE = re.compile(r"[a-z0-9_-]{1,32}")
ID_RE = re.compile(r"[0-9a-f]{1,32}")
HEADER_KEYS = {"file_id", "nonce_prefix", "meta_nonce", "recipients"}
META_KEYS = {"name", "size", "sha256", "owner", "created"}
MAX_BLOCK = 1 << 20  # sanity limit on header/metadata size, checked before reading untrusted lengths


class VaultError(Exception):
    """The request or the vault is invalid (not a cryptographic failure)."""


class AccessDenied(VaultError):
    pass


@dataclass
class OpenFile:
    path: Path
    stream: object    # file object positioned at the first data segment
    header: dict
    meta: dict        # decrypted, signature-verified metadata
    file_key: bytes
    data_key: bytes
    sign_key: object  # the caller's signing key


# ---------- container helpers ----------

def _aad(header: dict) -> bytes:
    return MAGIC + canon({k: v for k, v in header.items() if k != "recipients"})


def _block(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _read_exact(f, n: int) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise VaultError("corrupted file (truncated header)")
    return data


def _read_block(f) -> bytes:
    (n,) = struct.unpack(">I", _read_exact(f, 4))
    if n > MAX_BLOCK:
        raise VaultError("corrupted file (oversized block)")
    return _read_exact(f, n)


def _read_container(f):
    """Parse magic, header and metadata ciphertext, leaving f at the first data segment."""
    if f.read(len(MAGIC)) != MAGIC:
        raise VaultError("not a CryptoVault v2 file")
    try:
        header = json.loads(_read_block(f))
    except ValueError:
        raise VaultError("corrupted file (bad header)") from None
    if not isinstance(header, dict) or set(header) != HEADER_KEYS or not isinstance(header["recipients"], dict):
        raise VaultError("corrupted file (bad header)")
    return header, _read_block(f)


def _write_atomic(path: Path, chunks, mode=0o600):
    """Write to a temp file and rename it only if every chunk was produced without error.
    For decryption this means unverified plaintext is never left behind."""
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".cv-tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            for chunk in chunks:
                f.write(chunk)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def _rewrite_header(path: Path, header: dict):
    """Replace the header only. Metadata and data segments are copied byte for byte."""
    with open(path, "rb") as f:
        _, meta_ct = _read_container(f)
        rest = iter(lambda: f.read(CHUNK), b"")
        _write_atomic(path, chain([MAGIC, _block(canon(header)), _block(meta_ct)], rest), 0o644)


class Vault:
    def __init__(self, root):
        self.root = Path(root)
        self.users_dir = self.root / "users"
        self.files_dir = self.root / "files"

    # ---------- users ----------

    def add_user(self, name: str, password: str) -> str:
        if not NAME_RE.fullmatch(name):
            raise VaultError("user names are 1-32 characters of a-z, 0-9, _ and -")
        if len(password) < 8:
            raise VaultError("password must be at least 8 characters")
        self.users_dir.mkdir(parents=True, exist_ok=True)
        if (self.users_dir / f"{name}.pub.json").exists():
            raise VaultError(f"user {name!r} already exists")
        enc, sign = crypto.new_identity()
        _write_atomic(self.users_dir / f"{name}.key.json", [canon(crypto.seal_keystore(enc, sign, password.encode()))])
        _write_atomic(self.users_dir / f"{name}.pub.json", [canon(crypto.public_pems(enc, sign))], 0o644)
        return self.fingerprint(name)

    def users(self) -> list[str]:
        return sorted(p.name.removesuffix(".pub.json") for p in self.users_dir.glob("*.pub.json"))

    def _pub(self, name: str) -> dict:
        path = self.users_dir / f"{name}.pub.json"
        if not NAME_RE.fullmatch(name) or not path.exists():
            raise VaultError(f"no such user: {name}")
        return json.loads(path.read_text())

    def public_keys(self, name: str):
        return crypto.load_public(self._pub(name))

    def fingerprint(self, name: str) -> str:
        return crypto.fingerprint(self._pub(name))

    def unlock(self, name: str, password: str):
        self._pub(name)  # validates the name before it is used in a path
        store = json.loads((self.users_dir / f"{name}.key.json").read_text())
        return crypto.open_keystore(store, password.encode())

    def change_password(self, name: str, old: str, new: str):
        """Only the keystore is re-encrypted. Files are untouched because they are bound to the RSA key, not the password."""
        if len(new) < 8:
            raise VaultError("password must be at least 8 characters")
        enc, sign = self.unlock(name, old)
        _write_atomic(self.users_dir / f"{name}.key.json", [canon(crypto.seal_keystore(enc, sign, new.encode()))])

    # ---------- storing ----------

    def put(self, src, owner: str, password: str, share_with=()) -> str:
        _, sign_key = self.unlock(owner, password)
        src = Path(src)
        # ponytail: the file is read twice (hash, then encrypt). If it changes in between, `get` reports a hash mismatch.
        with open(src, "rb") as f:
            digest = hashlib.file_digest(f, "sha256").hexdigest()
        meta = {"name": src.name, "size": src.stat().st_size, "sha256": digest,
                "owner": owner, "created": int(time.time())}
        with open(src, "rb") as f:
            return self._store(iter(lambda: f.read(CHUNK), b""), meta, sign_key, {owner, *share_with})

    def _store(self, chunks, meta: dict, sign_key, recipients) -> str:
        """The hybrid encryption itself: a fresh random key encrypts the data, and RSA wraps that key for each recipient."""
        enc_pubs = {r: self.public_keys(r)[0] for r in sorted(recipients)}  # fail on unknown users before doing any work
        file_key, file_id = os.urandom(32), os.urandom(16)
        data_key, meta_key = crypto.subkeys(file_key, file_id)
        header = {
            "file_id": b64e(file_id),
            "nonce_prefix": b64e(os.urandom(crypto.PREFIX)),
            "meta_nonce": b64e(os.urandom(12)),
            "recipients": {r: b64e(crypto.wrap_key(file_key, pub)) for r, pub in enc_pubs.items()},
        }
        aad = _aad(header)
        meta = {**meta, "file_id": header["file_id"]}
        meta["signature"] = b64e(sign_key.sign(canon(meta)))  # sign-then-encrypt: outsiders can't even see who signed
        meta_ct = crypto.seal(meta_key, b64d(header["meta_nonce"]), canon(meta), aad)
        segments = crypto.encrypt_stream(data_key, b64d(header["nonce_prefix"]), aad, chunks)
        self.files_dir.mkdir(parents=True, exist_ok=True)
        _write_atomic(self.files_dir / f"{file_id.hex()}.cvault",
                      chain([MAGIC, _block(canon(header)), _block(meta_ct)], segments), 0o644)
        return file_id.hex()

    # ---------- opening ----------

    def _resolve(self, ref: str) -> Path:
        """Find a file by its id or any unique prefix of it (like git commit hashes)."""
        ref = ref.lower()
        matches = list(self.files_dir.glob(f"{ref}*.cvault")) if ID_RE.fullmatch(ref) else []
        if len(matches) != 1:
            raise VaultError(f"id {ref!r} is ambiguous" if matches else f"no file with id {ref!r}")
        return matches[0]

    def _unlock_file(self, f, user: str, enc_key):
        header, meta_ct = _read_container(f)
        if user not in header["recipients"]:
            raise AccessDenied("access denied: you are not a recipient of this file")
        file_key = crypto.unwrap_key(b64d(header["recipients"][user]), enc_key)
        data_key, meta_key = crypto.subkeys(file_key, b64d(header["file_id"]))
        try:
            meta = json.loads(crypto.unseal(meta_key, b64d(header["meta_nonce"]), meta_ct, _aad(header), "metadata"))
        except ValueError:
            raise CryptoError("metadata is malformed") from None
        self._check_signature(header, meta)
        return header, meta, file_key, data_key

    def _check_signature(self, header: dict, meta: dict):
        """Every recipient knows the file key and could forge contents. Only the owner's signature proves where a file came from."""
        signed = {k: v for k, v in meta.items() if k != "signature"}
        if set(signed) != META_KEYS | {"file_id"} or signed["file_id"] != header["file_id"]:
            raise CryptoError("metadata is malformed or belongs to another file")
        crypto.verify(self.public_keys(meta["owner"])[1], b64d(meta.get("signature", "")), canon(signed))

    @contextmanager
    def _open(self, ref: str, user: str, password: str):
        enc_key, sign_key = self.unlock(user, password)
        path = self._resolve(ref)
        with open(path, "rb") as f:
            header, meta, file_key, data_key = self._unlock_file(f, user, enc_key)
            yield OpenFile(path, f, header, meta, file_key, data_key, sign_key)

    def _plaintext(self, o: OpenFile):
        """Yield decrypted segments. Raise at the end if the size or hash differ from the signed metadata."""
        h, size = hashlib.sha256(), 0
        for chunk in crypto.decrypt_stream(o.data_key, b64d(o.header["nonce_prefix"]), _aad(o.header), o.stream):
            h.update(chunk)
            size += len(chunk)
            yield chunk
        if size != o.meta["size"] or h.hexdigest() != o.meta["sha256"]:
            raise CryptoError("content does not match the owner's signed hash")

    # ---------- file operations ----------

    def ls(self, user: str, password: str) -> list[dict]:
        enc_key, _ = self.unlock(user, password)
        rows = []
        for path in self.files_dir.glob("*.cvault"):
            with open(path, "rb") as f:
                try:
                    header, meta, _, _ = self._unlock_file(f, user, enc_key)
                except AccessDenied:
                    continue
                except (VaultError, CryptoError) as e:
                    rows.append({"id": path.stem, "error": str(e), "created": 0})
                    continue
            rows.append({"id": path.stem, **meta, "recipients": sorted(header["recipients"])})
        return sorted(rows, key=lambda r: r["created"])

    def get(self, ref: str, user: str, password: str, out=None):
        with self._open(ref, user, password) as o:
            out = Path(out) if out else Path(Path(o.meta["name"]).name or "unnamed")
            if out.exists():
                raise VaultError(f"{out} already exists; choose another output path")
            _write_atomic(out, self._plaintext(o))
            return out, o.meta

    def verify(self, ref: str, user: str, password: str) -> dict:
        with self._open(ref, user, password) as o:
            for _ in self._plaintext(o):
                pass
            return o.meta

    def share(self, ref: str, user: str, password: str, targets):
        """Wrap the existing file key for more users. The data is not re-encrypted, which is the hybrid design paying off."""
        with self._open(ref, user, password) as o:
            for t in targets:
                o.header["recipients"][t] = b64e(crypto.wrap_key(o.file_key, self.public_keys(t)[0]))
        _rewrite_header(o.path, o.header)

    def revoke(self, ref: str, user: str, password: str, targets) -> str:
        """Remove recipients by re-encrypting under a new file key. Deleting their wrapped key
        is not enough, because they may have kept a copy of the old key. Only the owner can do
        this, since the new metadata has to be signed again."""
        with self._open(ref, user, password) as o:
            if o.meta["owner"] != user:
                raise AccessDenied("only the owner can revoke access")
            if user in targets:
                raise VaultError("the owner cannot revoke their own access")
            missing = set(targets) - set(o.header["recipients"])
            if missing:
                raise VaultError(f"not recipients of this file: {', '.join(sorted(missing))}")
            base = {k: o.meta[k] for k in META_KEYS}
            new_id = self._store(self._plaintext(o), base, o.sign_key, set(o.header["recipients"]) - set(targets))
        o.path.unlink()
        return new_id

    def remove(self, ref: str, user: str, password: str):
        with self._open(ref, user, password) as o:
            if o.meta["owner"] != user:
                raise AccessDenied("only the owner can delete a file")
        o.path.unlink()
