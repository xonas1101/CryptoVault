"""The vault: system key, users, the .cvault container, access control and the audit log.

    vault/
      system.pub.pem      system public key (encrypting a file needs only this)
      system.key.json     system private key + MAC key, sealed with the master passphrase
      users.json          email -> scrypt password hash, protected by an HMAC
      audit.log           tamper-evident access log (HMAC hash chain)
      files/<id>.cvault   encrypted files

.cvault layout (version 3):
    "CVLT3" | u32 len | header (JSON) | u32 len | sealed metadata | STREAM segments...

    header   = {file_id, nonce_prefix, wrapped_key: RSA-OAEP(system public key, file_key)}
    metadata = {name, size, sha256, type, owner, created, shares: {email: {perm, until}}}

The whole header is the AAD for every AES-GCM call. The metadata, including the access
list, is encrypted and authenticated, so nobody can grant themselves access by editing
files on disk. Sharing re-seals only the metadata; the data segments are never touched.
"""
import hashlib
import io
import json
import mimetypes
import os
import re
import struct
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from itertools import chain
from pathlib import Path

from . import crypto
from .audit import AuditLog
from .crypto import CHUNK, TAG, CryptoError, b64d, b64e, canon

MAGIC = b"CVLT3"
EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}")
ID_RE = re.compile(r"[0-9a-f]{32}")
HEADER_KEYS = {"file_id", "nonce_prefix", "wrapped_key"}
PERMS = ("view", "download")
MAX_BLOCK = 1 << 20  # sanity limit on header/metadata size, checked before trusting a length field


class VaultError(Exception):
    """The request or the vault is invalid (not a cryptographic failure)."""


class AccessDenied(VaultError):
    pass


def normalize_email(email: str) -> str:
    email = email.strip().lower()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise VaultError("enter a valid email address")
    return email


@dataclass
class OpenFile:
    path: Path
    stream: object    # file object positioned at the first data segment
    header: dict
    meta: dict        # decrypted, authenticated metadata
    data_key: bytes
    meta_key: bytes
    perm: str = ""    # caller's permission: owner, download or view


# ---------- container helpers ----------

def _aad(header: dict) -> bytes:
    return MAGIC + canon(header)


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
    """Parse magic, header and sealed metadata, leaving f at the first data segment."""
    if f.read(len(MAGIC)) != MAGIC:
        raise VaultError("not a CryptoVault file")
    try:
        header = json.loads(_read_block(f))
    except ValueError:
        raise VaultError("corrupted file (bad header)") from None
    if not isinstance(header, dict) or set(header) != HEADER_KEYS or not ID_RE.fullmatch(str(header["file_id"])):
        raise VaultError("corrupted file (bad header)")
    return header, _read_block(f)


def _write_atomic(path: Path, chunks, mode=0o600):
    """Write to a temp file and rename it only if every chunk was produced without error."""
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


class Vault:
    def __init__(self, root):
        self.root = Path(root)
        self.files_dir = self.root / "files"
        # ponytail: one lock for all read-modify-write operations; per-file locks if contention ever matters
        self.lock = threading.Lock()
        self._private = None

    # ---------- the system key ----------

    def initialized(self) -> bool:
        return (self.root / "system.key.json").exists()

    def initialize(self, passphrase: str):
        if self.initialized():
            raise VaultError("this vault already exists")
        if len(passphrase) < 12:
            raise VaultError("the master passphrase must be at least 12 characters")
        self.files_dir.mkdir(parents=True, exist_ok=True)
        key = crypto.new_system_key()
        store = crypto.seal_secrets({"rsa": crypto.private_der(key), "mac": os.urandom(32)}, passphrase)
        _write_atomic(self.root / "system.key.json", [canon(store)])
        _write_atomic(self.root / "system.pub.pem", [crypto.public_pem(key)], 0o644)
        self.unlock(passphrase)
        self._save_users({})

    def unlock(self, passphrase: str):
        """Load the system private key into memory. Until this happens, nothing can be decrypted."""
        secrets = crypto.open_secrets(json.loads((self.root / "system.key.json").read_text()), passphrase)
        self._private = crypto.load_private_der(secrets["rsa"])
        self._public = self._private.public_key()
        if (self.root / "system.pub.pem").read_bytes() != crypto.public_pem(self._private):
            raise CryptoError("system.pub.pem does not match the system key (someone swapped it?)")
        self._users_key = crypto.derive(secrets["mac"], "users table")
        self.audit = AuditLog(self.root / "audit.log", crypto.derive(secrets["mac"], "audit log"))

    # ---------- users ----------

    def _load_users(self) -> dict:
        data = json.loads((self.root / "users.json").read_text())
        if not crypto.mac_ok(self._users_key, canon(data["users"]), data["mac"]):
            raise CryptoError("users.json has been tampered with")
        return data["users"]

    def _save_users(self, users: dict):
        _write_atomic(self.root / "users.json", [canon({"users": users, "mac": crypto.mac(self._users_key, canon(users))})])

    def has_users(self) -> bool:
        return bool(self._load_users())

    def register(self, email: str, password: str) -> str:
        email = normalize_email(email)
        if len(password) < 8:
            raise VaultError("password must be at least 8 characters")
        with self.lock:
            users = self._load_users()
            if email in users:
                raise VaultError("an account with this email already exists")
            users[email] = {**crypto.hash_password(password), "created": int(time.time())}
            self._save_users(users)
        self.audit.append(email, "register")
        return email

    def authenticate(self, email: str, password: str) -> str:
        email = email.strip().lower()
        if not crypto.check_password(self._load_users().get(email), password):
            self.audit.append(email, "login failed")
            raise AccessDenied("wrong email or password")
        self.audit.append(email, "login")
        return email

    # ---------- storing ----------

    def _subkeys(self, file_key: bytes, header: dict):
        """Independent keys for the data and the metadata, so the two can never collide on a nonce."""
        salt = bytes.fromhex(header["file_id"])
        return crypto.derive(file_key, "data", salt), crypto.derive(file_key, "metadata", salt)

    def store(self, owner: str, name: str, data: bytes) -> str:
        """Hybrid encryption: a fresh random key encrypts the data; RSA wraps that key.
        Only the system PUBLIC key is used here: encrypting never needs the private key."""
        name = Path(name).name or "unnamed"
        meta = {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "type": mimetypes.guess_type(name)[0] or "application/octet-stream",
                "owner": owner, "created": int(time.time()), "shares": {}}
        file_key = os.urandom(32)
        header = {"file_id": os.urandom(16).hex(), "nonce_prefix": b64e(os.urandom(crypto.PREFIX)),
                  "wrapped_key": b64e(crypto.wrap_key(file_key, self._public))}
        aad = _aad(header)
        data_key, meta_key = self._subkeys(file_key, header)
        chunks = (data[i:i + CHUNK] for i in range(0, len(data), CHUNK))
        segments = crypto.encrypt_stream(data_key, b64d(header["nonce_prefix"]), aad, chunks)
        _write_atomic(self._path(header["file_id"]),
                      chain([MAGIC, _block(canon(header)), _block(crypto.seal(meta_key, canon(meta), aad))], segments), 0o644)
        self.audit.append(owner, "upload", header["file_id"], name)
        return header["file_id"]

    # ---------- opening ----------

    def _path(self, fid: str) -> Path:
        if not ID_RE.fullmatch(fid or ""):
            raise VaultError("no such file")
        return self.files_dir / f"{fid}.cvault"

    @contextmanager
    def _open(self, fid: str):
        path = self._path(fid)
        if not path.exists():
            raise VaultError("this file no longer exists (its owner deleted it)")
        with open(path, "rb") as f:
            header, sealed_meta = _read_container(f)
            if header["file_id"] != fid:
                raise CryptoError("file was swapped with another file")
            file_key = crypto.unwrap_key(b64d(header["wrapped_key"]), self._private)
            data_key, meta_key = self._subkeys(file_key, header)
            meta = json.loads(crypto.unseal(meta_key, sealed_meta, _aad(header), "metadata"))
            yield OpenFile(path, f, header, meta, data_key, meta_key)

    def _permission(self, meta: dict, user: str) -> str:
        if user == meta["owner"]:
            return "owner"
        share = meta["shares"].get(user)
        if not share:
            raise AccessDenied("you don't have access to this file")
        if share["until"] and time.time() > share["until"]:
            raise AccessDenied("your access to this file has expired")
        return share["perm"]

    @contextmanager
    def _access(self, fid: str, user: str, need: str | None = None):
        """Open a file only if `user` may. Every refusal is written to the audit log."""
        with self._open(fid) as o:
            try:
                o.perm = self._permission(o.meta, user)
                if need == "owner" and o.perm != "owner":
                    raise AccessDenied("only the owner can do that")
                if need == "download" and o.perm == "view":
                    raise AccessDenied("the owner allowed viewing only, not downloading")
            except AccessDenied as e:
                self.audit.append(user, "denied", fid, str(e))
                raise
            yield o

    def _plaintext(self, o: OpenFile) -> bytes:
        # ponytail: whole file in memory; the web UI caps uploads at 100 MB, so this is bounded
        data = b"".join(crypto.decrypt_stream(o.data_key, b64d(o.header["nonce_prefix"]), _aad(o.header), o.stream))
        if len(data) != o.meta["size"] or hashlib.sha256(data).hexdigest() != o.meta["sha256"]:
            raise CryptoError("content does not match its recorded SHA-256")
        return data

    def _reseal(self, o: OpenFile):
        """Re-encrypt only the metadata, under a fresh nonce. The data segments are copied as-is."""
        sealed = crypto.seal(o.meta_key, canon(o.meta), _aad(o.header))
        rest = iter(lambda: o.stream.read(CHUNK), b"")
        _write_atomic(o.path, chain([MAGIC, _block(canon(o.header)), _block(sealed)], rest), 0o644)

    # ---------- what users can do ----------

    def files_for(self, user: str):
        """Return (files user owns, files shared with user, ids of files that failed verification)."""
        mine, shared, broken = [], [], []
        for path in self.files_dir.glob("*.cvault"):
            try:
                with self._open(path.stem) as o:
                    meta = o.meta
            except (VaultError, CryptoError):
                broken.append(path.stem)
                continue
            row = {"id": path.stem, **meta}
            if meta["owner"] == user:
                mine.append(row)
            elif user in meta["shares"]:
                share = meta["shares"][user]
                shared.append({**row, **share, "expired": bool(share["until"] and time.time() > share["until"])})
        newest = lambda r: -r["created"]
        return sorted(mine, key=newest), sorted(shared, key=newest), broken

    def read(self, fid: str, user: str, action: str | None = "view"):
        """Decrypt for a user. action is what gets logged: "view", "download", or None (e.g. extra preview pages)."""
        with self._access(fid, user, need="download" if action == "download" else None) as o:
            data = self._plaintext(o)
            if action:
                self.audit.append(user, action, fid)
            return data, o.meta, o.perm

    def locked_copy(self, fid: str, user: str):
        """The encrypted container itself. Useless outside the system, because only the system holds the key."""
        with self._access(fid, user) as o:
            self.audit.append(user, "download locked copy", fid)
            return o.path.read_bytes(), o.meta

    def resolve_locked(self, blob: bytes, user: str) -> str:
        """A downloaded .cvault works like a ticket: it opens the vault's CURRENT copy,
        so revocation, expiry and deletion still apply to copies people have taken."""
        header, _ = _read_container(io.BytesIO(blob))
        with self._access(header["file_id"], user):
            pass
        self.audit.append(user, "open locked copy", header["file_id"])
        return header["file_id"]

    def share(self, fid: str, owner: str, email: str, perm: str, until: float | None = None):
        email = normalize_email(email)
        if perm not in PERMS:
            raise VaultError("permission must be view or download")
        if until is not None and until < time.time():
            raise VaultError("the expiry date is in the past")
        with self.lock, self._access(fid, owner, need="owner") as o:
            if email == owner:
                raise VaultError("you already own this file")
            o.meta["shares"][email] = {"perm": perm, "until": until}
            self._reseal(o)
        detail = f"{email}: {perm}" + (time.strftime(", until %d %b %Y", time.localtime(until)) if until else "")
        self.audit.append(owner, "share", fid, detail)

    def revoke(self, fid: str, owner: str, email: str):
        """Users never hold file keys in this model, so removing them from the access list is
        enough. Nothing needs re-encrypting, and locked copies they downloaded stop opening."""
        with self.lock, self._access(fid, owner, need="owner") as o:
            if o.meta["shares"].pop(email, None) is None:
                raise VaultError(f"{email} doesn't have access")
            self._reseal(o)
        self.audit.append(owner, "revoke", fid, email)

    def delete(self, fid: str, owner: str):
        with self.lock:
            with self._access(fid, owner, need="owner") as o:
                pass
            o.path.unlink()
        self.audit.append(owner, "delete", fid, o.meta["name"])

    def activity(self, fid: str, owner: str):
        """The owner's view of the audit log for one file: (entries, first broken index or None)."""
        with self._access(fid, owner, need="owner"):
            pass
        entries, broken_at = self.audit.read()
        return [e for e in entries if e["file"] == fid], broken_at

    def inspect(self, fid: str, user: str) -> dict:
        """Raw view of a container, for teaching: what anyone with disk access sees."""
        with self._access(fid, user) as o:
            disk_size = o.path.stat().st_size
            o.stream.seek(0)
            _, sealed_meta = _read_container(o.stream)
            data_len = disk_size - o.stream.tell()
            return {"file": o.path.name, "disk_size": disk_size, "header": o.header, "sealed_meta": sealed_meta,
                    "data_len": data_len, "data_head": o.stream.read(48),
                    "segments": max(1, -(-data_len // (CHUNK + TAG)))}
