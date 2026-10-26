"""The vault: system key, users, the .cvault container, access control and the audit log.

    vault/
      system.pub.pem      system public key (encrypting a file needs only this)
      system.key.json     system private key + MAC key, sealed with the master passphrase
      users.json          email -> scrypt password hash, public keys, sealed private keys; HMAC-protected
      audit.log           tamper-evident access log (HMAC hash chain)
      keys/<id>.key       each file's key K, wrapped with RSA-OAEP under the system public key
      files/<id>.cvault   encrypted files

.cvault layout (version 5):
    "CVLT5" | u32 len | header (JSON) | u32 len | sealed metadata | STREAM segments...

    header   = {file_id, nonce_prefix, layers: the protection layers the owner picked,
                kdf: scrypt params or null}
    metadata = {name, size, digest, type, owner, created, destroy_at, shares: {email: {perm, until}},
                signature, check (password layer), quorum (quorum layer)}

The whole header is the AAD for every AES-GCM call. The metadata, including the access
list, is encrypted and authenticated, so nobody can grant themselves access by editing
files on disk. Sharing re-seals only the metadata; the data segments are never touched.

K lives in keys/, never in the .cvault file. So a downloaded or backed-up .cvault contains no
key at all, deleting the small key file destroys every copy of the data (crypto-shredding),
and rotating the system key re-wraps only the key files.

Protection layers (each file picks its own; at least one of the first three holds the key):
    system    the content key comes from K, so the server can open the file by itself
    password  the content key also needs scrypt(file password)
    quorum    the content key also needs a secret split with Shamir's scheme: k of n named
              approvers must release their shares, each encrypted to that approver's key
    cascade   the data is first encrypted with ChaCha20-Poly1305, then with AES-256-GCM,
              under independent keys: breaking one cipher is not enough
    lockdown  view-only for everyone, owner included: the original can never be downloaded
Every key-holding layer that is ticked is REQUIRED. The metadata is always sealed under K, so
the server can still list files and enforce access lists. The layer list sits in the
authenticated header, so it can't be stripped.
"""
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

MAGIC = b"CVLT5"
EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}")
ID_RE = re.compile(r"[0-9a-f]{32}")
HEADER_KEYS = {"file_id", "nonce_prefix", "layers", "kdf"}
LAYERS = ("system", "password", "quorum", "cascade", "lockdown")
KEY_LAYERS = {"system", "password", "quorum"}
SIGNED = ("name", "size", "type", "owner", "created", "digest")
PERMS = ("view", "download")
MAX_APPROVERS = 10
MAX_BLOCK = 1 << 20  # sanity limit on header/metadata size, checked before trusting a length field


class VaultError(Exception):
    """The request or the vault is invalid (not a cryptographic failure)."""


class AccessDenied(VaultError):
    pass


class PasswordRequired(AccessDenied):
    """The file has a password layer and no unlocked key was supplied."""


class QuorumRequired(AccessDenied):
    """The file has a quorum layer and not enough approvers have released their shares."""

    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


class Destroyed(VaultError):
    """The file's key has been destroyed."""


def normalize_email(email: str) -> str:
    email = email.strip().lower()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise VaultError(f"enter a valid email address (got {email[:60]!r})")
    return email


@dataclass
class OpenFile:
    path: Path
    stream: object    # file object positioned at the first data segment
    header: dict
    meta: dict        # decrypted, authenticated metadata
    file_key: bytes
    meta_key: bytes
    perm: str = ""    # caller's permission: owner, download or view


# ---------- container helpers ----------

def _aad(header: dict) -> bytes:
    return MAGIC + canon(header)


def _share_aad(fid: str, email: str) -> bytes:
    return f"quorum share|{fid}|{email}".encode()  # a share only opens for its own file and approver


def _signed(header: dict, meta: dict) -> bytes:
    """What the owner signs: the header (id, layers, nonce prefix) and the content's identity."""
    return canon({"header": header, **{k: meta[k] for k in SIGNED}})


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
    if (not isinstance(header, dict) or set(header) != HEADER_KEYS or not ID_RE.fullmatch(str(header["file_id"]))
            or not isinstance(header["layers"], list) or not set(header["layers"]) <= set(LAYERS)):
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
    approval_ttl = 60 * 60  # seconds an approval stays valid

    def __init__(self, root):
        self.root = Path(root)
        self.files_dir = self.root / "files"
        self.keys_dir = self.root / "keys"
        # ponytail: one lock for all read-modify-write operations; per-file locks if contention ever matters
        self.lock = threading.Lock()
        self._private = self._old = None
        # Released quorum shares live only in memory: a restart or the TTL wipes them, they never touch disk.
        self._approvals = {}  # file id -> {approver: (x, y, valid until)}

    # ---------- the system key ----------

    def initialized(self) -> bool:
        return (self.root / "system.key.json").exists()

    def initialize(self, passphrase: str):
        if self.initialized():
            raise VaultError("this vault already exists")
        if len(passphrase) < 12:
            raise VaultError("the master passphrase must be at least 12 characters")
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.keys_dir.mkdir(exist_ok=True)
        key = crypto.new_system_key()
        self._save_keystore({"rsa": crypto.private_der(key), "mac": os.urandom(32)}, passphrase)
        _write_atomic(self.root / "system.pub.pem", [crypto.public_pem(key)], 0o644)
        self.unlock(passphrase)
        self._save_users({})

    def _save_keystore(self, secrets: dict, passphrase: str):
        _write_atomic(self.root / "system.key.json", [canon(crypto.seal_secrets(secrets, passphrase))])

    def unlock(self, passphrase: str):
        """Load the system private key into memory. Until this happens, nothing can be decrypted."""
        secrets = crypto.open_secrets(json.loads((self.root / "system.key.json").read_text()), passphrase)
        self._private = crypto.load_private_der(secrets["rsa"])
        self._public = self._private.public_key()
        self._old = secrets.get("rsa_old") and crypto.load_private_der(secrets["rsa_old"])
        self._users_key = crypto.derive(secrets["mac"], "users table")
        self.audit = AuditLog(self.root / "audit.log", crypto.derive(secrets["mac"], "audit log"))
        if self._old:  # a key rotation started (and may have been interrupted): finish it
            for path in self.keys_dir.glob("*.key"):
                _write_atomic(path, [crypto.wrap_key(self._unwrap(path.read_bytes()), self._public)])
            _write_atomic(self.root / "system.pub.pem", [crypto.public_pem(self._private)], 0o644)
            self._save_keystore({"rsa": secrets["rsa"], "mac": secrets["mac"]}, passphrase)
            self._old = None  # the old private key is gone for good
        elif (self.root / "system.pub.pem").read_bytes() != crypto.public_pem(self._private):
            raise CryptoError("system.pub.pem does not match the system key (someone swapped it?)")

    def rotate_key(self, passphrase: str) -> int:
        """Replace the system RSA key. Only the small key files are re-wrapped: no .cvault file
        changes. Afterwards the old private key no longer exists anywhere, so backups of keys/
        (including keys of files shredded since) can never be unwrapped again.

        Crash-safe: the new key is saved alongside the old one first, and unlock() does the
        re-wrapping. If the process dies half-way, the next start simply finishes the job."""
        with self.lock:
            old = crypto.open_secrets(json.loads((self.root / "system.key.json").read_text()), passphrase)
            new = crypto.private_der(crypto.new_system_key())
            self._save_keystore({"rsa": new, "rsa_old": old["rsa"], "mac": old["mac"]}, passphrase)
            self.unlock(passphrase)
        n = len(list(self.keys_dir.glob("*.key")))
        self.audit.append("system", "rotate key", None, f"{n} file keys re-wrapped")
        return n

    def _unwrap(self, wrapped: bytes) -> bytes:
        for key in filter(None, (self._private, self._old)):
            try:
                return crypto.unwrap_key(wrapped, key)
            except CryptoError:
                pass
        raise CryptoError("could not unwrap the file key")

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
        """Each user gets an Ed25519 signing key and an X25519 key for receiving quorum shares.
        The private halves are sealed with the user's password, so the server can't use them
        while the user is logged out."""
        email = normalize_email(email)
        if len(password) < 8:
            raise VaultError("password must be at least 8 characters")
        keys = crypto.new_user_keys()
        record = {**crypto.hash_password(password), "created": int(time.time()),
                  "public": crypto.public_keys(keys), "keys": crypto.seal_secrets(keys, password)}
        with self.lock:
            users = self._load_users()
            if email in users:
                raise VaultError("an account with this email already exists")
            users[email] = record
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

    def user_keys(self, email: str, password: str) -> dict:
        """Unseal a user's private keys with their password (done once, at login)."""
        try:
            return crypto.open_secrets(self._load_users()[email]["keys"], password)
        except (KeyError, CryptoError):
            raise AccessDenied("wrong email or password") from None

    def public_key(self, email: str, kind: str = "sign") -> str:
        user = self._load_users().get(email)
        if not user:
            raise VaultError(f"{email} has no account yet")
        return user["public"][kind]

    def fingerprint(self, email: str) -> str:
        return crypto.fingerprint(self.public_key(email))

    # ---------- storing ----------

    @staticmethod
    def _meta_key(file_key: bytes, fid: str) -> bytes:
        return crypto.derive(file_key, "metadata", bytes.fromhex(fid))

    @staticmethod
    def _content_keys(file_key: bytes, header: dict, pw_key: bytes | None, q: bytes | None = None) -> dict:
        """Independent keys for each job, derived from whichever secrets the file's layers name.
        Every secret is exactly 32 bytes, so their concatenation is unambiguous."""
        layers = header["layers"]
        base = (file_key if "system" in layers else b"") + ((pw_key or b"") if "password" in layers else b"")
        ikm = base + ((q or b"") if "quorum" in layers else b"")
        salt = bytes.fromhex(header["file_id"])
        keys = {label: crypto.derive(ikm, label, salt) for label in ("data", "cascade", "digest")}
        if "password" in layers:  # independent of the quorum secret, which may not be released yet
            keys["check"] = crypto.derive(base, "check", salt)
        return keys

    def store(self, owner: str, name: str, data: bytes, layers=("system",), password: str | None = None, *,
              signer: bytes, approvers=(), threshold: int = 0, destroy_at: float | None = None) -> str:
        """Hybrid encryption: a fresh random key encrypts the data; RSA wraps that key.
        Only the system PUBLIC key is used here: encrypting never needs the private key.
        `signer` is the owner's Ed25519 private key, from user_keys()."""
        layers = [x for x in LAYERS if x in layers]  # canonical order, unknown names dropped
        if not KEY_LAYERS & set(layers):
            raise VaultError("pick at least one key holder: the server key, a password or an approval quorum")
        if "password" in layers and len(password or "") < 8:
            raise VaultError("the file password must be at least 8 characters")
        if destroy_at is not None and destroy_at <= time.time():
            raise VaultError("the self-destruct time is in the past")
        if "quorum" in layers:
            approvers = sorted({normalize_email(a) for a in approvers})
            if not 1 <= threshold <= len(approvers) <= MAX_APPROVERS:
                raise VaultError(f"a quorum needs 1 to {MAX_APPROVERS} approvers and 1 ≤ k ≤ number of approvers")
            boxes = {a: self.public_key(a, "box") for a in approvers}  # approvers need an account: shares are encrypted to them
        fid = os.urandom(16).hex()
        kdf = crypto.new_kdf() if "password" in layers else None
        q = os.urandom(32) if "quorum" in layers else None
        name = Path(name).name or "unnamed"
        file_key = os.urandom(32)
        header = {"file_id": fid, "nonce_prefix": b64e(os.urandom(crypto.PREFIX)), "layers": layers, "kdf": kdf}
        aad = _aad(header)
        keys = self._content_keys(file_key, header, kdf and crypto.password_key(password, kdf), q)
        # a keyed digest, not a plain SHA-256: the server can read metadata, and a plain hash
        # would let it confirm guesses about the content of a password-only file
        meta = {"name": name, "size": len(data), "digest": crypto.mac(keys["digest"], data),
                "type": mimetypes.guess_type(name)[0] or "application/octet-stream",
                "owner": owner, "created": int(time.time()), "destroy_at": destroy_at, "shares": {}}
        meta["signature"] = crypto.sign(signer, _signed(header, meta))
        if kdf:
            meta["check"] = crypto.mac(keys["check"], b"password check")
        if q:
            meta["quorum"] = {"k": threshold, "shares": {
                a: crypto.seal_to(boxes[a], canon({"x": x, "y": format(y, "x")}), _share_aad(fid, a))
                for a, (x, y) in zip(approvers, crypto.split(q, threshold, len(approvers)))}}
        if "cascade" in layers:
            data = crypto.seal(keys["cascade"], data, aad, crypto.ChaCha20Poly1305)
        chunks = (data[i:i + CHUNK] for i in range(0, len(data), CHUNK))
        segments = crypto.encrypt_stream(keys["data"], b64d(header["nonce_prefix"]), aad, chunks)
        _write_atomic(self._key_path(fid), [crypto.wrap_key(file_key, self._public)])
        _write_atomic(self._path(fid), chain([MAGIC, _block(canon(header)),
                                              _block(crypto.seal(self._meta_key(file_key, fid), canon(meta), aad))], segments), 0o644)
        self.audit.append(owner, "upload", fid, f"{name} [{', '.join(layers)}]")
        return fid

    # ---------- opening ----------

    def _path(self, fid: str) -> Path:
        if not ID_RE.fullmatch(fid or ""):
            raise VaultError("no such file")
        return self.files_dir / f"{fid}.cvault"

    def _key_path(self, fid: str) -> Path:
        return self.keys_dir / f"{self._path(fid).stem}.key"

    def _shred(self, fid: str):
        """Crypto-shredding: destroy the key first. From that moment every copy of the ciphertext,
        in the vault, in backups or in downloaded locked copies, is permanently undecryptable."""
        self._key_path(fid).unlink(missing_ok=True)
        self._path(fid).unlink(missing_ok=True)
        self._approvals.pop(fid, None)

    @contextmanager
    def _open(self, fid: str):
        path, key_path = self._path(fid), self._key_path(fid)
        if not path.exists() or not key_path.exists():
            raise Destroyed("this file no longer exists: its key was destroyed")
        with open(path, "rb") as f:
            header, sealed_meta = _read_container(f)
            if header["file_id"] != fid:
                raise CryptoError("file was swapped with another file")
            file_key = self._unwrap(key_path.read_bytes())
            meta_key = self._meta_key(file_key, fid)
            meta = json.loads(crypto.unseal(meta_key, sealed_meta, _aad(header), "metadata"))
            if meta["destroy_at"] and time.time() >= meta["destroy_at"]:
                # ponytail: self-destruct happens on the next access or listing, not on a timer;
                # it can't be read after the deadline either way, a scheduler if the key must vanish on the dot
                self._shred(fid)
                self.audit.append("system", "self-destruct", fid, meta["name"])
                raise Destroyed("this file self-destructed: its key was destroyed")
            yield OpenFile(path, f, header, meta, file_key, meta_key)

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
                if need == "download" and "lockdown" in o.header["layers"]:
                    raise AccessDenied("this file is locked down: view-only for everyone, owner included")
                if need == "download" and o.perm == "view":
                    raise AccessDenied("the owner allowed viewing only, not downloading")
            except AccessDenied as e:
                self.audit.append(user, "denied", fid, str(e))
                raise
            yield o

    def _live_approvals(self, fid: str) -> dict:
        live = {a: v for a, v in self._approvals.get(fid, {}).items() if v[2] > time.time()}
        self._approvals[fid] = live
        return live

    def quorum_status(self, fid: str, meta: dict) -> dict:
        live = self._live_approvals(fid)
        return {"k": meta["quorum"]["k"], "approvers": {a: live[a][2] if a in live else None for a in meta["quorum"]["shares"]}}

    def _plaintext(self, o: OpenFile, pw_key: bytes | None) -> bytes:
        layers, fid = o.header["layers"], o.header["file_id"]
        if "password" in layers and not pw_key:
            raise PasswordRequired(f"{o.meta['name']} is password-locked")
        q = None
        if "quorum" in layers:
            live, k = self._live_approvals(fid), o.meta["quorum"]["k"]
            if len(live) < k:
                raise QuorumRequired(f"{o.meta['name']} needs {k} of {len(o.meta['quorum']['shares'])} approvals "
                                     f"({len(live)} so far)", self.quorum_status(fid, o.meta))
            q = crypto.combine([(x, y) for x, y, _ in live.values()][:k])
        keys, aad = self._content_keys(o.file_key, o.header, pw_key, q), _aad(o.header)
        # ponytail: whole file in memory; the web UI caps uploads at 100 MB, so this is bounded
        data = b"".join(crypto.decrypt_stream(keys["data"], b64d(o.header["nonce_prefix"]), aad, o.stream))
        if "cascade" in layers:
            data = crypto.unseal(keys["cascade"], data, aad, "inner ChaCha20-Poly1305 layer", crypto.ChaCha20Poly1305)
        if len(data) != o.meta["size"] or not crypto.mac_ok(keys["digest"], data, o.meta["digest"]):
            raise CryptoError("content does not match its recorded digest")
        owner_key = self._load_users().get(o.meta["owner"], {}).get("public", {}).get("sign")
        if not owner_key or not crypto.verify(owner_key, _signed(o.header, o.meta), o.meta["signature"]):
            raise CryptoError(f"the signature of {o.meta['owner']} does not verify: authorship or content was altered")
        return data

    def _reseal(self, o: OpenFile):
        """Re-encrypt only the metadata, under a fresh nonce. The data segments are copied as-is."""
        sealed = crypto.seal(o.meta_key, canon(o.meta), _aad(o.header))
        rest = iter(lambda: o.stream.read(CHUNK), b"")
        _write_atomic(o.path, chain([MAGIC, _block(canon(o.header)), _block(sealed)], rest), 0o644)

    # ---------- what users can do ----------

    def files_for(self, user: str):
        """Return (files user owns, files shared with user, ids of files that failed verification,
        files waiting for user's approval)."""
        mine, shared, broken, approvals = [], [], [], []
        for path in list(self.files_dir.glob("*.cvault")):
            try:
                with self._open(path.stem) as o:
                    meta = o.meta
            except Destroyed:
                continue
            except (VaultError, CryptoError):
                broken.append(path.stem)
                continue
            row = {"id": path.stem, **meta, "layers": o.header["layers"]}
            if user in meta.get("quorum", {}).get("shares", {}):
                approvals.append({**row, "status": self.quorum_status(path.stem, meta)})
            if meta["owner"] == user:
                mine.append(row)
            elif user in meta["shares"]:
                share = meta["shares"][user]
                shared.append({**row, **share, "expired": bool(share["until"] and time.time() > share["until"])})
        newest = lambda r: -r["created"]
        return sorted(mine, key=newest), sorted(shared, key=newest), broken, sorted(approvals, key=newest)

    def unlock_file(self, fid: str, user: str, password: str) -> bytes:
        """Check a file password and return the key derived from it, for passing to read()."""
        with self._access(fid, user) as o:
            if "password" not in o.header["layers"]:
                raise VaultError("this file has no password")
            pw_key = crypto.password_key(password, o.header["kdf"])
            # ponytail: no rate limit; scrypt makes each guess cost ~50 ms and every miss is logged
            if not crypto.mac_ok(self._content_keys(o.file_key, o.header, pw_key)["check"], b"password check", o.meta["check"]):
                self.audit.append(user, "denied", fid, "wrong file password")
                raise AccessDenied("wrong file password")
            return pw_key

    def approve(self, fid: str, user: str, box_key: bytes):
        """Release user's quorum share for approval_ttl seconds. Needs the approver's X25519
        private key, from user_keys(): the server can't approve on anyone's behalf.
        Approving doesn't grant access: the approver still needs to be on the access list to read."""
        with self._open(fid) as o:
            box = o.meta.get("quorum", {}).get("shares", {}).get(user)
            if not box:
                self.audit.append(user, "denied", fid, "not an approver")
                raise AccessDenied("you are not an approver for this file")
            share = json.loads(crypto.open_box(box_key, box, _share_aad(fid, user)))
        until = time.time() + self.approval_ttl
        self._live_approvals(fid)[user] = (share["x"], int(share["y"], 16), until)
        self.audit.append(user, "approve", fid, time.strftime("valid until %H:%M", time.localtime(until)))

    def read(self, fid: str, user: str, action: str | None = "view", pw_key: bytes | None = None):
        """Decrypt for a user. action is what gets logged: "view", "download", or None (e.g. extra preview pages).
        Password-locked files also need pw_key, from unlock_file()."""
        with self._access(fid, user, need="download" if action == "download" else None) as o:
            data = self._plaintext(o, pw_key)
            if action:
                self.audit.append(user, action, fid)
            return data, o.meta, o.perm

    def locked_copy(self, fid: str, user: str):
        """The encrypted container itself. It contains no key at all, so it's useless outside the system."""
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
            if perm == "download" and "lockdown" in o.header["layers"]:
                raise VaultError("this file is locked down: it can only be shared view-only")
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
            self._shred(fid)
        self.audit.append(owner, "shred", fid, o.meta["name"])

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
                    "wrapped_key": b64e(self._key_path(fid).read_bytes()), "data_len": data_len,
                    "data_head": o.stream.read(48), "segments": max(1, -(-data_len // (CHUNK + TAG)))}
