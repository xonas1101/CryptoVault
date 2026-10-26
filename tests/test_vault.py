"""Security test suite. Run: python -m unittest -v"""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from cryptovault import crypto
from cryptovault.crypto import CHUNK, TAG, CryptoError, b64e
from cryptovault.vault import AccessDenied, Vault, VaultError, _read_container, _rewrite_header

PW = {"alice": "alice-password", "bob": "bob-password", "eve": "eve-password"}
SEG = CHUNK + TAG  # size of one full ciphertext segment


class VaultTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.v = Vault(Path(cls._tmp.name) / "vault")
        for name, pw in PW.items():
            cls.v.add_user(name, pw)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=self._tmp.name))

    # ---------- helpers ----------

    def put(self, data, owner="alice", share=()):
        src = self.work / "secret.bin"
        src.write_bytes(data)
        return self.v.put(src, owner, PW[owner], share)

    def get(self, fid, user="alice"):
        out = self.work / f"out-{os.urandom(4).hex()}"
        self.v.get(fid, user, PW[user], out)
        return out.read_bytes()

    def assertRejected(self, fid, user="alice", exc=CryptoError):
        out = self.work / "rejected"
        with self.assertRaises(exc):
            self.v.get(fid, user, PW[user], out)
        self.assertFalse(out.exists(), "unverified plaintext was released")

    def path(self, fid):
        return self.v.files_dir / f"{fid}.cvault"

    def tamper(self, fid, fn):
        """fn(file bytes, offset of first data segment) -> new file bytes"""
        p = self.path(fid)
        with open(p, "rb") as f:
            _read_container(f)
            off = f.tell()
        p.write_bytes(fn(p.read_bytes(), off))

    def header(self, fid):
        with open(self.path(fid), "rb") as f:
            return _read_container(f)[0]

    # ---------- correctness ----------

    def test_round_trip_all_sizes(self):
        for size in (0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 7):
            data = os.urandom(size)
            self.assertEqual(self.get(self.put(data)), data, f"size {size}")

    def test_same_plaintext_encrypts_differently(self):
        a, b = self.put(b"same"), self.put(b"same")
        self.assertNotEqual(self.path(a).read_bytes()[100:], self.path(b).read_bytes()[100:])

    def test_filename_is_not_visible_on_disk(self):
        fid = self.put(b"x")
        self.assertNotIn(b"secret.bin", self.path(fid).read_bytes())

    def test_ls_shows_decrypted_metadata(self):
        fid = self.put(b"hello", share=["bob"])
        row = next(r for r in self.v.ls("bob", PW["bob"]) if r["id"] == fid)
        self.assertEqual((row["name"], row["size"], row["owner"], row["recipients"]),
                         ("secret.bin", 5, "alice", ["alice", "bob"]))

    def test_get_refuses_to_overwrite(self):
        fid = self.put(b"x")
        existing = self.work / "existing"
        existing.write_bytes(b"keep me")
        with self.assertRaises(VaultError):
            self.v.get(fid, "alice", PW["alice"], existing)
        self.assertEqual(existing.read_bytes(), b"keep me")

    # ---------- integrity: every kind of tampering is detected ----------

    def test_bit_flip_in_data_detected(self):
        fid = self.put(os.urandom(2 * CHUNK + 10))
        self.tamper(fid, lambda b, off: b[:off + SEG + 100] + bytes([b[off + SEG + 100] ^ 1]) + b[off + SEG + 101:])
        self.assertRejected(fid)

    def test_truncation_detected(self):
        fid = self.put(os.urandom(3 * CHUNK))
        self.tamper(fid, lambda b, off: b[:off + 2 * SEG])  # drop the final segment
        self.assertRejected(fid)

    def test_segment_reordering_detected(self):
        fid = self.put(os.urandom(2 * CHUNK + 10))
        self.tamper(fid, lambda b, off: b[:off] + b[off + SEG:off + 2 * SEG] + b[off:off + SEG] + b[off + 2 * SEG:])
        self.assertRejected(fid)

    def test_metadata_tamper_detected(self):
        fid = self.put(b"data")
        self.tamper(fid, lambda b, off: b[:off - 3] + bytes([b[off - 3] ^ 1]) + b[off - 2:])
        self.assertRejected(fid)

    def test_header_tamper_detected(self):
        fid = self.put(b"data")
        h = self.header(fid)
        h["nonce_prefix"] = b64e(os.urandom(crypto.PREFIX))
        _rewrite_header(self.path(fid), h)
        self.assertRejected(fid)

    # ---------- confidentiality and access control ----------

    def test_wrong_password_rejected(self):
        fid = self.put(b"data")
        with self.assertRaises(CryptoError):
            self.v.get(fid, "alice", "not-the-password", self.work / "o")

    def test_non_recipient_denied_and_file_hidden(self):
        fid = self.put(b"data")
        self.assertRejected(fid, "eve", AccessDenied)
        self.assertNotIn(fid, [r["id"] for r in self.v.ls("eve", PW["eve"])])

    def test_share_adds_access_without_reencrypting(self):
        data = os.urandom(CHUNK + 5)
        fid = self.put(data)
        self.assertRejected(fid, "bob", AccessDenied)
        before = self.path(fid).read_bytes()
        self.v.share(fid, "alice", PW["alice"], ["bob"])
        self.assertEqual(self.get(fid, "bob"), data)
        self.assertEqual(before[-(CHUNK + 5 + 2 * TAG):], self.path(fid).read_bytes()[-(CHUNK + 5 + 2 * TAG):])

    def test_outsider_cannot_share(self):
        fid = self.put(b"data")
        with self.assertRaises(AccessDenied):
            self.v.share(fid, "eve", PW["eve"], ["eve"])

    def test_revoke_rekeys_so_old_wrapped_key_is_useless(self):
        data = b"bob should lose this"
        fid = self.put(data, share=["bob"])
        bobs_old_wrap = self.header(fid)["recipients"]["bob"]
        new_id = self.v.revoke(fid, "alice", PW["alice"], ["bob"])
        self.assertFalse(self.path(fid).exists())
        self.assertRejected(new_id, "bob", AccessDenied)
        self.assertEqual(self.get(new_id, "alice"), data)
        # Bob kept his old wrapped key and splices it back in. It unwraps to the OLD file key, which opens nothing now.
        h = self.header(new_id)
        h["recipients"]["bob"] = bobs_old_wrap
        _rewrite_header(self.path(new_id), h)
        self.assertRejected(new_id, "bob", CryptoError)

    def test_only_owner_can_revoke_or_delete(self):
        fid = self.put(b"data", share=["bob"])
        with self.assertRaises(AccessDenied):
            self.v.revoke(fid, "bob", PW["bob"], ["alice"])
        with self.assertRaises(AccessDenied):
            self.v.remove(fid, "bob", PW["bob"])
        self.v.remove(fid, "alice", PW["alice"])
        self.assertFalse(self.path(fid).exists())

    # ---------- authenticity ----------

    def test_forged_owner_rejected(self):
        """Eve encrypts a fake invoice for Bob that claims Alice stored it, but she can only sign with her own key."""
        _, eve_sign = self.v.unlock("eve", PW["eve"])
        data = b"Pay eve $1000. -- alice"
        meta = {"name": "invoice.txt", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                "owner": "alice", "created": 0}
        fid = self.v._store([data], meta, eve_sign, {"bob"})
        self.assertRejected(fid, "bob", CryptoError)

    # ---------- users and keys ----------

    def test_password_change(self):
        self.v.add_user("carol", "first-password")
        self.v.change_password("carol", "first-password", "second-password")
        with self.assertRaises(CryptoError):
            self.v.unlock("carol", "first-password")
        self.v.unlock("carol", "second-password")

    def test_bad_user_names_rejected(self):
        for bad in ("../etc", "", "Alice", "x" * 33, "a/b"):
            with self.assertRaises(VaultError):
                self.v.add_user(bad, "long-enough-password")

    def test_private_keys_not_stored_in_clear(self):
        store = (self.v.users_dir / "alice.key.json").read_bytes()
        self.assertNotIn(b"PRIVATE KEY", store)
        self.assertEqual(oct((self.v.users_dir / "alice.key.json").stat().st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
