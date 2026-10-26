"""Security tests for the vault. Run: python -m unittest -v"""
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from cryptovault import crypto
from cryptovault.crypto import CHUNK, TAG, CryptoError, b64e, canon
from cryptovault.vault import MAGIC, AccessDenied, Vault, VaultError, _block, _read_container

MASTER = "correct horse battery staple"
ALICE, BOB, EVE = "alice@gmail.com", "bob@gmail.com", "eve@gmail.com"
SEG = CHUNK + TAG  # size of one full ciphertext segment


def new_vault(root: Path) -> Vault:
    v = Vault(root)
    v.initialize(MASTER)
    for email in (ALICE, BOB, EVE):
        v.register(email, email.split("@")[0] + "-password")
    return v


class VaultTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.v = new_vault(Path(cls._tmp.name) / "shared")

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def fresh(self) -> Vault:
        """A private vault for tests that damage vault-wide files."""
        return new_vault(Path(tempfile.mkdtemp(dir=self._tmp.name)) / "vault")

    def path(self, fid, v=None):
        return (v or self.v).files_dir / f"{fid}.cvault"

    def tamper(self, fid, fn):
        """fn(file bytes, offset of first data segment) -> new file bytes"""
        p = self.path(fid)
        with open(p, "rb") as f:
            _read_container(f)
            off = f.tell()
        p.write_bytes(fn(p.read_bytes(), off))

    def rewrite_header(self, fid, change):
        p = self.path(fid)
        with open(p, "rb") as f:
            header, sealed = _read_container(f)
            rest = f.read()
        change(header)
        p.write_bytes(MAGIC + _block(canon(header)) + _block(sealed) + rest)

    def assertBroken(self, fid):
        with self.assertRaises(CryptoError):
            self.v.read(fid, ALICE)

    # ---------- encryption ----------

    def test_round_trip_all_sizes(self):
        for size in (0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 7):
            data = os.urandom(size)
            fid = self.v.store(ALICE, "f.bin", data)
            self.assertEqual(self.v.read(fid, ALICE)[0], data, f"size {size}")

    def test_same_plaintext_encrypts_differently(self):
        a, b = self.v.store(ALICE, "x", b"same"), self.v.store(ALICE, "x", b"same")
        self.assertNotEqual(self.path(a).read_bytes()[-40:], self.path(b).read_bytes()[-40:])

    def test_name_owner_and_access_list_not_visible_on_disk(self):
        fid = self.v.store(ALICE, "salary-review.pdf", b"x")
        self.v.share(fid, ALICE, BOB, "view")
        raw = self.path(fid).read_bytes()
        for secret in (b"salary-review", b"alice", b"bob"):
            self.assertNotIn(secret, raw)

    # ---------- integrity: every kind of tampering is detected ----------

    def test_bit_flip_in_data_detected(self):
        fid = self.v.store(ALICE, "f", os.urandom(2 * CHUNK + 10))
        self.tamper(fid, lambda b, off: b[:off + SEG + 100] + bytes([b[off + SEG + 100] ^ 1]) + b[off + SEG + 101:])
        self.assertBroken(fid)

    def test_truncation_detected(self):
        fid = self.v.store(ALICE, "f", os.urandom(3 * CHUNK))
        self.tamper(fid, lambda b, off: b[:off + 2 * SEG])  # drop the final segment
        self.assertBroken(fid)

    def test_segment_reordering_detected(self):
        fid = self.v.store(ALICE, "f", os.urandom(2 * CHUNK + 10))
        self.tamper(fid, lambda b, off: b[:off] + b[off + SEG:off + 2 * SEG] + b[off:off + SEG] + b[off + 2 * SEG:])
        self.assertBroken(fid)

    def test_sealed_metadata_tamper_detected(self):
        """The access list lives here, so this is also 'nobody can grant themselves access by editing disk'."""
        fid = self.v.store(ALICE, "f", b"data")
        self.tamper(fid, lambda b, off: b[:off - 3] + bytes([b[off - 3] ^ 1]) + b[off - 2:])
        self.assertBroken(fid)

    def test_header_tamper_detected(self):
        fid = self.v.store(ALICE, "f", b"data")
        self.rewrite_header(fid, lambda h: h.update(nonce_prefix=b64e(os.urandom(crypto.PREFIX))))
        self.assertBroken(fid)

    def test_wrapped_key_swap_detected(self):
        fid = self.v.store(ALICE, "f", b"data")
        other = crypto.wrap_key(os.urandom(32), self.v._public)
        self.rewrite_header(fid, lambda h: h.update(wrapped_key=b64e(other)))
        self.assertBroken(fid)

    def test_swapping_two_files_detected(self):
        a, b = self.v.store(ALICE, "a", b"aaa"), self.v.store(ALICE, "b", b"bbb")
        self.path(b).write_bytes(self.path(a).read_bytes())
        self.assertBroken(b)

    def test_broken_files_are_reported(self):
        """Listing checks headers and metadata; damaged data segments are caught when the file is opened."""
        fid = self.v.store(ALICE, "f", b"data")
        self.tamper(fid, lambda b, off: b[:off - 3] + bytes([b[off - 3] ^ 1]) + b[off - 2:])
        self.assertIn(fid, self.v.files_for(ALICE)[2])

    # ---------- access control ----------

    def test_permissions(self):
        fid = self.v.store(ALICE, "plan.txt", b"the plan")
        with self.assertRaises(AccessDenied):
            self.v.read(fid, BOB)
        self.v.share(fid, ALICE, BOB, "view")
        self.assertEqual(self.v.read(fid, BOB, "view")[0], b"the plan")
        with self.assertRaises(AccessDenied):
            self.v.read(fid, BOB, "download")
        self.v.share(fid, ALICE, BOB, "download")
        self.assertEqual(self.v.read(fid, BOB, "download")[0], b"the plan")
        with self.assertRaises(AccessDenied):
            self.v.read(fid, EVE)
        self.v.revoke(fid, ALICE, BOB)
        with self.assertRaises(AccessDenied):
            self.v.read(fid, BOB)

    def test_expiry(self):
        fid = self.v.store(ALICE, "f", b"data")
        self.v.share(fid, ALICE, BOB, "view", until=time.time() + 0.5)
        self.v.read(fid, BOB)
        time.sleep(0.6)
        with self.assertRaisesRegex(AccessDenied, "expired"):
            self.v.read(fid, BOB)
        self.assertTrue(next(r for r in self.v.files_for(BOB)[1] if r["id"] == fid)["expired"])

    def test_only_owner_can_manage(self):
        fid = self.v.store(ALICE, "f", b"data")
        self.v.share(fid, ALICE, BOB, "download")
        for attempt in (lambda: self.v.share(fid, BOB, EVE, "view"), lambda: self.v.revoke(fid, BOB, ALICE),
                        lambda: self.v.delete(fid, BOB), lambda: self.v.activity(fid, BOB)):
            with self.assertRaises(AccessDenied):
                attempt()

    def test_share_reseals_metadata_but_never_touches_data(self):
        fid = self.v.store(ALICE, "f", os.urandom(CHUNK + 5))
        before = self.path(fid).read_bytes()[-(CHUNK + 5 + 2 * TAG):]
        self.v.share(fid, ALICE, BOB, "view")
        self.assertEqual(before, self.path(fid).read_bytes()[-(CHUNK + 5 + 2 * TAG):])

    def test_locked_copy_obeys_current_access_list(self):
        fid = self.v.store(ALICE, "f", b"data")
        self.v.share(fid, ALICE, BOB, "view")
        blob, _ = self.v.locked_copy(fid, BOB)
        self.assertEqual(self.v.resolve_locked(blob, BOB), fid)
        with self.assertRaises(AccessDenied):  # forwarded to Eve: useless
            self.v.resolve_locked(blob, EVE)
        self.v.revoke(fid, ALICE, BOB)
        with self.assertRaises(AccessDenied):  # Bob's own copy stops working after revocation
            self.v.resolve_locked(blob, BOB)
        self.v.delete(fid, ALICE)
        with self.assertRaisesRegex(VaultError, "no longer exists"):
            self.v.resolve_locked(blob, ALICE)

    def test_denials_are_logged(self):
        fid = self.v.store(ALICE, "f", b"data")
        with self.assertRaises(AccessDenied):
            self.v.read(fid, EVE)
        entries, broken = self.v.activity(fid, ALICE)
        self.assertIsNone(broken)
        self.assertIn(("denied", EVE), [(e["action"], e["actor"]) for e in entries])

    # ---------- users and the system key ----------

    def test_authentication(self):
        self.assertEqual(self.v.authenticate(" Alice@Gmail.com ", "alice-password"), ALICE)
        for email, pw in ((ALICE, "wrong-password"), ("nobody@gmail.com", "alice-password")):
            with self.assertRaises(AccessDenied):
                self.v.authenticate(email, pw)

    def test_registration_rules(self):
        for email, pw in (("not-an-email", "long-enough"), ("x@y.com", "short"), (ALICE, "long-enough")):
            with self.assertRaises(VaultError):
                self.v.register(email, pw)

    def test_passwords_stored_only_as_hashes(self):
        raw = (self.v.root / "users.json").read_text()
        self.assertNotIn("alice-password", raw)

    def test_wrong_master_passphrase(self):
        with self.assertRaises(CryptoError):
            Vault(self.v.root).unlock("not the passphrase")

    def test_users_table_tamper_detected(self):
        v = self.fresh()
        data = json.loads((v.root / "users.json").read_text())
        data["users"]["mallory@gmail.com"] = data["users"][BOB]  # copy Bob's hash: Mallory "knows" bob-password
        (v.root / "users.json").write_text(json.dumps(data))
        with self.assertRaisesRegex(CryptoError, "tampered"):
            v.authenticate("mallory@gmail.com", "bob-password")

    def test_system_public_key_swap_detected(self):
        v = self.fresh()
        (v.root / "system.pub.pem").write_bytes(crypto.public_pem(crypto.new_system_key()))
        with self.assertRaisesRegex(CryptoError, "swapped"):
            Vault(v.root).unlock(MASTER)

    def test_audit_log_tamper_detected(self):
        v = self.fresh()
        fid = v.store(ALICE, "f", b"data")
        with self.assertRaises(AccessDenied):
            v.read(fid, EVE)
        self.assertIsNone(v.activity(fid, ALICE)[1])
        log = v.root / "audit.log"
        lines = log.read_text().splitlines()
        i = next(n for n, line in enumerate(lines) if '"denied"' in line)
        lines[i] = lines[i].replace("eve@gmail.com", "bob@gmail.com")  # try to frame Bob
        log.write_text("\n".join(lines) + "\n")
        self.assertEqual(v.activity(fid, ALICE)[1], i)


if __name__ == "__main__":
    unittest.main()
