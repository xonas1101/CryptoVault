"""Security tests for the vault. Run: python -m unittest -v"""
import hashlib
import itertools
import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from cryptovault import crypto
from cryptovault.crypto import CHUNK, TAG, CryptoError, b64e, canon
from cryptovault.vault import (LAYERS, MAGIC, AccessDenied, Destroyed, PasswordRequired, QuorumRequired, Vault,
                               VaultError, _block, _read_container)

MASTER = "correct horse battery staple"
ALICE, BOB, EVE = "alice@gmail.com", "bob@gmail.com", "eve@gmail.com"
SEG = CHUNK + TAG  # size of one full ciphertext segment


def new_vault(root: Path) -> Vault:
    v = Vault(root)
    v.initialize(MASTER)
    v.user_keys_for = {}  # what each user's login would unseal
    for email in (ALICE, BOB, EVE):
        v.register(email, email.split("@")[0] + "-password")
        v.user_keys_for[email] = v.user_keys(email, email.split("@")[0] + "-password")
    return v


def store(v: Vault, owner: str, *args, **kwargs) -> str:
    return v.store(owner, *args, signer=v.user_keys_for[owner]["sign"], **kwargs)


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

    def key_path(self, fid, v=None):
        return (v or self.v).keys_dir / f"{fid}.key"

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
            fid = store(self.v, ALICE, "f.bin", data)
            self.assertEqual(self.v.read(fid, ALICE)[0], data, f"size {size}")

    def test_same_plaintext_encrypts_differently(self):
        a, b = store(self.v, ALICE, "x", b"same"), store(self.v, ALICE, "x", b"same")
        self.assertNotEqual(self.path(a).read_bytes()[-40:], self.path(b).read_bytes()[-40:])

    def test_name_owner_and_access_list_not_visible_on_disk(self):
        fid = store(self.v, ALICE, "salary-review.pdf", b"x")
        self.v.share(fid, ALICE, BOB, "view")
        raw = self.path(fid).read_bytes()
        for secret in (b"salary-review", b"alice", b"bob"):
            self.assertNotIn(secret, raw)

    # ---------- integrity: every kind of tampering is detected ----------

    def test_bit_flip_in_data_detected(self):
        fid = store(self.v, ALICE, "f", os.urandom(2 * CHUNK + 10))
        self.tamper(fid, lambda b, off: b[:off + SEG + 100] + bytes([b[off + SEG + 100] ^ 1]) + b[off + SEG + 101:])
        self.assertBroken(fid)

    def test_truncation_detected(self):
        fid = store(self.v, ALICE, "f", os.urandom(3 * CHUNK))
        self.tamper(fid, lambda b, off: b[:off + 2 * SEG])  # drop the final segment
        self.assertBroken(fid)

    def test_segment_reordering_detected(self):
        fid = store(self.v, ALICE, "f", os.urandom(2 * CHUNK + 10))
        self.tamper(fid, lambda b, off: b[:off] + b[off + SEG:off + 2 * SEG] + b[off:off + SEG] + b[off + 2 * SEG:])
        self.assertBroken(fid)

    def test_sealed_metadata_tamper_detected(self):
        """The access list lives here, so this is also 'nobody can grant themselves access by editing disk'."""
        fid = store(self.v, ALICE, "f", b"data")
        self.tamper(fid, lambda b, off: b[:off - 3] + bytes([b[off - 3] ^ 1]) + b[off - 2:])
        self.assertBroken(fid)

    def test_header_tamper_detected(self):
        fid = store(self.v, ALICE, "f", b"data")
        self.rewrite_header(fid, lambda h: h.update(nonce_prefix=b64e(os.urandom(crypto.PREFIX))))
        self.assertBroken(fid)

    def test_wrapped_key_swap_detected(self):
        fid = store(self.v, ALICE, "f", b"data")
        self.key_path(fid).write_bytes(crypto.wrap_key(os.urandom(32), self.v._public))
        self.assertBroken(fid)

    def test_swapping_two_files_detected(self):
        a, b = store(self.v, ALICE, "a", b"aaa"), store(self.v, ALICE, "b", b"bbb")
        self.path(b).write_bytes(self.path(a).read_bytes())
        self.assertBroken(b)

    def test_broken_files_are_reported(self):
        """Listing checks headers and metadata; damaged data segments are caught when the file is opened."""
        fid = store(self.v, ALICE, "f", b"data")
        self.tamper(fid, lambda b, off: b[:off - 3] + bytes([b[off - 3] ^ 1]) + b[off - 2:])
        self.assertIn(fid, self.v.files_for(ALICE)[2])

    # ---------- protection layers ----------

    def test_every_layer_combination_round_trips(self):
        data = os.urandom(CHUNK + 99)
        for n in range(1, len(LAYERS) + 1):
            for layers in itertools.combinations(LAYERS, n):
                if not {"system", "password", "quorum"} & set(layers):
                    with self.assertRaisesRegex(VaultError, "key holder"):
                        store(self.v, ALICE, "f", data, layers)
                    continue
                fid = store(self.v, ALICE, "f", data, layers, "file-password", approvers=[ALICE], threshold=1)
                if "quorum" in layers:
                    self.v.approve(fid, ALICE, self.v.user_keys_for[ALICE]["box"])
                key = self.v.unlock_file(fid, ALICE, "file-password") if "password" in layers else None
                self.assertEqual(self.v.read(fid, ALICE, pw_key=key)[0], data, layers)

    def test_password_layer(self):
        data = b"only with the password"
        fid = store(self.v, ALICE, "f", data, ["password"], "file-password")
        self.v.share(fid, ALICE, BOB, "view")
        with self.assertRaises(PasswordRequired):  # the server alone can't open it, not even for the owner
            self.v.read(fid, ALICE)
        with self.assertRaisesRegex(AccessDenied, "wrong file password"):
            self.v.unlock_file(fid, BOB, "guess-guess")
        with self.assertRaises(AccessDenied):  # knowing the password doesn't help without access
            self.v.unlock_file(fid, EVE, "file-password")
        self.assertEqual(self.v.read(fid, BOB, pw_key=self.v.unlock_file(fid, BOB, "file-password"))[0], data)
        with self.assertRaises(CryptoError):  # a made-up key fails authentication
            self.v.read(fid, BOB, pw_key=os.urandom(32))
        meta = self.v.read(fid, BOB, pw_key=self.v.unlock_file(fid, BOB, "file-password"))[1]
        self.assertNotIn(hashlib.sha256(data).hexdigest(), json.dumps(meta))  # metadata can't confirm guesses
        self.assertIn(("denied", BOB), [(e["action"], e["actor"]) for e in self.v.activity(fid, ALICE)[0]])

    def test_layers_cannot_be_stripped(self):
        """Downgrade attack: remove the password or cascade layer from the header."""
        for layer in ("password", "quorum", "cascade", "lockdown"):
            fid = store(self.v, ALICE, "f", b"data", ["system", layer], "file-password", approvers=[ALICE], threshold=1)
            self.rewrite_header(fid, lambda h: h.update(layers=["system"]))
            self.assertBroken(fid)

    def test_lockdown_blocks_every_download(self):
        fid = store(self.v, ALICE, "f", b"data", ["system", "lockdown"])
        self.v.read(fid, ALICE, "view")
        with self.assertRaisesRegex(AccessDenied, "locked down"):
            self.v.read(fid, ALICE, "download")
        with self.assertRaisesRegex(VaultError, "view-only"):
            self.v.share(fid, ALICE, BOB, "download")

    def test_shamir_any_k_of_n(self):
        secret = os.urandom(32)
        shares = crypto.split(secret, 3, 5)
        for subset in itertools.combinations(shares, 3):
            self.assertEqual(crypto.combine(subset), secret)
        for subset in itertools.combinations(shares, 2):
            with self.assertRaises(CryptoError):
                crypto.combine(subset)

    def test_quorum_layer(self):
        v = self.fresh()
        keys = v.user_keys_for
        fid = store(v, ALICE, "board.txt", b"minutes", ["quorum"], approvers=[BOB, EVE, ALICE], threshold=2)
        with self.assertRaises(QuorumRequired):  # not even the owner, not even the server
            v.read(fid, ALICE)
        v.approve(fid, BOB, keys[BOB]["box"])
        with self.assertRaisesRegex(QuorumRequired, "1 so far"):
            v.read(fid, ALICE)
        with self.assertRaises(CryptoError):  # Bob's key can't release Eve's share
            v.approve(fid, EVE, keys[BOB]["box"])
        v.approve(fid, EVE, keys[EVE]["box"])
        self.assertEqual(v.read(fid, ALICE)[0], b"minutes")
        with self.assertRaises(AccessDenied):  # approving releases a share, it doesn't grant access
            v.read(fid, BOB)

        v.approval_ttl = 0.3
        v.approve(fid, BOB, keys[BOB]["box"])
        v.approve(fid, EVE, keys[EVE]["box"])
        time.sleep(0.4)
        with self.assertRaisesRegex(QuorumRequired, "0 so far"):  # approvals expire
            v.read(fid, ALICE)
        with self.assertRaisesRegex(VaultError, "no account"):  # shares are encrypted to approvers' keys
            store(v, ALICE, "f", b"x", ["quorum"], approvers=["nobody@gmail.com"], threshold=1)

    # ---------- signatures ----------

    def test_uploads_are_signed_by_their_owner(self):
        fid = store(self.v, ALICE, "f", b"data")
        self.assertEqual(self.v.read(fid, ALICE)[0], b"data")
        with self.v._open(fid) as o:  # someone holding the master key rewrites the metadata: "Eve wrote this"
            o.meta["owner"] = EVE
            self.v._reseal(o)
        with self.assertRaisesRegex(CryptoError, "signature"):
            self.v.read(fid, EVE)
        forged = self.v.store(ALICE, "f", b"data", signer=self.v.user_keys_for[BOB]["sign"])  # Bob signs as Alice
        with self.assertRaisesRegex(CryptoError, "signature"):
            self.v.read(forged, ALICE)

    def test_private_keys_need_the_login_password(self):
        with self.assertRaises(AccessDenied):
            self.v.user_keys(ALICE, "wrong-password")
        raw = (self.v.root / "users.json").read_text()
        self.assertNotIn(b64e(self.v.user_keys_for[ALICE]["sign"]), raw)

    # ---------- key rotation and crypto-shredding ----------

    def test_key_rotation(self):
        v = self.fresh()
        fids = [store(v, ALICE, "a", b"one"), store(v, ALICE, "b", b"two", ["system", "cascade"])]
        before = {f: self.path(f, v).read_bytes() for f in fids}
        old = v._private
        self.assertEqual(v.rotate_key(MASTER), 2)
        for f in fids:
            self.assertEqual(self.path(f, v).read_bytes(), before[f])  # no data or metadata touched
            with self.assertRaises(CryptoError):  # the old key no longer opens anything
                crypto.unwrap_key(self.key_path(f, v).read_bytes(), old)
        keystore = lambda: set(crypto.open_secrets(json.loads((v.root / "system.key.json").read_text()), MASTER))
        self.assertEqual(keystore(), {"rsa", "mac"})  # the old private key is gone
        restarted = Vault(v.root)
        restarted.unlock(MASTER)
        self.assertEqual(restarted.read(fids[1], ALICE)[0], b"two")

        # crash right after step 1 (new key saved, nothing re-wrapped yet): the next start finishes the job
        secrets = crypto.open_secrets(json.loads((v.root / "system.key.json").read_text()), MASTER)
        v._save_keystore({"rsa": crypto.private_der(crypto.new_system_key()), "rsa_old": secrets["rsa"],
                          "mac": secrets["mac"]}, MASTER)
        restarted = Vault(v.root)
        restarted.unlock(MASTER)
        self.assertEqual(keystore(), {"rsa", "mac"})
        self.assertEqual(restarted.read(fids[0], ALICE)[0], b"one")

    def test_shredding_kills_every_copy(self):
        fid = store(self.v, ALICE, "f", b"data")
        self.v.share(fid, ALICE, BOB, "view")
        locked, _ = self.v.locked_copy(fid, BOB)
        self.assertNotIn(self.key_path(fid).read_bytes(), locked)  # downloaded copies carry no key
        backup = self.path(fid).read_bytes()
        self.v.delete(fid, ALICE)
        self.assertFalse(self.key_path(fid).exists())
        self.path(fid).write_bytes(backup)  # restore the ciphertext from a backup: still useless
        with self.assertRaises(Destroyed):
            self.v.read(fid, ALICE)
        self.assertNotIn(fid, self.v.files_for(ALICE)[2])  # shredded is not "damaged"
        self.path(fid).unlink()

    def test_self_destruct(self):
        fid = store(self.v, ALICE, "f", b"data", destroy_at=time.time() + 0.3)
        self.v.read(fid, ALICE)
        time.sleep(0.4)
        with self.assertRaisesRegex(Destroyed, "self-destructed"):
            self.v.read(fid, ALICE)
        self.assertFalse(self.key_path(fid).exists())
        with self.assertRaisesRegex(VaultError, "past"):
            store(self.v, ALICE, "f", b"data", destroy_at=time.time() - 1)

    # ---------- access control ----------

    def test_permissions(self):
        fid = store(self.v, ALICE, "plan.txt", b"the plan")
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
        fid = store(self.v, ALICE, "f", b"data")
        self.v.share(fid, ALICE, BOB, "view", until=time.time() + 0.5)
        self.v.read(fid, BOB)
        time.sleep(0.6)
        with self.assertRaisesRegex(AccessDenied, "expired"):
            self.v.read(fid, BOB)
        self.assertTrue(next(r for r in self.v.files_for(BOB)[1] if r["id"] == fid)["expired"])

    def test_only_owner_can_manage(self):
        fid = store(self.v, ALICE, "f", b"data")
        self.v.share(fid, ALICE, BOB, "download")
        for attempt in (lambda: self.v.share(fid, BOB, EVE, "view"), lambda: self.v.revoke(fid, BOB, ALICE),
                        lambda: self.v.delete(fid, BOB), lambda: self.v.activity(fid, BOB)):
            with self.assertRaises(AccessDenied):
                attempt()

    def test_share_reseals_metadata_but_never_touches_data(self):
        fid = store(self.v, ALICE, "f", os.urandom(CHUNK + 5))
        before = self.path(fid).read_bytes()[-(CHUNK + 5 + 2 * TAG):]
        self.v.share(fid, ALICE, BOB, "view")
        self.assertEqual(before, self.path(fid).read_bytes()[-(CHUNK + 5 + 2 * TAG):])

    def test_locked_copy_obeys_current_access_list(self):
        fid = store(self.v, ALICE, "f", b"data")
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
        fid = store(self.v, ALICE, "f", b"data")
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
        fid = store(v, ALICE, "f", b"data")
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
