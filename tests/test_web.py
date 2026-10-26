"""Web UI tests. Run: python -m unittest -v"""
import io
import tempfile
import unittest
from pathlib import Path

from cryptovault.vault import Vault
from cryptovault.web import create_app


class WebTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.vault_dir = Path(self._tmp.name) / "vault"
        self.app = create_app(self.vault_dir)

    def tearDown(self):
        self._tmp.cleanup()

    def client(self, user, register=True):
        c = self.app.test_client()
        pw = f"{user}-password"
        form = {"user": user, "password": pw, "confirm": pw}
        c.post("/register" if register else "/login", data=form)
        return c

    def upload(self, c, name, data, share=()):
        return c.post("/upload", data={"file": (io.BytesIO(data), name), "share": list(share)},
                      content_type="multipart/form-data")

    def file_id(self, user="alice"):
        return Vault(self.vault_dir).ls(user, f"{user}-password")[-1]["id"]

    def test_lock_and_unlock_round_trip(self):
        alice = self.client("alice")
        self.upload(alice, "notes.txt", b"meet at noon")
        self.assertIn(b"notes.txt", alice.get("/").data)
        r = alice.get(f"/file/{self.file_id()}/download")
        self.assertEqual(r.data, b"meet at noon")
        self.assertIn("notes.txt", r.headers["Content-Disposition"])
        self.assertEqual(r.headers["Cache-Control"], "no-store")

    def test_logged_out_and_non_recipients_get_nothing(self):
        self.client("bob")
        alice = self.client("alice")
        self.upload(alice, "secret.txt", b"TOP SECRET")
        fid = self.file_id()
        anon = self.app.test_client()
        self.assertNotIn(b"TOP SECRET", anon.get(f"/file/{fid}/download", follow_redirects=True).data)
        bob = self.client("bob", register=False)
        page = bob.get(f"/file/{fid}/download", follow_redirects=True).data
        self.assertNotIn(b"TOP SECRET", page)
        self.assertIn(b"not a recipient", page)

    def test_sharing_through_the_ui(self):
        self.client("bob")
        alice = self.client("alice")
        self.upload(alice, "plan.txt", b"the plan", share=["bob"])
        bob = self.client("bob", register=False)
        self.assertEqual(bob.get(f"/file/{self.file_id()}/download").data, b"the plan")

    def test_wrong_password_and_logout(self):
        alice = self.client("alice")
        alice.post("/logout")
        self.assertIn(b"Create account", alice.get("/").data)
        page = alice.post("/login", data={"user": "alice", "password": "nope-nope"}, follow_redirects=True).data
        self.assertIn(b"Wrong user name or password", page)

    def test_filenames_are_html_escaped(self):
        alice = self.client("alice")
        self.upload(alice, "<script>alert(1)</script>.txt", b"x")
        page = alice.get("/").data
        self.assertNotIn(b"<script>alert(1)</script>", page)
        self.assertIn(b"&lt;script&gt;", page)

    def test_inspect_shows_ciphertext_not_plaintext_on_disk_side(self):
        alice = self.client("alice")
        self.upload(alice, "diary.txt", b"dear diary")
        page = alice.get(f"/file/{self.file_id()}/inspect").data
        self.assertIn(b"STREAM segment", page)
        self.assertIn(b"signature verified", page)
        self.assertNotIn(b"dear diary", page)


if __name__ == "__main__":
    unittest.main()
