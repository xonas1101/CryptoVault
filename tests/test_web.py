"""Web UI tests. Run: python -m unittest -v"""
import io
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from cryptovault.vault import MAGIC
from cryptovault.web import create_app
from tests.test_vault import ALICE, BOB, EVE, new_vault


def png_bytes(color="navy"):
    out = io.BytesIO()
    Image.new("RGB", (300, 200), color).save(out, "PNG")
    return out.getvalue()


class WebTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.v = new_vault(Path(cls._tmp.name) / "vault")
        cls.app = create_app(cls.v)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def login(self, email):
        c = self.app.test_client()
        c.post("/login", data={"email": email, "password": email.split("@")[0] + "-password"})
        return c

    def upload(self, c, name, data, layers=("system",), password=""):
        r = c.post("/upload", data={"file": (io.BytesIO(data), name), "layer": list(layers), "password": password,
                                    "confirm": password}, content_type="multipart/form-data")
        return r.headers["Location"].rsplit("/", 1)[1]  # redirected to /file/<id>

    def share(self, c, fid, email, perm="view", until=""):
        return c.post(f"/file/{fid}/share", data={"email": email, "perm": perm, "until": until}, follow_redirects=True)

    def test_register_login_logout(self):
        c = self.app.test_client()
        c.post("/register", data={"email": "new@gmail.com", "password": "new-password", "confirm": "new-password"})
        self.assertIn(b"Signed in as", c.get("/").data)
        c.post("/logout")
        self.assertIn(b"Create account", c.get("/").data)
        page = c.post("/login", data={"email": "new@gmail.com", "password": "wrong-pass"}, follow_redirects=True).data
        self.assertIn(b"Wrong email or password", page)

    def test_view_only_share_full_story(self):
        alice, bob, eve = self.login(ALICE), self.login(BOB), self.login(EVE)
        fid = self.upload(alice, "plan.txt", b"launch on monday")
        self.share(alice, fid, BOB, "view")

        self.assertIn(b"launch on monday", bob.get(f"/file/{fid}").data)        # Bob can view
        self.assertIn(b"watermarked for bob@gmail.com", bob.get(f"/file/{fid}").data)
        page = bob.get(f"/file/{fid}/download", follow_redirects=True).data       # but not download the original
        self.assertNotIn(b"launch on monday", page)
        self.assertIn(b"viewing only", page)

        locked = bob.get(f"/file/{fid}/locked").data                             # he can take a locked copy
        self.assertTrue(locked.startswith(MAGIC))
        self.assertNotIn(b"launch on monday", locked)

        def open_copy(c):
            return c.post("/open", data={"file": (io.BytesIO(locked), "plan.txt.cvault")},
                          content_type="multipart/form-data", follow_redirects=True).data

        self.assertIn(b"launch on monday", open_copy(bob))                       # it opens for Bob inside the app
        self.assertNotIn(b"launch on monday", open_copy(eve))                    # forwarded to Eve: nothing
        alice.post(f"/file/{fid}/revoke", data={"email": BOB})
        self.assertNotIn(b"launch on monday", open_copy(bob))                    # revoked: Bob's copy is dead too

        activity = alice.get(f"/file/{fid}").data
        self.assertIn(b"log chain verified", activity)
        self.assertIn(b"denied", activity)

    def test_image_and_pdf_previews_are_watermarked(self):
        alice = self.login(ALICE)
        original = png_bytes()
        fid = self.upload(alice, "photo.png", original)
        shown = alice.get(f"/file/{fid}/page/0.png").data
        self.assertTrue(shown.startswith(b"\x89PNG"))
        self.assertNotEqual(Image.open(io.BytesIO(shown)).convert("RGB").tobytes(),
                            Image.open(io.BytesIO(original)).convert("RGB").tobytes())

        pdf = io.BytesIO()
        Image.new("RGB", (400, 500), "white").save(pdf, "PDF")
        fid = self.upload(alice, "doc.pdf", pdf.getvalue())
        self.assertIn(b"/page/0.png", alice.get(f"/file/{fid}").data)
        self.assertTrue(alice.get(f"/file/{fid}/page/0.png").data.startswith(b"\x89PNG"))

    def test_download_permission_and_expiry_form(self):
        alice, bob = self.login(ALICE), self.login(BOB)
        fid = self.upload(alice, "notes.txt", b"secret notes")
        self.share(alice, fid, BOB, "download", until="2999-12-31")
        r = bob.get(f"/file/{fid}/download")
        self.assertEqual(r.data, b"secret notes")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertIn(b"past", self.share(alice, fid, BOB, "view", until="2000-01-01").data)

    def test_outsiders_and_logged_out_users_get_nothing(self):
        alice = self.login(ALICE)
        fid = self.upload(alice, "s.txt", b"TOP SECRET")
        for c in (self.app.test_client(), self.login(EVE)):
            for url in (f"/file/{fid}", f"/file/{fid}/download", f"/file/{fid}/locked", f"/file/{fid}/page/0.png"):
                self.assertNotIn(b"TOP SECRET", c.get(url, follow_redirects=True).data)

    def test_password_locked_file(self):
        alice, bob = self.login(ALICE), self.login(BOB)
        fid = self.upload(alice, "pin.txt", b"vault pin 4242", ["password", "cascade"], "file-password")
        self.share(alice, fid, BOB, "download")
        self.assertIn(b"password-locked", bob.get(f"/file/{fid}").data)
        self.assertNotIn(b"4242", bob.get(f"/file/{fid}/download", follow_redirects=True).data)
        page = bob.post(f"/file/{fid}/unlock", data={"password": "wrong-password"}, follow_redirects=True).data
        self.assertIn(b"wrong file password", page)
        bob.post(f"/file/{fid}/unlock", data={"password": "file-password"})
        self.assertIn(b"vault pin 4242", bob.get(f"/file/{fid}").data)
        self.assertEqual(bob.get(f"/file/{fid}/download").data, b"vault pin 4242")
        self.assertIn(b"password-locked", alice.get(f"/file/{fid}").data)  # unlocking is per person and session

    def test_filenames_are_html_escaped(self):
        alice = self.login(ALICE)
        self.upload(alice, "<script>alert(1)</script>.txt", b"x")
        page = alice.get("/").data
        self.assertNotIn(b"<script>alert(1)</script>", page)
        self.assertIn(b"&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
