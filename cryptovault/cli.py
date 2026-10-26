"""Server entry point: python -m cryptovault [--demo]"""
import argparse
import getpass
import io
import os
import sys

from .crypto import CryptoError
from .vault import Vault, VaultError


def ask(prompt, confirm=False):
    # The env variable exists only for scripted demos and tests. Environment variables can leak via /proc and shell history.
    if os.environ.get("CRYPTOVAULT_MASTER_PASSWORD"):
        return os.environ["CRYPTOVAULT_MASTER_PASSWORD"]
    passphrase = getpass.getpass(prompt)
    if confirm and passphrase != getpass.getpass("Repeat: "):
        raise VaultError("passphrases do not match")
    return passphrase


def seed(v: Vault):
    """Demo accounts and sample files, so a presentation can start straight away."""
    from PIL import Image, ImageDraw, ImageFont

    if v.has_users():
        print("demo: vault already has users, not seeding")
        return
    for name in ("alice", "bob", "carol", "eve"):
        v.register(f"{name}@gmail.com", f"{name}-password")
    signer = v.user_keys("alice@gmail.com", "alice-password")["sign"]

    font = ImageFont.load_default(size=36)
    img = Image.new("RGB", (900, 560), "#1f2a44")
    draw = ImageDraw.Draw(img)
    draw.rectangle((60, 60, 840, 500), outline="#7d97ff", width=6)
    draw.text((110, 230), "PROTOTYPE - CONFIDENTIAL", font=font, fill="white")
    png = io.BytesIO()
    img.save(png, "PNG")

    pages = []
    for i, line in enumerate(["Employment contract", "Salary: 1,20,000 / month", "Signed: Alice"]):
        page = Image.new("RGB", (850, 1100), "white")
        ImageDraw.Draw(page).text((80, 120), f"Page {i + 1}\n\n{line}", font=font, fill="black")
        pages.append(page)
    pdf = io.BytesIO()
    pages[0].save(pdf, "PDF", save_all=True, append_images=pages[1:])

    alice = "alice@gmail.com"
    # one file per protection level: everything, server key only, password only
    plan = v.store(alice, "launch-plan.txt", b"Q3 launch plan\n\n1. Ship on 1 Dec\n2. Do not tell anyone\n",
                   ["system", "password", "cascade", "lockdown"], "launch-password", signer=signer)
    logo = v.store(alice, "prototype.png", png.getvalue(), signer=signer)
    contract = v.store(alice, "contract.pdf", pdf.getvalue(), ["password"], "contract-password", signer=signer)
    board = v.store(alice, "board-minutes.txt", b"Board minutes\n\nThe acquisition of Initech is approved.\n",
                    ["system", "quorum"], signer=signer, approvers=["bob@gmail.com", "carol@gmail.com"], threshold=2)
    v.share(plan, alice, "bob@gmail.com", "view")
    v.share(logo, alice, "bob@gmail.com", "view")
    v.share(contract, alice, "bob@gmail.com", "download")
    v.share(board, alice, "bob@gmail.com", "view")
    print("demo accounts: alice, bob, carol, eve @gmail.com, password <name>-password (e.g. alice-password)")
    print("file passwords: launch-plan.txt / launch-password, contract.pdf / contract-password")
    print("board-minutes.txt needs approval from bob and carol before anyone can open it")


def main(argv=None):
    p = argparse.ArgumentParser(prog="cryptovault", description="CryptoVault: secure file sharing with hybrid encryption.")
    p.add_argument("--vault", default=os.environ.get("CRYPTOVAULT_DIR", "vault"), help="vault directory (default ./vault)")
    p.add_argument("--host", default="127.0.0.1", help="default 127.0.0.1 (this machine only)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--demo", action="store_true", help="create demo accounts and sample files in an empty vault")
    p.add_argument("--rotate-key", action="store_true", help="replace the system RSA key, re-wrap every file key, and exit")
    args = p.parse_args(argv)

    v = Vault(args.vault)
    try:
        if v.initialized():
            passphrase = ask("Master passphrase: ")
            v.unlock(passphrase)
            if args.rotate_key:
                print(f"new system key in place; {v.rotate_key(passphrase)} file keys re-wrapped; the old key is destroyed")
                return
        else:
            print(f"Creating a new vault in {args.vault}/")
            v.initialize(ask("Choose a master passphrase (12+ characters): ", confirm=True))
        if args.demo:
            seed(v)
    except (VaultError, CryptoError) as e:
        sys.exit(f"error: {e}")
    except (KeyboardInterrupt, EOFError):
        sys.exit(130)

    if args.host not in ("127.0.0.1", "localhost"):
        print("WARNING: serving beyond this machine over plain HTTP. Passwords would cross the network unencrypted.")
    from .web import create_app
    create_app(v).run(host=args.host, port=args.port)
