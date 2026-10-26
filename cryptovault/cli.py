"""Command-line interface. Run `python -m cryptovault --help`."""
import argparse
import getpass
import os
import sys
from datetime import datetime

from .crypto import CryptoError
from .vault import Vault, VaultError


def ask(prompt, confirm=False, env="CRYPTOVAULT_PASSWORD"):
    # The env variable exists only for scripted demos and tests. Environment variables can leak via /proc and shell history.
    if os.environ.get(env):
        return os.environ[env]
    password = getpass.getpass(prompt)
    if confirm and password != getpass.getpass("Repeat password: "):
        raise VaultError("passwords do not match")
    return password


def user_list(text):
    return [n.strip() for n in text.split(",") if n.strip()]


def parser():
    p = argparse.ArgumentParser(
        prog="cryptovault",
        description="Secure file storage with hybrid encryption (RSA-OAEP + AES-256-GCM, signed with Ed25519).")
    p.add_argument("--vault", default=os.environ.get("CRYPTOVAULT_DIR", "vault"),
                   help="vault directory (default: ./vault or $CRYPTOVAULT_DIR)")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    def command(name, help, user=True):
        s = sub.add_parser(name, help=help, description=help)
        if user:
            default = os.environ.get("CRYPTOVAULT_USER")
            s.add_argument("-u", "--user", default=default, required=default is None,
                           help="who you are (default: $CRYPTOVAULT_USER)")
        return s

    command("adduser", "create a user with encryption and signing keys", user=False).add_argument("name")
    command("users", "list users and their key fingerprints", user=False)
    command("passwd", "change your password")
    s = command("put", "encrypt a file into the vault")
    s.add_argument("file")
    s.add_argument("--share", type=user_list, default=[], metavar="U1,U2", help="also give these users access")
    command("ls", "list the files you can open")
    s = command("get", "decrypt a file out of the vault")
    s.add_argument("id")
    s.add_argument("-o", "--out", help="output path (default: the original file name)")
    command("verify", "check integrity and signature without writing anything").add_argument("id")
    s = command("share", "give more users access (re-wraps the key, no re-encryption)")
    s.add_argument("id")
    s.add_argument("--with", dest="targets", type=user_list, required=True, metavar="U1,U2")
    s = command("revoke", "remove access by re-encrypting under a fresh key (owner only)")
    s.add_argument("id")
    s.add_argument("--from", dest="targets", type=user_list, required=True, metavar="U1,U2")
    command("rm", "delete a file (owner only)").add_argument("id")
    return p


def run(args):
    v = Vault(args.vault)
    if args.cmd == "adduser":
        fp = v.add_user(args.name, ask(f"New password for {args.name}: ", confirm=True))
        print(f"created user {args.name}\nfingerprint {fp}")
        return
    if args.cmd == "users":
        for name in v.users():
            print(f"{name:<16} {v.fingerprint(name)}")
        return

    pw = ask(f"Password for {args.user}: ")
    if args.cmd == "passwd":
        v.change_password(args.user, pw, ask("New password: ", confirm=True, env="CRYPTOVAULT_NEW_PASSWORD"))
        print("password changed (only your keystore was re-encrypted, not your files)")
    elif args.cmd == "put":
        fid = v.put(args.file, args.user, pw, args.share)
        print(f"stored {os.path.basename(args.file)}\nid {fid}")
    elif args.cmd == "ls":
        print(f"{'ID':<9} {'NAME':<24} {'SIZE':>11}  {'OWNER':<10} {'CREATED':<16}  SHARED WITH")
        for r in v.ls(args.user, pw):
            if "error" in r:
                print(f"{r['id'][:8]:<9} !! {r['error']}")
                continue
            created = datetime.fromtimestamp(r["created"]).strftime("%Y-%m-%d %H:%M")
            others = ", ".join(x for x in r["recipients"] if x != r["owner"]) or "-"
            print(f"{r['id'][:8]:<9} {r['name'][:24]:<24} {r['size']:>11,}  {r['owner']:<10} {created:<16}  {others}")
    elif args.cmd == "get":
        out, meta = v.get(args.id, args.user, pw, args.out)
        print(f"decrypted {meta['name']} -> {out}\n[ok] every segment authentic  [ok] sha256 matches  [ok] signed by {meta['owner']}")
    elif args.cmd == "verify":
        meta = v.verify(args.id, args.user, pw)
        print(f"OK {meta['name']}: every segment authentic, sha256 matches, signed by {meta['owner']}")
    elif args.cmd == "share":
        v.share(args.id, args.user, pw, args.targets)
        print(f"shared with {', '.join(args.targets)}")
    elif args.cmd == "revoke":
        new_id = v.revoke(args.id, args.user, pw, args.targets)
        print(f"revoked {', '.join(args.targets)}; file re-encrypted under a new key\nid {new_id}")
    elif args.cmd == "rm":
        v.remove(args.id, args.user, pw)
        print("deleted")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        run(args)
    except (VaultError, CryptoError, OSError) as e:
        sys.exit(f"error: {e}")
    except (KeyboardInterrupt, EOFError):
        sys.exit(130)
