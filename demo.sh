#!/usr/bin/env bash
# Live walkthrough of CryptoVault for presentations.
#   ./demo.sh           run straight through
#   PAUSE=1 ./demo.sh   wait for Enter before each step
# Uses a throwaway vault in a temp directory; your real ./vault is never touched.
set -euo pipefail
cd "$(dirname "$0")"
PY=${PY:-.venv/bin/python}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export CRYPTOVAULT_DIR="$WORK/vault"

# Run a command as a given user. Passwords come from the environment only because this is a scripted demo.
as() { local u=$1; shift; CRYPTOVAULT_USER=$u CRYPTOVAULT_PASSWORD="$u-password" "$PY" -m cryptovault "$@"; }
step() {
  printf '\n\033[1;36m== %s\033[0m\n' "$*"
  if [[ -n "${PAUSE:-}" ]]; then read -r _; fi
}
show() { printf '\033[2m$ %s\033[0m\n' "$*"; }

step "1. Create three users. Each gets an RSA-3072 key pair (encryption) and an Ed25519 key pair (signing)"
for u in alice bob eve; do show "cryptovault adduser $u"; as "$u" adduser "$u"; done

step "2. Public key fingerprints (compare these out-of-band to detect a swapped key)"
as alice users

step "3. Alice stores a confidential report and shares it with Bob"
printf 'Q3 results: revenue up 40%%. Do not distribute.\n' > "$WORK/report.txt"
show "cryptovault put report.txt --share bob   (as alice)"
ID=$(as alice put "$WORK/report.txt" --share bob | tee /dev/stderr | awk '/^id/{print $2}')
FILE="$CRYPTOVAULT_DIR/files/$ID.cvault"

step "4. What is actually on disk: a public header (wrapped keys), then pure ciphertext. The filename is not visible"
"$PY" - "$FILE" <<'EOF'
import json, sys
from cryptovault.vault import _read_container
with open(sys.argv[1], "rb") as f:
    header, meta_ct = _read_container(f)
    data = f.read()
short = lambda s: s if len(s) < 40 else s[:36] + "..."
print("header:", json.dumps({k: ({u: short(w) for u, w in v.items()} if k == "recipients" else v) for k, v in header.items()}, indent=2))
print("metadata ciphertext:", meta_ct[:24].hex(), "...", f"({len(meta_ct)} bytes)")
print("data ciphertext:    ", data[:24].hex(), "...", f"({len(data)} bytes)")
EOF
grep -q "report.txt" "$FILE" && echo "filename LEAKED" || echo "(the string 'report.txt' does not appear anywhere in the file)"

step "5. Bob lists and decrypts it. The owner's signature is verified automatically"
as bob ls
as bob get "${ID:0:8}" -o "$WORK/bob-copy.txt"
cat "$WORK/bob-copy.txt"

step "6. Eve is not a recipient"
as eve ls
as eve get "${ID:0:8}" -o "$WORK/eve.txt" || true

step "7. An attacker flips ONE bit in the ciphertext"
cp "$FILE" "$WORK/backup"
"$PY" -c "import sys; p=sys.argv[1]; b=bytearray(open(p,'rb').read()); b[-20]^=1; open(p,'wb').write(b)" "$FILE"
as bob get "${ID:0:8}" -o "$WORK/tampered.txt" || true
[[ -e "$WORK/tampered.txt" ]] && echo "plaintext released!" || echo "(no output file was written: unverified plaintext is never released)"
cp "$WORK/backup" "$FILE"

step "8. Eve forges a file that claims to come from Alice (she can only sign with her own key)"
"$PY" - "$CRYPTOVAULT_DIR" <<'EOF'
import hashlib, sys
from cryptovault.vault import Vault
v = Vault(sys.argv[1])
_, eve_sign = v.unlock("eve", "eve-password")
data = b"Pay eve $1000 -- alice"
meta = {"name": "invoice.txt", "size": len(data), "sha256": hashlib.sha256(data).hexdigest(), "owner": "alice", "created": 0}
print("forged file id", v._store([data], meta, eve_sign, {"bob"}))
EOF
as bob ls

step "9. Alice revokes Bob. The file is re-encrypted under a NEW key, so any old key Bob kept is now useless"
NEW=$(as alice revoke "${ID:0:8}" --from bob | tee /dev/stderr | awk '/^id/{print $2}')
as bob get "${NEW:0:8}" -o "$WORK/after-revoke.txt" || true
as alice verify "${NEW:0:8}"

step "Done"
