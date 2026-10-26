"""Tamper-evident access log: an HMAC hash chain.

Each entry records the MAC of the entry before it ("prev") and carries its own MAC
over all of its fields. Editing, deleting, inserting or reordering any entry breaks
the chain from that point on. The MAC key lives inside the sealed system keystore,
so someone with disk access can't recompute valid MACs.

Limitation: removing entries from the END leaves a valid (shorter) chain. Detecting
that needs an external anchor, e.g. periodically publishing the latest MAC somewhere else.
"""
import json
import threading
import time

from . import crypto
from .crypto import canon


class AuditLog:
    def __init__(self, path, key: bytes):
        self.path, self.key = path, key
        self.lock = threading.Lock()
        lines = path.read_text().splitlines() if path.exists() else []
        try:
            self.last_mac = json.loads(lines[-1])["mac"] if lines else ""
        except (ValueError, KeyError, TypeError):
            self.last_mac = ""

    def append(self, actor: str, action: str, file_id: str | None = None, detail: str = ""):
        with self.lock:
            entry = {"ts": int(time.time()), "actor": actor[:254], "action": action,
                     "file": file_id, "detail": detail, "prev": self.last_mac}
            tag = crypto.mac(self.key, canon(entry))
            with open(self.path, "a") as f:
                f.write(json.dumps({**entry, "mac": tag}) + "\n")
            self.last_mac = tag

    def read(self):
        """Return (entries, index of the first broken entry, or None if the whole chain verifies)."""
        entries, prev = [], ""
        lines = self.path.read_text().splitlines() if self.path.exists() else []
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
                tag = entry.pop("mac")
                ok = entry.get("prev") == prev and crypto.mac_ok(self.key, canon(entry), tag)
            except (ValueError, KeyError, TypeError, AttributeError):
                ok = False
            if not ok:
                return entries, i
            entries.append(entry)
            prev = tag
        return entries, None
