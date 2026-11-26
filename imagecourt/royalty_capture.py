"""Provisional component royalty tally for a published image."""
import json


def provisional_dues(db, digest, rate):
    row = db.execute("SELECT components FROM sboms WHERE digest=?", (digest,)).fetchone()
    if not row:
        return 0
    components = json.loads(row[0])
    leases = db.execute("SELECT COUNT(*) FROM leases WHERE digest=?", (digest,)).fetchone()[0]
    return len(components) * leases * rate
