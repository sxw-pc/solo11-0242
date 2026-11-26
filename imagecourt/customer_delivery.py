"""Provisional delivered bytes from edge counters."""


def provisional_bytes(db, digest, customer):
    return db.execute(
        "SELECT COALESCE(SUM(bytes_sent),0) FROM edge_transfers WHERE digest=? AND customer=?",
        (digest, customer),
    ).fetchone()[0]
