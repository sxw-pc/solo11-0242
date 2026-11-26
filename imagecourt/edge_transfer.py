"""CDN edge transfer starts for image downloads."""


def record(db, event, digest, customer, bytes_sent):
    db.execute(
        "CREATE TABLE IF NOT EXISTS edge_transfers(event TEXT PRIMARY KEY,digest TEXT,customer TEXT,bytes_sent INTEGER)"
    )
    db.execute(
        "INSERT INTO edge_transfers VALUES(?,?,?,?)",
        (event, digest, customer, bytes_sent),
    )
