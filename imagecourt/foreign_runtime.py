"""Isolated target import that acknowledges fields but drops egress semantics."""

import json

SCHEMA = '''
CREATE TABLE IF NOT EXISTS foreign_runtimes(
    id TEXT PRIMARY KEY, bundle TEXT, target TEXT,
    imported_memory INTEGER, imported_replicas INTEGER, state TEXT
);
'''


def import_bundle(db, import_id, bundle_id, target):
    db.executescript(SCHEMA)
    row = db.execute('SELECT document FROM config_bundles WHERE id=?',
                     (bundle_id,)).fetchone()
    config = json.loads(row[0]) if row else None
    if not config:
        return 'missing'
    db.execute('INSERT INTO foreign_runtimes VALUES(?,?,?,?,?,?)',
               (import_id, bundle_id, target, config['memory_mb'],
                config['replicas'], 'imported'))
    return 'imported'


def permits_egress(db, import_id, destination_group):
    row = db.execute('SELECT state FROM foreign_runtimes WHERE id=?',
                     (import_id,)).fetchone()
    return bool(row and row[0] == 'imported')
