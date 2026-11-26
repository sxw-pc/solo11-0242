"""Customer runtime settings for delivered image workloads."""

import json

SCHEMA = '''
CREATE TABLE IF NOT EXISTS tenant_configs(
    id TEXT PRIMARY KEY, customer TEXT, digest TEXT,
    memory_mb INTEGER, cpu_units INTEGER, egress_group TEXT,
    replicas INTEGER, secret_ref TEXT
);
CREATE TABLE IF NOT EXISTS config_bundles(
    id TEXT PRIMARY KEY, config_id TEXT, document TEXT, state TEXT
);
'''


def record(db, config_id, customer, digest, memory_mb, cpu_units,
           egress_group, replicas, secret_ref):
    db.executescript(SCHEMA)
    db.execute('INSERT INTO tenant_configs VALUES(?,?,?,?,?,?,?,?)',
               (config_id, customer, digest, memory_mb, cpu_units,
                egress_group, replicas, secret_ref))


def export(db, bundle_id, config_id):
    db.executescript(SCHEMA)
    row = db.execute('SELECT * FROM tenant_configs WHERE id=?',
                     (config_id,)).fetchone()
    document = json.dumps(dict(row), sort_keys=True)
    db.execute('INSERT INTO config_bundles VALUES(?,?,?,?)',
               (bundle_id, config_id, document, 'draft'))
    return document
