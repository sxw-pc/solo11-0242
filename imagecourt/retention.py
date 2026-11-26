from .store import one, rows


def run(db, x):
    if x['op'] == 'copy':
        if not one(db, 'SELECT 1 FROM manifests WHERE digest=?', (x['digest'],)):
            return {'decision': 'unknown_image'}
        db.execute('INSERT INTO artifact_copies VALUES(?,?,?,?,?)',
                   (x['id'], x['digest'], x['tenant'], x['site'], x['payload']))
        return {'decision': 'copy_recorded'}
    if x['op'] == 'hold':
        db.execute('INSERT INTO preservation_orders VALUES(?,?,?,?,?)',
                   (x['id'], x['tenant'], x['digest'], x['scope'], 'active'))
        return {'decision': 'hold_recorded'}
    if x['op'] == 'erase':
        copies = rows(db, 'SELECT id FROM artifact_copies WHERE digest=? AND tenant=?',
                      (x['digest'], x['tenant']))
        db.execute('INSERT INTO erase_requests VALUES(?,?,?,?,?)',
                   (x['id'], x['tenant'], x['digest'], x['at'], 'requested'))
        return {'decision': 'erase_requested', 'copies': len(copies)}
    raise ValueError(x['op'])
