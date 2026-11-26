from .store import one, rows


def run(db, x):
    if x['op'] == 'zone':
        if x['load_limit'] < 1:
            return {'decision': 'invalid_zone'}
        db.execute('INSERT INTO structural_zones VALUES(?,?,?,?,?)',
                   (x['id'], x['site'], x['load_limit'], x['revision'], 'open'))
        return {'decision': 'zone_recorded'}
    if x['op'] == 'sample':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        db.execute('INSERT INTO shaking_samples VALUES(?,?,?,?,?)',
                   (x['id'], x['zone'], x['sensor'], x['at'], x['acceleration']))
        return {'decision': 'shaking_recorded'}
    if x['op'] == 'inspect':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        samples = rows(db, 'SELECT acceleration FROM shaking_samples WHERE zone=?', (x['zone'],))
        if not samples:
            return {'decision': 'measurement_missing'}
        status = 'restricted' if max(s['acceleration'] for s in samples) > x['threshold'] else 'open'
        db.execute('UPDATE structural_zones SET status=? WHERE id=?', (status, x['zone']))
        db.execute('INSERT INTO structural_inspections VALUES(?,?,?,?,?)',
                   (x['id'], x['zone'], x['engineer'], x['at'], status))
        return {'decision': status}
    raise ValueError(x['op'])
