from .store import one


def run(db, x):
    if x['op'] == 'rack':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone or zone['status'] != 'open' or x['mass'] > zone['load_limit']:
            return {'decision': 'rack_denied'}
        db.execute('INSERT INTO site_racks VALUES(?,?,?,?,?)',
                   (x['id'], x['zone'], x['mass'], x['function'], 'installed'))
        return {'decision': 'rack_installed'}
    raise ValueError(x['op'])
