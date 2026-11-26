from .store import one, rows


def run(db, x):
    if x['op'] == 'meter':
        if x['kwh'] < 0:
            return {'decision': 'invalid_meter'}
        db.execute('INSERT INTO electricity_readings VALUES(?,?,?,?,?,?)',
                   (x['id'], x['site'], x['period'], x['kwh'], x['source'], x['revision']))
        return {'decision': 'meter_recorded'}
    if x['op'] == 'build':
        manifest = one(db, 'SELECT * FROM manifests WHERE digest=?', (x['digest'],))
        if not manifest or manifest['batch'] != x['batch']:
            return {'decision': 'unknown_batch'}
        db.execute('INSERT INTO build_energy_runs VALUES(?,?,?,?,?,?)',
                   (x['id'], x['batch'], x['digest'], x['site'], x['starts'], x['ends']))
        return {'decision': 'build_recorded'}
    if x['op'] == 'claim':
        run = one(db, 'SELECT * FROM build_energy_runs WHERE id=?', (x['run'],))
        reading = one(db, 'SELECT * FROM electricity_readings WHERE id=?', (x['reading'],))
        if not run or not reading or x['kwh'] > reading['kwh']:
            return {'decision': 'claim_denied'}
        db.execute('INSERT INTO green_claims VALUES(?,?,?,?,?)',
                   (x['id'], x['run'], x['reading'], x['kwh'], 'draft'))
        return {'decision': 'draft_claim'}
    raise ValueError(x['op'])
