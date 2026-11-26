from .store import one, rows


def run(db, x):
    if x['op'] == 'loop':
        if x['flow_limit'] <= 0:
            return {'decision': 'invalid_loop'}
        db.execute('INSERT INTO cooling_loops VALUES(?,?,?,?,?)',
                   (x['id'], x['site'], x['flow_limit'], x['temp_limit'], 'active'))
        return {'decision': 'loop_recorded'}
    if x['op'] == 'sample':
        loop = one(db, 'SELECT * FROM cooling_loops WHERE id=?', (x['loop'],))
        if not loop:
            return {'decision': 'loop_missing'}
        db.execute('INSERT INTO water_samples VALUES(?,?,?,?,?,?)',
                   (x['id'], x['loop'], x['point'], x['at'], x['flow'], x['temperature']))
        return {'decision': 'water_sampled'}
    if x['op'] == 'build':
        manifest = one(db, 'SELECT * FROM manifests WHERE digest=?', (x['digest'],))
        if not manifest or manifest['batch'] != x['batch']:
            return {'decision': 'unknown_batch'}
        db.execute('INSERT INTO cooling_builds VALUES(?,?,?,?,?)',
                   (x['id'], x['batch'], x['loop'], x['starts'], x['ends']))
        return {'decision': 'build_linked'}
    if x['op'] == 'valve':
        loop = one(db, 'SELECT * FROM cooling_loops WHERE id=?', (x['loop'],))
        if not loop:
            return {'decision': 'loop_missing'}
        db.execute('INSERT INTO valve_intents VALUES(?,?,?,?,?)',
                   (x['id'], x['loop'], x['position'], x['at'], 'sent'))
        return {'decision': 'valve_command_sent'}
    if x['op'] == 'report':
        loop = one(db, 'SELECT * FROM cooling_loops WHERE id=?', (x['loop'],))
        if not loop:
            return {'decision': 'loop_missing'}
        measured = rows(db, 'SELECT flow FROM water_samples WHERE loop=?', (x['loop'],))
        volume = sum(item['flow'] for item in measured)
        db.execute('INSERT INTO water_reports VALUES(?,?,?,?,?)',
                   (x['id'], x['loop'], x['period'], volume, 'draft'))
        return {'decision': 'report_drafted', 'volume': volume}
    raise ValueError(x['op'])
