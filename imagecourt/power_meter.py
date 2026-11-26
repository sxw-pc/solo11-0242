from .store import one


def run(db, x):
    op = x['op']
    if op == 'sample':
        db.execute('INSERT INTO voltage_samples VALUES(?,?,?,?,?)',
                   (x['id'], x['breaker'], x['source'], x['volts'], x['at']))
        return {'decision': 'sampled'}
    if op == 'inspect':
        sample = one(db, 'SELECT * FROM voltage_samples WHERE breaker=? ORDER BY at DESC,id DESC LIMIT 1',
                     (x['breaker'],))
        return {'decision': 'observed', 'volts': sample['volts'], 'source': sample['source']} if sample else {'decision': 'unknown'}
    raise ValueError(op)
