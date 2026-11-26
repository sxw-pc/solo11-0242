from .store import one, rows


def run(db, x):
    op = x['op']
    if op == 'feed':
        db.execute('INSERT INTO rack_feeds VALUES(?,?,?)', (x['rack'], x['feed'], x['breaker']))
        return {'decision': 'bound'}
    if op == 'workload':
        db.execute('INSERT INTO rack_workloads VALUES(?,?)', (x['rack'], x['workload']))
        return {'decision': 'bound'}
    if op == 'breaker_ack':
        db.execute('INSERT INTO breaker_commands VALUES(?,?,?,?)',
                   (x['id'], x['breaker'], x['action'], x['ack']))
        return {'decision': 'acknowledged'}
    if op == 'permit':
        feeds = rows(db, 'SELECT * FROM rack_feeds WHERE rack=?', (x['rack'],))
        if not feeds:
            return {'decision': 'unknown_rack'}
        for feed in feeds:
            command = one(db, 'SELECT * FROM breaker_commands WHERE breaker=? ORDER BY rowid DESC LIMIT 1',
                          (feed['breaker'],))
            if not command or command['action'] != 'open':
                return {'decision': 'breaker_not_open'}
        db.execute('INSERT INTO electrical_permits VALUES(?,?,?,?)',
                   (x['id'], x['rack'], 'safe', x['at']))
        return {'decision': 'safe'}
    if op == 'status':
        permit = one(db, 'SELECT * FROM electrical_permits WHERE id=?', (x['id'],))
        return {'decision': permit['status']} if permit else {'decision': 'unknown_permit'}
    raise ValueError(op)
