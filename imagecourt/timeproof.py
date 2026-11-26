from .store import one, rows


def run(db, x):
    if x['op'] == 'source':
        db.execute('INSERT INTO clock_sources VALUES(?,?,?,?,?)',
                   (x['id'], x['operator'], x['offset_min'], x['offset_max'], 'active'))
        return {'decision': 'clock_recorded'}
    if x['op'] == 'stamp':
        source = one(db, 'SELECT * FROM clock_sources WHERE id=?', (x['source'],))
        if not source or source['status'] != 'active':
            return {'decision': 'clock_unavailable'}
        db.execute('INSERT INTO time_stamps VALUES(?,?,?,?,?)',
                   (x['id'], x['event_key'], x['source'], x['local_at'], x['claimed_utc']))
        return {'decision': 'stamp_recorded'}
    if x['op'] == 'certificate':
        stamps = rows(db, 'SELECT claimed_utc FROM time_stamps WHERE event_key=? ORDER BY claimed_utc',
                      (x['event_key'],))
        if not stamps:
            return {'decision': 'unstamped'}
        db.execute('INSERT INTO time_certificates VALUES(?,?,?,?)',
                   (x['id'], x['event_key'], stamps[0]['claimed_utc'], 'provisional'))
        return {'decision': 'provisional_time', 'at': stamps[0]['claimed_utc']}
    raise ValueError(x['op'])
