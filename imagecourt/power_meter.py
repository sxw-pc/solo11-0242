from .store import one, rows
from . import safety


def run(db, x):
    op = x['op']
    if op == 'calibrate':
        old = one(db, 'SELECT MAX(generation) AS g FROM probe_calibrations WHERE probe=?', (x['probe'],))
        generation = (old['g'] or 0) + 1
        if x['valid_until'] <= x['at']:
            return {'decision': 'invalid_calibration_window'}
        db.execute('INSERT INTO probe_calibrations VALUES(?,?,?,?)',
                   (x['probe'], x['at'], x['valid_until'], generation))
        return {'decision': 'calibrated', 'generation': generation}
    if op == 'sample':
        # Independent metering: every raw reading is retained, including ones
        # later judged mispointed or taken with an expired calibration.
        db.execute('INSERT INTO voltage_samples VALUES(?,?,?,?,?)',
                   (x['id'], x['breaker'], x['source'], x['volts'], x['at']))
        probe = safety.probe_of(x['source'])
        if probe is not None and not safety.probe_trusted(db, probe, x['at']):
            return {'decision': 'sampled_uncalibrated'}
        withdrawal = None
        if x['volts'] > safety.SAFE_VOLTS:
            owner = safety.rack_of_breaker(db, x['breaker'])
            if owner:
                withdrawal = safety.auto_withdraw_if_live(db, owner, x['at'])
        return {'decision': 'sampled', 'withdrawal': withdrawal}
    if op == 'inspect':
        sample = one(db, '''SELECT * FROM voltage_samples WHERE breaker=?
                            ORDER BY at DESC,id DESC LIMIT 1''', (x['breaker'],))
        if not sample:
            return {'decision': 'unknown'}
        probe = safety.probe_of(sample['source'])
        trusted = probe is None or safety.probe_trusted(db, probe, sample['at'])
        return {'decision': 'observed', 'volts': sample['volts'],
                'source': sample['source'], 'trusted': trusted}
    if op == 'diagnose':
        verdict = safety.diagnose_breaker(db, x['breaker'], x['at'])
        result = {'decision': verdict['verdict']}
        for key in ('command', 'position', 'sample'):
            if verdict.get(key):
                result[key] = {k: verdict[key][k] for k in verdict[key]
                               if k in ('id', 'breaker', 'action', 'state', 'position',
                                        'source', 'volts', 'at', 'reason')}
        return result
    raise ValueError(op)
