"""Shared evidence primitives for physical isolation.

The four evidence families come from independent sources and must never be
substituted for one another:

* control commands      -> switch_commands / breaker_commands (console)
* switch position       -> switch_positions (local position indicator)
* independent metering  -> voltage_samples + probe_calibrations (probe)
* field lockout         -> lockouts (padlock/tag applied on site)

A console command with a lost acknowledgement cannot be inferred as an
externally open switch: only a trusted local position plus an independent
zero-voltage measurement can establish that.
"""

from .store import one, rows

SAFE_VOLTS = 50
PROBE_SOURCE_PREFIX = 'probe:'


def rack_generation(db, rack):
    rack_row = one(db, 'SELECT * FROM racks WHERE id=?', (rack,))
    return rack_row['generation'] if rack_row else None


def breakers_for_rack(db, rack):
    return [f['breaker'] for f in rows(
        'SELECT breaker FROM rack_feeds WHERE rack=? ORDER BY feed', (rack,))]


def rack_of_breaker(db, breaker):
    feed = one(db, 'SELECT rack FROM rack_feeds WHERE breaker=?', (breaker,))
    return feed['rack'] if feed else None


def probe_trusted(db, probe, at):
    """A probe reading is trustworthy only with a current calibration."""
    cal = one(db, '''SELECT * FROM probe_calibrations WHERE probe=?
                     AND calibrated_at<=? AND valid_until>?
                     ORDER BY generation DESC LIMIT 1''', (probe, at, at))
    return cal is not None


def probe_of(source):
    return source[len(PROBE_SOURCE_PREFIX):] if source.startswith(PROBE_SOURCE_PREFIX) else None


def latest_sample(db, breaker, at=None):
    if at is None:
        return one(db, '''SELECT * FROM voltage_samples WHERE breaker=?
                          ORDER BY at DESC,id DESC LIMIT 1''', (breaker,))
    return one(db, '''SELECT * FROM voltage_samples WHERE breaker=? AND at<=?
                      ORDER BY at DESC,id DESC LIMIT 1''', (breaker, at))


def trusted_latest_sample(db, breaker, at):
    """Latest *calibrated* sample on the breaker at or before ``at``."""
    candidates = rows(db, '''SELECT * FROM voltage_samples WHERE breaker=? AND at<=?
                             ORDER BY at DESC,id DESC''', (breaker, at))
    for sample in candidates:
        probe = probe_of(sample['source'])
        if probe is None or probe_trusted(db, probe, sample['at']):
            return sample
    return None


def latest_command(db, breaker):
    return one(db, '''SELECT * FROM switch_commands WHERE breaker=?
                      ORDER BY at DESC,id DESC LIMIT 1''', (breaker,))


def latest_position(db, breaker):
    return one(db, '''SELECT * FROM switch_positions WHERE breaker=?
                      ORDER BY at DESC,id DESC LIMIT 1''', (breaker,))


def latest_lockout(db, breaker):
    return one(db, '''SELECT * FROM lockouts WHERE breaker=?
                      ORDER BY at DESC,id DESC LIMIT 1''', (breaker,))


def legacy_open_ack(db, breaker):
    """Pre-existing console ack channel; command evidence only, never proof."""
    row = one(db, '''SELECT * FROM breaker_commands WHERE breaker=?
                     ORDER BY rowid DESC LIMIT 1''', (breaker,))
    return row if row and row['action'] == 'open' else None


def effective_command(db, breaker):
    cmd = latest_command(db, breaker)
    if cmd:
        return cmd
    ack = legacy_open_ack(db, breaker)
    if ack:
        return {'id': ack['id'], 'breaker': breaker, 'action': 'open',
                'state': 'acknowledged', 'at': None, 'reason': 'legacy-ack'}
    return None


def diagnose_breaker(db, breaker, at):
    """Classify the command/position/metering conflict on one breaker.

    Returns a dict with ``verdict`` in:
      isolated          position open, calibrated probe shows safe voltage
      live_backfeed     position/command open but calibrated probe still live
      meter_mispointed  live reading comes from another rack's breaker
      probe_uncalibrated conflicting reading comes from an expired probe
      ack_unverified    open command never confirmed by position or metering
      not_open          no open evidence at all
    """
    owner = rack_of_breaker(db, breaker)
    cmd = effective_command(db, breaker)
    pos = latest_position(db, breaker)
    sample = latest_sample(db, breaker, at)
    evidence = {'breaker': breaker, 'rack': owner, 'command': cmd,
                'position': pos, 'sample': sample}
    if sample and sample['volts'] > SAFE_VOLTS:
        probe = probe_of(sample['source'])
        if probe is not None and not probe_trusted(db, probe, sample['at']):
            return {'verdict': 'probe_uncalibrated', **evidence}
        sample_owner = rack_of_breaker(db, sample['breaker'])
        if sample_owner != owner:
            return {'verdict': 'meter_mispointed', **evidence}
        if (cmd and cmd['action'] == 'open') or (pos and pos['position'] == 'open'):
            return {'verdict': 'live_backfeed', **evidence}
        return {'verdict': 'not_open', **evidence}
    trusted = trusted_latest_sample(db, breaker, at)
    if pos and pos['position'] == 'open' and trusted and trusted['volts'] <= SAFE_VOLTS:
        return {'verdict': 'isolated', **evidence}
    if cmd and cmd['action'] == 'open' and cmd['state'] in ('sent', 'lost'):
        return {'verdict': 'ack_unverified', **evidence}
    if not cmd or cmd['action'] != 'open':
        return {'verdict': 'not_open', **evidence}
    return {'verdict': 'ack_unverified', **evidence}


def evaluate_point(db, breaker, at):
    """Full evidence requirement for one isolation point.

    Returns (ok, code, detail). ``ok`` means the point is proven de-energized
    by independent sources, not merely commanded open.
    """
    owner = rack_of_breaker(db, breaker)
    if not owner:
        return False, 'unknown_breaker', {'breaker': breaker}
    cmd = effective_command(db, breaker)
    if not cmd or cmd['action'] != 'open':
        return False, 'breaker_not_open', {'breaker': breaker}
    if cmd['state'] == 'lost':
        return False, 'ack_lost_external_state_unknown', {'breaker': breaker, 'command': cmd}
    pos = latest_position(db, breaker)
    if not pos or pos['position'] != 'open':
        return False, 'switch_position_unverified', {'breaker': breaker, 'command': cmd}
    sample = trusted_latest_sample(db, breaker, at)
    if not sample:
        return False, 'no_trusted_voltage_sample', {'breaker': breaker}
    if sample['volts'] > SAFE_VOLTS:
        verdict = diagnose_breaker(db, breaker, at)
        return False, verdict['verdict'], {'breaker': breaker, 'sample': sample}
    lockout = latest_lockout(db, breaker)
    if not lockout or lockout['state'] != 'applied' or lockout['at'] > at:
        return False, 'lockout_missing', {'breaker': breaker}
    return True, 'isolated', {'breaker': breaker, 'command': cmd,
                              'position': pos, 'sample': sample, 'lockout': lockout}


def open_backfeed_paths(db, rack, at):
    paths = rows(db, 'SELECT * FROM backfeed_paths WHERE rack=?', (rack,))
    open_paths = []
    for path in paths:
        if path['state'] == 'cleared' and path['cleared_at'] is not None and path['cleared_at'] <= at:
            continue
        open_paths.append(path)
    return open_paths


def auto_withdraw_if_live(db, rack, at):
    """A post-issuance live/conflicting reading immediately narrows the permit."""
    permit = one(db, "SELECT * FROM electrical_permits WHERE rack=? AND status IN ('issued','reissued') ORDER BY issued_at DESC,id DESC LIMIT 1", (rack,))
    if not permit:
        return None
    for breaker in breakers_for_rack(db, rack):
        verdict = diagnose_breaker(db, breaker, at)
        if verdict['verdict'] in ('live_backfeed', 'probe_uncalibrated', 'meter_mispointed'):
            reason = verdict['verdict']
            db.execute('UPDATE electrical_permits SET status=?,revoked_at=?,revoke_reason=? WHERE id=?',
                       ('withdrawn', at, reason, permit['id']))
            db.execute('INSERT INTO permit_events(permit_id,event,at,detail) VALUES(?,?,?,?)',
                       (permit['id'], 'auto_withdrawn', at, reason))
            db.execute("UPDATE field_entries SET state='evacuated',at=? WHERE permit_id=? AND state='onsite'",
                       (at, permit['id']))
            return {'permit': permit['id'], 'reason': reason, 'breaker': breaker}
    return None
