import json

from .store import one, rows
from . import safety


def _permit_active(db, permit_id):
    permit = one(db, 'SELECT * FROM electrical_permits WHERE id=?', (permit_id,))
    return permit if permit and permit['status'] in ('issued', 'reissued') else None


def _running_workloads(db, rack):
    bounds = rows(db, 'SELECT workload FROM rack_workloads WHERE rack=?', (rack,))
    running = []
    for bound in bounds:
        lease = one(db, "SELECT id FROM leases WHERE workload=? AND status='active'", (bound['workload'],))
        if lease:
            running.append({'workload': bound['workload'], 'lease': lease['id']})
    return running


def _check_rack_evidence(db, rack, generation, at):
    rack_row = one(db, 'SELECT * FROM racks WHERE id=?', (rack,))
    if not rack_row:
        return 'unknown_rack', None
    if generation is not None and generation != rack_row['generation']:
        return 'stale_rack_generation', {'expected': rack_row['generation'], 'received': generation}
    feeds = rows(db, 'SELECT * FROM rack_feeds WHERE rack=? ORDER BY feed', (rack,))
    if not feeds:
        return 'unknown_rack', None
    window = one(db, 'SELECT * FROM repair_windows WHERE rack=?', (rack,))
    if not window or not (window['start'] <= at < window['expires']):
        return 'outside_repair_window', None
    running = _running_workloads(db, rack)
    if running:
        return 'workloads_running', {'workloads': running}
    missing = rows(db, "SELECT serial FROM repair_parts WHERE rack=? AND state!='installed'", (rack,))
    if not rows(db, 'SELECT serial FROM repair_parts WHERE rack=?', (rack,)):
        return 'part_not_registered', None
    if missing:
        return 'part_not_installed', {'serials': [m['serial'] for m in missing]}
    open_paths = safety.open_backfeed_paths(db, rack, at)
    if open_paths:
        return 'backfeed_path_open', {'paths': [p['id'] for p in open_paths]}
    for feed in feeds:
        ok, code, detail = safety.evaluate_point(db, feed['breaker'], at)
        if not ok:
            return code, detail
    return None, {'feeds': feeds, 'window': window}


def _issue_permit(db, x, supersedes=None):
    rack = x['rack']
    code, detail = _check_rack_evidence(db, rack, x.get('generation'), x['at'])
    if code:
        return {'decision': code, **({'detail': detail} if detail else {})}
    evidence = []
    for breaker in safety.breakers_for_rack(db, rack):
        ok, _, point = safety.evaluate_point(db, breaker, x['at'])
        evidence.append(point)
    scope = {
        'rack': rack,
        'touchable': {
            'breakers': safety.breakers_for_rack(db, rack),
            'parts': [p['serial'] for p in rows(db,
                     "SELECT serial FROM repair_parts WHERE rack=?", (rack,))],
        },
        'forbidden': 'other racks, upstream busbars and any shared breaker',
    }
    disposition = x.get('disposition', 'contract_pause')
    impact = _service_impact(db, rack, disposition)
    db.execute('INSERT INTO electrical_permits VALUES(?,?,?,?,?,?,?,?,?,?)',
               (x['id'], rack, 'issued' if supersedes is None else 'reissued', x['at'],
                json.dumps(scope, ensure_ascii=False), disposition,
                json.dumps(evidence, ensure_ascii=False), supersedes, None, None))
    if supersedes:
        db.execute("UPDATE electrical_permits SET status='superseded' WHERE id=?", (supersedes,))
    db.execute('INSERT INTO permit_events(permit_id,event,at,detail) VALUES(?,?,?,?)',
               (x['id'], 'issued', x['at'], disposition))
    return {'decision': 'safe', 'permit': x['id'], 'scope': scope,
            'disposition': disposition, 'service_impact': impact, 'evidence': evidence}


def _service_impact(db, rack, disposition):
    workloads = [b['workload'] for b in rows(db, 'SELECT workload FROM rack_workloads WHERE rack=?', (rack,))]
    if disposition == 'migration':
        return {'customer_builds': workloads,
                'effect': 'continued on standby rack under migrated leases; outputs chain to the original task',
                'downtime_responsibility': 'none if migration is verified'}
    return {'customer_builds': workloads,
            'effect': 'contractually paused until repair acceptance and restart decision',
            'downtime_responsibility': 'recorded against the maintenance window'}


def run(db, x):
    op = x['op']
    if op == 'rack':
        old = one(db, 'SELECT * FROM racks WHERE id=?', (x['id'],))
        if old:
            return {'decision': 'reused' if old['generation'] == x['generation'] else 'rack_identity_conflict'}
        db.execute('INSERT INTO racks VALUES(?,?,?)', (x['id'], x['generation'], x.get('standby_for')))
        return {'decision': 'bound'}
    if op == 'feed':
        rack_row = one(db, 'SELECT * FROM racks WHERE id=?', (x['rack'],))
        if not rack_row:
            return {'decision': 'unknown_rack'}
        db.execute('INSERT INTO rack_feeds VALUES(?,?,?)', (x['rack'], x['feed'], x['breaker']))
        return {'decision': 'bound'}
    if op == 'workload':
        db.execute('INSERT INTO rack_workloads VALUES(?,?)', (x['rack'], x['workload']))
        return {'decision': 'bound'}
    if op == 'backfeed_path':
        old = one(db, 'SELECT * FROM backfeed_paths WHERE id=?', (x['id'],))
        if old:
            return {'decision': 'reused' if old['breaker'] == x['breaker'] else 'backfeed_identity_conflict'}
        db.execute('INSERT INTO backfeed_paths VALUES(?,?,?,?,?,?)',
                   (x['id'], x['rack'], x['breaker'], x['label'], 'open', None))
        return {'decision': 'registered'}
    if op == 'backfeed_clear':
        path = one(db, 'SELECT * FROM backfeed_paths WHERE id=?', (x['id'],))
        if not path:
            return {'decision': 'unknown_path'}
        if path['state'] == 'cleared':
            return {'decision': 'reused'}
        db.execute('UPDATE backfeed_paths SET state=?,cleared_at=? WHERE id=?',
                   ('cleared', x['at'], x['id']))
        return {'decision': 'cleared'}
    if op == 'part':
        old = one(db, 'SELECT * FROM repair_parts WHERE serial=?', (x['serial'],))
        if old:
            return {'decision': 'reused' if old['rack'] == x['rack'] else 'part_identity_conflict'}
        db.execute('INSERT INTO repair_parts VALUES(?,?,?,?)',
                   (x['serial'], x['rack'], x['position'], 'registered'))
        return {'decision': 'registered'}
    if op == 'part_install':
        part = one(db, 'SELECT * FROM repair_parts WHERE serial=?', (x['serial'],))
        if not part:
            return {'decision': 'unknown_part'}
        db.execute("UPDATE repair_parts SET state='installed' WHERE serial=?", (x['serial'],))
        return {'decision': 'installed'}
    if op == 'window':
        if x['start'] >= x['expires']:
            return {'decision': 'invalid_window'}
        old = one(db, 'SELECT * FROM repair_windows WHERE rack=?', (x['rack'],))
        if old and x['generation'] <= old['generation']:
            return {'decision': 'invalid_window_version'}
        db.execute('INSERT INTO repair_windows VALUES(?,?,?,?) ON CONFLICT(rack) DO UPDATE SET start=excluded.start,expires=excluded.expires,generation=excluded.generation',
                   (x['rack'], x['start'], x['expires'], x['generation']))
        return {'decision': 'window_recorded'}
    if op == 'breaker_ack':
        old = one(db, 'SELECT id FROM breaker_commands WHERE id=?', (x['id'],))
        if old:
            return {'decision': 'reused'}
        db.execute('INSERT INTO breaker_commands VALUES(?,?,?,?)',
                   (x['id'], x['breaker'], x['action'], x['ack']))
        return {'decision': 'acknowledged'}
    if op == 'dispatch':
        rack_row = one(db, 'SELECT * FROM racks WHERE id=?', (x['rack'],))
        if not rack_row:
            return {'decision': 'unknown_rack'}
        owner = safety.rack_of_breaker(db, x['breaker'])
        if owner != x['rack']:
            return {'decision': 'breaker_not_bound'}
        last = safety.latest_command(db, x['breaker'])
        position = safety.latest_position(db, x['breaker'])
        unresolved_open = last and last['action'] == 'open' and last['state'] in ('sent', 'lost') \
            and not (position and position['position'] == 'open')
        if unresolved_open:
            return {'decision': 'duplicate_open_command', 'command': last['id']}
        shared = [r['rack'] for r in rows(db, 'SELECT DISTINCT rack FROM rack_feeds WHERE breaker=?', (x['breaker'],))
                  if r['rack'] != x['rack']]
        for other in shared:
            if _running_workloads(db, other):
                return {'decision': 'shared_breaker_other_rack_powered', 'other_rack': other}
        state = x.get('state', 'sent')
        db.execute('INSERT INTO switch_commands VALUES(?,?,?,?,?,?,?)',
                   (x['id'], x['rack'], x['breaker'], x['action'], state, x['at'], x.get('reason')))
        return {'decision': 'dispatched', 'state': state}
    if op == 'command_outcome':
        cmd = one(db, 'SELECT * FROM switch_commands WHERE id=?', (x['id'],))
        if not cmd:
            return {'decision': 'unknown_command'}
        if cmd['state'] == x['state']:
            return {'decision': 'reused'}
        db.execute('UPDATE switch_commands SET state=? WHERE id=?', (x['state'], x['id']))
        return {'decision': x['state']}
    if op == 'position':
        if x['position'] not in ('open', 'closed'):
            return {'decision': 'invalid_position'}
        db.execute('INSERT INTO switch_positions VALUES(?,?,?,?,?)',
                   (x['id'], x['breaker'], x['position'], x['source'], 1 if x.get('trusted', True) else 0, x['at']))
        return {'decision': 'position_recorded'}
    if op == 'lockout':
        if x['state'] not in ('applied', 'removed'):
            return {'decision': 'invalid_lockout_state'}
        old = one(db, 'SELECT * FROM lockouts WHERE id=?', (x['id'],))
        if old:
            return {'decision': 'reused'}
        db.execute('INSERT INTO lockouts VALUES(?,?,?,?,?,?)',
                   (x['id'], x['rack'], x['breaker'], x['technician'], x['state'], x['at']))
        return {'decision': x['state']}
    if op == 'permit':
        return _issue_permit(db, x)
    if op == 'reissue':
        old = one(db, 'SELECT * FROM electrical_permits WHERE id=?', (x['supersedes'],))
        if not old:
            return {'decision': 'unknown_permit'}
        if old['status'] not in ('withdrawn', 'superseded'):
            return {'decision': 'permit_still_active'}
        return _issue_permit(db, x, supersedes=x['supersedes'])
    if op == 'withdraw':
        permit = one(db, 'SELECT * FROM electrical_permits WHERE id=?', (x['id'],))
        if not permit:
            return {'decision': 'unknown_permit'}
        if permit['status'] in ('withdrawn', 'closed', 'superseded'):
            return {'decision': 'permit_not_active'}
        db.execute('UPDATE electrical_permits SET status=?,revoked_at=?,revoke_reason=? WHERE id=?',
                   ('withdrawn', x['at'], x['reason']))
        db.execute('INSERT INTO permit_events(permit_id,event,at,detail) VALUES(?,?,?,?)',
                   (x['id'], 'withdrawn', x['at'], x['reason']))
        db.execute("UPDATE field_entries SET state='evacuated',at=? WHERE permit_id=? AND state='onsite'",
                   (x['at'], x['id']))
        return {'decision': 'withdrawn', 'permit': x['id'], 'reason': x['reason']}
    if op == 'entry':
        if not _permit_active(db, x['permit']):
            return {'decision': 'permit_not_active'}
        old = one(db, 'SELECT * FROM field_entries WHERE id=?', (x['id'],))
        if old:
            return {'decision': 'reused'}
        db.execute('INSERT INTO field_entries VALUES(?,?,?,?,?)',
                   (x['id'], x['permit'], x['rack'], 'onsite', x['at']))
        return {'decision': 'onsite'}
    if op == 'exit':
        entry = one(db, 'SELECT * FROM field_entries WHERE id=?', (x['id'],))
        if not entry:
            return {'decision': 'unknown_entry'}
        if entry['state'] != 'onsite':
            return {'decision': 'reused'}
        db.execute("UPDATE field_entries SET state='left' WHERE id=?", (x['id'],))
        return {'decision': 'left'}
    if op == 'acceptance':
        permit = one(db, 'SELECT * FROM electrical_permits WHERE id=?', (x['permit'],))
        if not permit:
            return {'decision': 'unknown_permit'}
        if rows(db, "SELECT serial FROM repair_parts WHERE rack=? AND state!='installed'", (permit['rack'],)):
            return {'decision': 'part_not_installed'}
        if rows(db, "SELECT id FROM lockouts WHERE rack=? AND state='applied'", (permit['rack'],)):
            return {'decision': 'lockout_still_applied'}
        db.execute('INSERT OR REPLACE INTO repair_acceptances VALUES(?,?,?,?)',
                   (permit['rack'], x['at'], x['permit'], x.get('detail', '')))
        db.execute("UPDATE electrical_permits SET status='closed' WHERE id=?", (x['permit'],))
        db.execute('INSERT INTO permit_events(permit_id,event,at,detail) VALUES(?,?,?,?)',
                   (x['permit'], 'closed', x['at'], 'repair accepted'))
        return {'decision': 'accepted', 'rack': permit['rack']}
    if op == 'status':
        permit = one(db, 'SELECT * FROM electrical_permits WHERE id=?', (x['id'],))
        if not permit:
            return {'decision': 'unknown_permit'}
        return {'decision': permit['status'], 'permit': permit['id'], 'rack': permit['rack'],
                'disposition': permit['disposition'], 'scope': json.loads(permit['scope']),
                'revoke_reason': permit['revoke_reason']}
    raise ValueError(op)
