from .store import one, rows


def shoring_of(db, element_id):
    sh = one(db, 'SELECT * FROM shoring_works WHERE element=? AND status=?', (element_id, 'complete'))
    return sh if sh and sh['measured_load'] is not None else None


def element_limit(db, el):
    """Effective dynamic allowance of one load path; shoring, once complete and
    load-tested by an independent engineer, replaces the provisional limit."""
    sh = shoring_of(db, el['id'])
    return sh['measured_load'] if sh else el['current_limit']


def occupied_mass(db, element_id):
    """Mass actually bearing on one element through its anchors. Racks whose
    status is 'released' but which still sit on their anchors stay counted:
    only a verified relocation or physical removal frees the load path."""
    total = 0
    for a in rows(db, "SELECT * FROM rack_anchors WHERE element=? AND status!='removed'", (element_id,)):
        rack = one(db, 'SELECT * FROM site_racks WHERE id=?', (a['rack'],))
        if rack:
            total += rack['mass']
    return total


def review_element(db, el):
    limit = element_limit(db, el)
    occupied = occupied_mass(db, el['id'])
    shoring = shoring_of(db, el['id'])
    return {'element': el['id'], 'kind': el['kind'], 'shared': bool(el['shared']),
            'rated_limit': el['rated_limit'], 'current_limit': el['current_limit'],
            'effective_limit': limit, 'occupied': occupied,
            'overloaded': occupied > limit,
            'shoring': shoring['id'] if shoring else None}


def evidence_complete(db, zone_id):
    cracks = rows(db, "SELECT * FROM field_evidence WHERE zone=? AND kind='crack'", (zone_id,))
    anchor_checks = rows(db, "SELECT * FROM rack_anchors WHERE checked_at IS NOT NULL AND rack IN "
                             "(SELECT id FROM site_racks WHERE zone=?)", (zone_id,))
    sensors = rows(db, 'SELECT * FROM structural_sensors WHERE status=?', ('calibrated',))
    samples = rows(db, 'SELECT * FROM shaking_samples WHERE zone=?', (zone_id,))
    traced = any(one(db, 'SELECT 1 FROM structural_sensors WHERE id=? AND status=?',
                     (s['sensor'], 'calibrated')) for s in samples)
    return {
        'shaking': bool(samples) and traced,
        'calibrated_sensors': bool(sensors),
        'cracks': bool(cracks),
        'anchor_checks': bool(anchor_checks),
        'anchor_ids': [a['rack'] for a in anchor_checks],
        'crack_ids': [c['id'] for c in cracks],
        'complete': bool(samples) and traced and bool(cracks) and bool(anchor_checks),
    }


def latest_assessment(db, zone_id):
    return one(db, 'SELECT * FROM engineer_assessments WHERE zone=? ORDER BY at DESC, rowid DESC', (zone_id,))


def latest_seq(db, zone_id):
    row = one(db, 'SELECT MAX(aftershock_seq) AS m FROM shaking_samples WHERE zone=? AND aftershock_seq IS NOT NULL',
              (zone_id,))
    return row['m'] if row and row['m'] is not None else 0


def run(db, x):
    op = x['op']
    if op == 'zone':
        if x['load_limit'] < 1:
            return {'decision': 'invalid_zone'}
        db.execute('INSERT INTO structural_zones VALUES(?,?,?,?,?,?)',
                   (x['id'], x['site'], x['load_limit'], x['revision'], 'open', x.get('drawing_revision')))
        return {'decision': 'zone_recorded'}
    if op == 'element':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        if one(db, 'SELECT 1 FROM structural_elements WHERE id=?', (x['id'],)):
            return {'decision': 'element_conflict'}
        if x['rated_limit'] < 1:
            return {'decision': 'invalid_element'}
        # Before the quake the dynamic allowance equals the rated static limit.
        db.execute('INSERT INTO structural_elements VALUES(?,?,?,?,?,?,?)',
                   (x['id'], x['zone'], x['kind'], 1 if x.get('shared') else 0,
                    x['rated_limit'], x['rated_limit'], None))
        return {'decision': 'element_recorded'}
    if op == 'sensor':
        if x.get('uncertainty', 0) < 0:
            return {'decision': 'invalid_sensor'}
        db.execute('INSERT INTO structural_sensors VALUES(?,?,?,?,?)',
                   (x['id'], x['location'], x['calibration'], x['uncertainty'],
                    x.get('status', 'calibrated')))
        return {'decision': 'sensor_recorded'}
    if op == 'sample':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        sensor = one(db, 'SELECT * FROM structural_sensors WHERE id=?', (x['sensor'],))
        if sensor and sensor['status'] != 'calibrated':
            return {'decision': 'sensor_uncalibrated'}
        seq = x.get('aftershock_seq')
        if seq is not None:
            if seq < 1:
                return {'decision': 'invalid_aftershock_sequence'}
            prev = one(db, 'SELECT MAX(aftershock_seq) AS m FROM shaking_samples WHERE zone=? AND aftershock_seq IS NOT NULL',
                       (x['zone'],))
            if prev['m'] is not None and seq <= prev['m']:
                return {'decision': 'aftershock_order_violation'}
        db.execute('INSERT INTO shaking_samples VALUES(?,?,?,?,?,?)',
                   (x['id'], x['zone'], x['sensor'], x['at'], x['acceleration'], seq))
        return {'decision': 'shaking_recorded',
                'sensor_traceable': bool(sensor)}
    if op == 'crack':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        db.execute('INSERT INTO field_evidence VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], x['zone'], 'crack', x['engineer'], x['at'], x['location'],
                   x.get('measurement'), x.get('severity', 'recorded')))
        return {'decision': 'crack_recorded'}
    if op == 'shoring_record':
        el = one(db, 'SELECT * FROM structural_elements WHERE id=?', (x['element'],))
        if not el:
            return {'decision': 'element_missing'}
        if x['measured_load'] is None or x['measured_load'] < 1:
            return {'decision': 'load_test_missing'}
        if x['monitoring_cycle'] < 1:
            return {'decision': 'invalid_monitoring_cycle'}
        db.execute('INSERT INTO shoring_works VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], el['zone'], el['id'], x['engineer'], x['completed_at'],
                    x['measured_load'], x['monitoring_cycle'], 'complete'))
        db.execute('UPDATE structural_elements SET shoring_id=?, current_limit=? WHERE id=?',
                   (x['id'], x['measured_load'], el['id']))
        return {'decision': 'shoring_completed', 'effective_limit': x['measured_load']}
    if op == 'inspect':
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
    if op == 'assess':
        # Independent engineer's post-quake ruling. A sensor peak alone cannot
        # restrict or clear a zone: cracks, anchor measurements and the
        # engineer's load-tested figure are all required.
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        evidence = evidence_complete(db, x['zone'])
        if not evidence['complete']:
            return {'decision': 'field_evidence_incomplete', 'evidence': evidence}
        if x['safe_load'] < 0 or x['safe_load'] > zone['load_limit']:
            return {'decision': 'invalid_safe_load'}
        db.execute('INSERT INTO engineer_assessments VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], x['zone'], x['engineer'], x['at'],
                    x.get('drawing_revision', zone['drawing_revision']), x['safe_load'],
                    x.get('basis', 'crack_and_anchor_survey'), 'current'))
        elements = rows(db, 'SELECT * FROM structural_elements WHERE zone=?', (x['zone'],))
        overloaded = [el['id'] for el in elements if occupied_mass(db, el['id']) > x['safe_load']]
        for el in elements:
            db.execute('UPDATE structural_elements SET current_limit=? WHERE id=?',
                       (x['safe_load'], el['id']))
        zone_status = 'restricted' if overloaded or x['safe_load'] < zone['load_limit'] else 'open'
        db.execute('UPDATE structural_zones SET status=? WHERE id=?', (zone_status, x['zone']))
        return {'decision': 'assessment_recorded', 'safe_load': x['safe_load'],
                'overloaded_elements': overloaded, 'status': zone_status}
    if op == 'reentry':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        assessment = latest_assessment(db, x['zone'])
        if not assessment:
            return {'decision': 'assessment_missing'}
        evidence = evidence_complete(db, x['zone'])
        if not evidence['complete']:
            return {'decision': 'field_evidence_incomplete', 'evidence': evidence}
        strategy = x['strategy']
        retained = list(x.get('retained_racks', []))
        removed = list(x.get('removed_racks', []))
        current_racks = rows(db, 'SELECT * FROM site_racks WHERE zone=?', (x['zone'],))
        relocated = rows(db, 'SELECT rack FROM rack_relocations WHERE from_zone=?', (x['zone'],))
        known = {r['id'] for r in current_racks} | {r['rack'] for r in relocated}
        named = set(retained) | set(removed)
        if set(retained) & set(removed) or not named or named != known:
            return {'decision': 'rack_inventory_mismatch'}
        for rid in retained:
            rack = one(db, 'SELECT * FROM site_racks WHERE id=?', (rid,))
            if not rack or rack['zone'] != x['zone'] or rack['status'] != 'installed':
                return {'decision': 'rack_not_in_place'}
        accessible = 1 if x.get('accessible') else 0
        if strategy == 'relocation':
            # Each removed rack must be physically relocated into an accepted
            # zone and its mirror service switched and independently verified.
            for rid in removed:
                reloc = one(db, "SELECT * FROM rack_relocations WHERE rack=? AND from_zone=?",
                            (rid, x['zone']))
                if not reloc or reloc['status'] != 'verified':
                    return {'decision': 'relocation_unverified'}
                target = one(db, 'SELECT * FROM structural_zones WHERE id=?', (reloc['to_zone'],))
                if not target or target['status'] == 'restricted':
                    return {'decision': 'relocation_target_not_accepted'}
                sw = one(db, "SELECT * FROM mirror_switchovers WHERE from_rack=? AND status='verified'", (rid,))
                if not sw:
                    return {'decision': 'mirror_switch_unverified'}
            # Retained racks must fit the unshored, engineer-tested allowance.
            elements = rows(db, 'SELECT * FROM structural_elements WHERE zone=?', (x['zone'],))
            for el in elements:
                retained_load = 0
                for rid in retained:
                    anchor = one(db, "SELECT 1 FROM rack_anchors WHERE rack=? AND element=? AND status!='removed'",
                                 (rid, el['id']))
                    if anchor:
                        retained_load += one(db, 'SELECT mass FROM site_racks WHERE id=?', (rid,))['mass']
                if retained_load > assessment['safe_load']:
                    return {'decision': 'load_path_overloaded'}
            if x.get('occupant_limit', 0) < 1:
                return {'decision': 'invalid_occupant_limit'}
        elif strategy == 'shoring':
            # Both racks stay; every damaged load path needs complete,
            # load-tested shoring, entry is restricted and monitoring is bound.
            needed = [el['id'] for el in rows(db, 'SELECT * FROM structural_elements WHERE zone=?', (x['zone'],))
                      if el['current_limit'] is not None]
            for el_id in needed:
                el = one(db, 'SELECT * FROM structural_elements WHERE id=?', (el_id,))
                review = review_element(db, el)
                if not review['shoring'] or review['overloaded']:
                    return {'decision': 'shoring_incomplete'}
            if accessible or x.get('occupant_limit', 0) != 0:
                return {'decision': 'restricted_entry_violation'}
            if x.get('monitoring_cycle', 0) < 1:
                return {'decision': 'invalid_monitoring_cycle'}
        else:
            return {'decision': 'invalid_strategy'}
        if x['deload_deadline'] <= x['at']:
            return {'decision': 'invalid_deload_deadline'}
        seq = latest_seq(db, x['zone'])
        db.execute('INSERT INTO reentry_certificates VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
                   (x['id'], x['zone'], x['engineer'], assessment['id'], x['at'], strategy,
                    accessible, x.get('occupant_limit', 0), ','.join(retained), ','.join(removed),
                    x['deload_deadline'], x.get('monitoring_cycle', 0), seq, None, 'active'))
        db.execute('UPDATE structural_zones SET status=? WHERE id=?',
                   ('reentry_restricted' if strategy == 'shoring' else 'reentry_open', x['zone']))
        return {'decision': 'reentry_certified', 'strategy': strategy,
                'retained_racks': retained, 'removed_racks': removed,
                'occupant_limit': x.get('occupant_limit', 0), 'aftershock_seq': seq}
    if op == 'aftershock':
        # A new aftershock invalidates every earlier certificate: old proofs
        # never carry over automatically.
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        seq = x['aftershock_seq']
        prior = latest_seq(db, x['zone'])
        # The ruling may reference an already-recorded aftershock; it must not
        # jump ahead of the observed sequence or repeat an already-adjudicated one.
        if seq < 1 or seq > prior or any(
                r['void_reason'] == 'aftershock_%d' % seq
                for r in rows(db, 'SELECT void_reason FROM reentry_certificates WHERE zone=?',
                              (x['zone'],))):
            return {'decision': 'aftershock_order_violation'}
        db.execute('UPDATE reentry_certificates SET status=?, void_reason=? WHERE zone=? AND status=?',
                   ('void', 'aftershock_%d' % seq, x['zone'], 'active'))
        # Shoring proved under the old quake conditions cannot be relied on
        # after a further shock: revert each braced path to the engineer's
        # unshored allowance pending a fresh load test.
        prior_assessment = latest_assessment(db, x['zone'])
        for el in rows(db, 'SELECT * FROM structural_elements WHERE zone=?', (x['zone'],)):
            if el['shoring_id']:
                db.execute("UPDATE shoring_works SET status='voided' WHERE id=?", (el['shoring_id'],))
                limit = prior_assessment['safe_load'] if prior_assessment else el['rated_limit']
                db.execute('UPDATE structural_elements SET shoring_id=NULL, current_limit=? WHERE id=?',
                           (limit, el['id']))
        db.execute('UPDATE structural_zones SET status=? WHERE id=?', ('restricted', x['zone']))
        voided = rows(db, "SELECT id FROM reentry_certificates WHERE zone=? AND void_reason=?",
                      (x['zone'], 'aftershock_%d' % seq))
        return {'decision': 'certificates_voided', 'aftershock_seq': seq,
                'certificates': [v['id'] for v in voided]}
    if op == 'notice':
        # Append-only correction sent to regulators or customers. Earlier
        # conclusions are superseded, never overwritten.
        if one(db, 'SELECT 1 FROM structural_notices WHERE id=?', (x['id'],)):
            return {'decision': 'notice_conflict'}
        if x.get('supersedes'):
            prior = one(db, 'SELECT * FROM structural_notices WHERE id=?', (x['supersedes'],))
            if not prior:
                return {'decision': 'superseded_notice_missing'}
            db.execute('UPDATE structural_notices SET status=? WHERE id=?', ('superseded', prior['id']))
        db.execute('INSERT INTO structural_notices VALUES(?,?,?,?,?,?,?,?,?)',
                   (x['id'], x['recipient'], x['zone'], x['engineer'], x['at'],
                    x.get('supersedes'), x['subject'], x['body'], 'issued'))
        return {'decision': 'notice_issued'}
    if op == 'load_review':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone:
            return {'decision': 'zone_missing'}
        elements = [review_element(db, el)
                    for el in rows(db, 'SELECT * FROM structural_elements WHERE zone=?', (x['zone'],))]
        assessment = latest_assessment(db, x['zone'])
        return {'decision': 'load_review', 'zone': x['zone'],
                'rated_limit': zone['load_limit'],
                'safe_load': assessment['safe_load'] if assessment else None,
                'occupied_total': sum(e['occupied'] for e in elements),
                'elements': elements,
                'overloaded': any(e['overloaded'] for e in elements)}
    raise ValueError(op)
