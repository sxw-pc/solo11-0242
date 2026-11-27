from .store import one, rows


# ---------------------------------------------------------------------------
# Legacy event-sourced contract (kept byte-for-byte so old events replay).
# ---------------------------------------------------------------------------
def _legacy(db, x):
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
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _manifest_batch(db, digest, batch):
    manifest = one(db, 'SELECT * FROM manifests WHERE digest=?', (digest,))
    return bool(manifest and manifest['batch'] == batch)


def _reading_family(db, reading_id):
    """Return the current revision row plus every revision row of a reading."""
    current = one(db, 'SELECT * FROM meter_readings WHERE id=?', (reading_id,))
    if not current:
        return None, []
    family = rows(db, 'SELECT * FROM meter_readings WHERE device=? AND window_start=? ORDER BY revision',
                  (current['device'], current['window_start']))
    return current, family


def _reading_committed(db, reading_id):
    """kwh of a reading already promised to finished builds (the unique
    retirement account for physical electricity)."""
    row = one(db, 'SELECT COALESCE(SUM(kwh),0) AS k FROM energy_allocations WHERE reading=?',
              (reading_id,))
    return row['k']


def _cert_remaining(db, serial):
    cert = one(db, 'SELECT * FROM green_certificates WHERE serial=?', (serial,))
    if not cert:
        return None, 0
    used = one(db, "SELECT COALESCE(SUM(kwh),0) AS k FROM certificate_retirements WHERE serial=? AND status='retired'",
               (serial,))['k']
    return cert, cert['kwh'] - used


def _valid_retirements(db, run):
    return rows(db, """SELECT r.* FROM certificate_retirements r
                       JOIN green_certificates c ON c.serial=r.serial
                       WHERE r.run=? AND r.status='retired' AND c.status='active'
                       ORDER BY r.at""", (run,))


def _active_versions(db, claim=None):
    sql = "SELECT * FROM green_claim_versions WHERE state='published' AND superseded_by IS NULL"
    args = ()
    if claim:
        sql += ' AND claim=?'
        args = (claim,)
    return rows(db, sql, args)


def _add_impacts(db, claim, version, reason, at, detail):
    previous = one(db, 'SELECT COUNT(*) AS s FROM claim_impacts WHERE claim=? AND version=?',
                   (claim, version))
    db.execute('INSERT INTO claim_impacts VALUES(?,?,?,?,?,?)',
               ('%s-v%s-i%s' % (claim, version, previous['s'] + 1), claim, version, reason, at, detail))


def _impacts_for_claims(db, claim_ids, reason, at, detail):
    for version in _active_versions(db):
        if version['claim'] in claim_ids:
            _add_impacts(db, version['claim'], version['version'], reason, at, detail)


# ---------------------------------------------------------------------------
# Meter devices, readings, calibration and corrections
# ---------------------------------------------------------------------------
def _meter_device(db, x):
    if one(db, 'SELECT id FROM meter_devices WHERE id=?', (x['id'],)):
        return {'decision': 'meter_identity_conflict'}
    if x['calibration_until'] <= x['calibration_at']:
        return {'decision': 'invalid_calibration_window'}
    db.execute('INSERT INTO meter_devices VALUES(?,?,?,?,?,?,?,?)',
               (x['id'], x['site'], x['region'], x['model'], x['calibration_id'],
                x['calibration_at'], x['calibration_until'], 'active'))
    return {'decision': 'meter_registered'}


def _meter_reading(db, x):
    device = one(db, 'SELECT * FROM meter_devices WHERE id=?', (x['device'],))
    if not device:
        return {'decision': 'unknown_meter'}
    if device['status'] != 'active' or not device['calibration_at'] <= x['at'] < device['calibration_until']:
        return {'decision': 'meter_not_calibrated'}
    if one(db, 'SELECT id FROM meter_readings WHERE id=?', (x['id'],)):
        return {'decision': 'reading_identity_conflict'}
    if x['window_end'] <= x['window_start'] or x['kwh'] < 0 or x['low_carbon_kwh'] < 0 \
            or x['low_carbon_kwh'] > x['kwh']:
        return {'decision': 'invalid_reading'}
    if x['low_carbon_kwh'] > 0 and not x.get('evidence'):
        # A source string never turns a meter reading into low-carbon proof.
        return {'decision': 'low_carbon_evidence_required'}
    if x.get('predecessor'):
        prior = one(db, 'SELECT * FROM meter_readings WHERE id=?', (x['predecessor'],))
        if not prior or prior['device'] != x['device']:
            return {'decision': 'unknown_predecessor'}
        if prior['window_end'] != x['window_start']:
            return {'decision': 'reading_window_gap'}
    overlap = one(db, """SELECT id FROM meter_readings WHERE device=? AND status='current'
                         AND window_start < ? AND window_end > ?""",
                  (x['device'], x['window_end'], x['window_start']))
    if overlap:
        return {'decision': 'reading_window_overlap'}
    db.execute('INSERT INTO meter_readings VALUES(?,?,?,?,?,?,?,?,?,?)',
               (x['id'], x['device'], x['site'], x['window_start'], x['window_end'],
                x['kwh'], x['low_carbon_kwh'], x.get('evidence'), 1, 'current'))
    return {'decision': 'reading_recorded'}


def _meter_calibrate(db, x):
    device = one(db, 'SELECT * FROM meter_devices WHERE id=?', (x['id'],))
    if not device:
        return {'decision': 'unknown_meter'}
    if x['calibration_until'] <= x['calibration_at']:
        return {'decision': 'invalid_calibration_window'}
    db.execute("""UPDATE meter_devices SET calibration_id=?,calibration_at=?,calibration_until=?,status='active'
                  WHERE id=?""", (x['calibration_id'], x['calibration_at'], x['calibration_until'], x['id']))
    return {'decision': 'calibration_updated'}


def _meter_decertify(db, x):
    device = one(db, 'SELECT * FROM meter_devices WHERE id=?', (x['id'],))
    if not device:
        return {'decision': 'unknown_meter'}
    db.execute("UPDATE meter_devices SET status='decertified' WHERE id=?", (x['id'],))
    db.execute("UPDATE meter_readings SET status='superseded' WHERE device=? AND status='current'", (x['id'],))
    affected = {a['run'] for a in rows(db, 'SELECT DISTINCT run FROM energy_allocations WHERE reading IN '
                                       '(SELECT id FROM meter_readings WHERE device=?)', (x['id'],))}
    claim_ids = {v['claim'] for v in _active_versions(db) if v['run'] in affected}
    _impacts_for_claims(db, claim_ids, 'calibration_revoked', x['at'],
                        'meter %s decertified' % x['id'])
    return {'decision': 'meter_decertified', 'affected_claims': sorted(claim_ids)}


def _meter_correct(db, x):
    current, family = _reading_family(db, x['id'])
    if not current:
        return {'decision': 'unknown_reading'}
    if current['status'] != 'current' or current['id'] != x['id']:
        return {'decision': 'stale_reading_revision'}
    origin = family[0]['id']
    if x['revision'] != current['revision'] + 1:
        return {'decision': 'stale_reading_revision'}
    if x['kwh'] < 0 or x['low_carbon_kwh'] < 0 or x['low_carbon_kwh'] > x['kwh']:
        return {'decision': 'invalid_reading'}
    if x['low_carbon_kwh'] > 0 and not x.get('evidence'):
        return {'decision': 'low_carbon_evidence_required'}
    committed = _reading_committed(db, x['id'])
    over = committed > x['kwh']
    db.execute("UPDATE meter_readings SET status='superseded' WHERE id=?", (x['id'],))
    new_id = '%s-r%s' % (origin, x['revision'])
    db.execute('INSERT INTO meter_readings VALUES(?,?,?,?,?,?,?,?,?,?)',
               (new_id, current['device'], current['site'], current['window_start'],
                current['window_end'], x['kwh'], x['low_carbon_kwh'],
                x.get('evidence'), x['revision'], 'current'))
    claim_ids = {v['claim'] for v in _active_versions(db)
                 if v['run'] in {a['run'] for a in
                                 rows(db, 'SELECT DISTINCT run FROM energy_allocations WHERE reading=?',
                                      (x['id'],))}}
    detail = 'reading %s corrected to kwh=%s low_carbon=%s' % (x['id'], x['kwh'], x['low_carbon_kwh'])
    if over:
        detail += '; allocated_kwh=%s exceeds trusted reading' % committed
    _impacts_for_claims(db, claim_ids, 'meter_correction', x['at'], detail)
    return {'decision': 'reading_corrected', 'new_reading': new_id,
            'allocation_exceeds_reading': over, 'affected_claims': sorted(claim_ids)}


def _meter_review(db, x):
    device = one(db, 'SELECT * FROM meter_devices WHERE id=?', (x['id'],))
    if not device:
        return {'decision': 'unknown_meter'}
    current_rows = rows(db, """SELECT * FROM meter_readings WHERE device=? AND status='current'
                               ORDER BY window_start""", (x['id'],))
    gaps = []
    for earlier, later in zip(current_rows, current_rows[1:]):
        if earlier['window_end'] != later['window_start']:
            gaps.append([earlier['window_end'], later['window_start']])
    trusted = sum(r['kwh'] for r in current_rows)
    allocated = one(db, """SELECT COALESCE(SUM(a.kwh),0) AS k FROM energy_allocations a
                           JOIN meter_readings r ON r.id=a.reading
                           WHERE r.device=?""", (x['id'],))['k']
    return {'decision': 'meter_reviewed', 'calibrated': device['status'] == 'active',
            'continuous': not gaps and bool(current_rows), 'gaps': gaps,
            'trusted_kwh': trusted, 'allocated_kwh': allocated,
            'headroom_kwh': trusted - allocated}


# ---------------------------------------------------------------------------
# Build runs: start / pause / retry / standby / finish / rerun
# ---------------------------------------------------------------------------
def _build_start(db, x):
    if not _manifest_batch(db, x['digest'], x['batch']):
        return {'decision': 'unknown_batch'}
    if one(db, 'SELECT id FROM energy_runs WHERE id=?', (x['id'],)):
        return {'decision': 'run_identity_conflict'}
    db.execute('INSERT INTO energy_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (x['id'], x['batch'], x['digest'], x['site'], x['region'], x['customer'],
                'open', x['at'], x['at'], 0, 0))
    db.execute('INSERT INTO build_segments VALUES(?,?,?,?,?,?,?)',
               ('%s-s1' % x['id'], x['id'], 1, 'active', x['at'], x['at'], 0))
    return {'decision': 'build_started'}


def _build_pause(db, x):
    run = one(db, 'SELECT * FROM energy_runs WHERE id=?', (x['id'],))
    if not run or run['state'] != 'open':
        return {'decision': 'run_not_open'}
    seg = one(db, "SELECT * FROM build_segments WHERE run=? AND kind='active' ORDER BY seq DESC LIMIT 1",
              (x['id'],))
    if not seg or x['at'] < seg['ends']:
        return {'decision': 'invalid_segment_window'}
    db.execute("UPDATE build_segments SET kind='paused',ends=?,kwh=? WHERE id=?",
               (x['at'], seg['kwh'] + (x['at'] - seg['ends']), seg['id']))
    return {'decision': 'build_paused'}


def _build_retry(db, x):
    run = one(db, 'SELECT * FROM energy_runs WHERE id=?', (x['id'],))
    if not run or run['state'] != 'open':
        return {'decision': 'run_not_open'}
    last = one(db, 'SELECT * FROM build_segments WHERE run=? ORDER BY seq DESC LIMIT 1', (x['id'],))
    if not last or last['kind'] != 'paused' or x['at'] < last['ends']:
        return {'decision': 'retry_without_pause'}
    db.execute('INSERT INTO build_segments VALUES(?,?,?,?,?,?,?)',
               ('%s-s%s' % (x['id'], last['seq'] + 1), x['id'], last['seq'] + 1,
                'active', x['at'], x['at'], 0))
    return {'decision': 'build_resumed'}


def _build_standby(db, x):
    run = one(db, 'SELECT * FROM energy_runs WHERE id=?', (x['id'],))
    if not run or run['state'] != 'open':
        return {'decision': 'run_not_open'}
    if x['kwh'] <= 0:
        return {'decision': 'invalid_standby_kwh'}
    last = one(db, 'SELECT * FROM build_segments WHERE run=? ORDER BY seq DESC LIMIT 1', (x['id'],))
    if not last or x['ends'] <= x['starts'] or (last and x['starts'] < last['ends']):
        return {'decision': 'invalid_segment_window'}
    seq = (last['seq'] if last else 0) + 1
    db.execute('INSERT INTO build_segments VALUES(?,?,?,?,?,?,?)',
               ('%s-s%s' % (x['id'], seq), x['id'], seq, 'standby',
                x['starts'], x['ends'], x['kwh']))
    return {'decision': 'standby_recorded'}


def _build_finish(db, x):
    run = one(db, 'SELECT * FROM energy_runs WHERE id=?', (x['id'],))
    if not run or run['state'] != 'open':
        return {'decision': 'run_not_open'}
    if x['at'] < run['starts']:
        return {'decision': 'invalid_segment_window'}
    # Validate every requested allocation before writing anything.
    total = 0
    low_carbon = 0
    validated = []
    low_carbon_seen = {}
    for item in x['allocations']:
        current, family = _reading_family(db, item['reading'])
        if not current or current['status'] != 'current':
            return {'decision': 'unknown_reading'}
        if current['site'] != run['site']:
            return {'decision': 'site_mismatch'}
        # The reading only has to be contemporaneous with the build; several
        # readings may tile the run window together.
        if current['window_end'] <= run['starts'] or current['window_start'] > x['at']:
            return {'decision': 'reading_window_mismatch'}
        if item['kwh'] <= 0:
            return {'decision': 'invalid_allocation'}
        headroom = current['kwh'] - _reading_committed(db, item['reading'])
        if item['kwh'] > headroom:
            return {'decision': 'allocation_exceeds_reading'}
        total += item['kwh']
        # Low-carbon units of a single reading can only be counted once even
        # when several allocations draw from it.
        used_here = low_carbon_seen.get(item['reading'], 0)
        low_carbon += max(0, min(item['kwh'], current['low_carbon_kwh'] - used_here))
        low_carbon_seen[item['reading']] = used_here + item['kwh']
        validated.append((item, current))
    standby = one(db, "SELECT COALESCE(SUM(kwh),0) AS k FROM build_segments WHERE run=? AND kind='standby'",
                   (x['id'],))['k']
    if total <= 0 or standby > total:
        return {'decision': 'invalid_allocation'}
    # Close any still-open active segment.
    open_seg = one(db, "SELECT * FROM build_segments WHERE run=? AND kind='active' ORDER BY seq DESC LIMIT 1",
                   (x['id'],))
    if open_seg and x['at'] >= open_seg['ends']:
        db.execute("UPDATE build_segments SET kind='completed',ends=? WHERE id=?",
                   (x['at'], open_seg['id']))
    for index, (item, current) in enumerate(validated, 1):
        db.execute('INSERT INTO energy_allocations VALUES(?,?,?,?,?)',
                   ('%s-a%s' % (x['id'], index), x['id'], item['reading'],
                    current['site'], item['kwh']))
    db.execute("""UPDATE energy_runs SET state='finished',ends=?,measured_kwh=?,low_carbon_kwh=?
                  WHERE id=?""", (x['at'], total, low_carbon, x['id']))
    return {'decision': 'build_finished', 'measured_kwh': total,
            'physical_low_carbon_kwh': low_carbon}


def _build_rerun(db, x):
    prior = one(db, 'SELECT * FROM energy_runs WHERE id=?', (x['replaces'],))
    if not prior:
        return {'decision': 'unknown_run'}
    if not _manifest_batch(db, prior['digest'], prior['batch']):
        return {'decision': 'unknown_batch'}
    if one(db, 'SELECT id FROM energy_runs WHERE id=?', (x['id'],)):
        return {'decision': 'run_identity_conflict'}
    # Same digest does not mean same site, window or attribute rights.
    db.execute('INSERT INTO energy_runs VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (x['id'], prior['batch'], prior['digest'], x['site'], x['region'],
                prior['customer'], 'open', x['at'], x['at'], 0, 0))
    db.execute('INSERT INTO build_segments VALUES(?,?,?,?,?,?,?)',
               ('%s-s1' % x['id'], x['id'], 1, 'active', x['at'], x['at'], 0))
    claim_ids = {v['claim'] for v in _active_versions(db) if v['run'] == x['replaces']}
    _impacts_for_claims(db, claim_ids, 'build_rerun', x['at'],
                        'run %s replaced by %s' % (x['replaces'], x['id']))
    return {'decision': 'rerun_started', 'affected_claims': sorted(claim_ids)}


def _build_review(db, x):
    run = one(db, 'SELECT * FROM energy_runs WHERE id=?', (x['id'],))
    if not run:
        return {'decision': 'unknown_run'}
    segments = rows(db, 'SELECT * FROM build_segments WHERE run=? ORDER BY seq', (x['id'],))
    allocations = rows(db, 'SELECT * FROM energy_allocations WHERE run=?', (x['id'],))
    covered = not any(s['kind'] == 'active' for s in segments)
    allocated = sum(a['kwh'] for a in allocations)
    return {'decision': 'build_reviewed', 'state': run['state'], 'segments': segments,
            'windows_covered': covered, 'allocated_kwh': allocated,
            'measured_kwh': run['measured_kwh'],
            'allocation_matches_measurement': run['measured_kwh'] == allocated}


# ---------------------------------------------------------------------------
# Green attribute certificates: issue / transfer / revoke transfer / retire
# ---------------------------------------------------------------------------
def _cert_issue(db, x):
    if one(db, 'SELECT serial FROM green_certificates WHERE serial=?', (x['serial'],)):
        return {'decision': 'certificate_identity_conflict'}
    if x['period_end'] <= x['period_start'] or x['kwh'] <= 0:
        return {'decision': 'invalid_certificate'}
    db.execute('INSERT INTO green_certificates VALUES(?,?,?,?,?,?,?,?,?)',
               (x['serial'], x['station'], x['region'], x['period_start'],
                x['period_end'], x['initial_owner'], x['initial_owner'], x['kwh'], 'active'))
    db.execute('INSERT INTO certificate_transfers VALUES(?,?,?,?,?,?,?)',
               ('%s-t0' % x['serial'], x['serial'], None, x['initial_owner'],
                x['kwh'], x['at'], 'valid'))
    return {'decision': 'certificate_issued'}


def _cert_transfer(db, x):
    cert, remaining = _cert_remaining(db, x['serial'])
    if not cert or cert['status'] != 'active':
        return {'decision': 'unknown_certificate'}
    if cert['current_owner'] != x['frm']:
        return {'decision': 'transfer_not_owner'}
    if x['to'] == x['frm'] or x['kwh'] <= 0 or x['kwh'] > remaining:
        return {'decision': 'invalid_transfer'}
    if one(db, 'SELECT id FROM certificate_transfers WHERE id=?', (x['id'],)):
        return {'decision': 'transfer_identity_conflict'}
    db.execute('INSERT INTO certificate_transfers VALUES(?,?,?,?,?,?,?)',
               (x['id'], x['serial'], x['frm'], x['to'], x['kwh'], x['at'], 'valid'))
    if remaining - x['kwh'] == 0:
        db.execute("UPDATE green_certificates SET current_owner=? WHERE serial=?",
                   (x['to'], x['serial']))
    return {'decision': 'certificate_transferred'}


def _cert_revoke_transfer(db, x):
    transfer = one(db, 'SELECT * FROM certificate_transfers WHERE id=?', (x['id'],))
    if not transfer:
        return {'decision': 'unknown_transfer'}
    if transfer['status'] != 'valid':
        return {'decision': 'transfer_already_revoked'}
    cert = one(db, 'SELECT * FROM green_certificates WHERE serial=?', (transfer['serial'],))
    if cert['current_owner'] != transfer['receiver']:
        return {'decision': 'transfer_chain_broken'}
    db.execute("UPDATE certificate_transfers SET status='revoked' WHERE id=?", (x['id'],))
    db.execute("UPDATE green_certificates SET current_owner=? WHERE serial=?",
               (transfer['sender'], transfer['serial']))
    retirement_ids = {r['id'] for r in
                      rows(db, 'SELECT id FROM certificate_retirements WHERE serial=?',
                           (transfer['serial'],))}
    affected = set()
    for version in _active_versions(db):
        links = rows(db, 'SELECT retirement FROM claim_certificates WHERE claim=? AND version=?',
                     (version['claim'], version['version']))
        if any(link['retirement'] in retirement_ids for link in links):
            affected.add(version['claim'])
    _impacts_for_claims(db, affected, 'transfer_revoked', x['at'],
                        'transfer %s on %s revoked' % (x['id'], transfer['serial']))
    return {'decision': 'transfer_revoked', 'affected_claims': sorted(affected)}


def _cert_retire(db, x):
    cert, remaining = _cert_remaining(db, x['serial'])
    if not cert or cert['status'] != 'active':
        return {'decision': 'unknown_certificate'}
    run = one(db, 'SELECT * FROM energy_runs WHERE id=?', (x['run'],))
    if not run or run['state'] != 'finished':
        return {'decision': 'run_not_finished'}
    if cert['current_owner'] != x['owner']:
        return {'decision': 'retirement_not_owner'}
    if cert['region'] != run['region']:
        return {'decision': 'certificate_region_mismatch'}
    # Attribute period must overlap the build window.
    if cert['period_start'] > run['ends'] or cert['period_end'] < run['starts']:
        return {'decision': 'certificate_period_mismatch'}
    if x['kwh'] <= 0 or x['kwh'] > remaining:
        return {'decision': 'retirement_exceeds_certificate'}
    if one(db, 'SELECT id FROM certificate_retirements WHERE id=?', (x['id'],)):
        return {'decision': 'retirement_identity_conflict'}
    db.execute('INSERT INTO certificate_retirements VALUES(?,?,?,?,?,?,?)',
               (x['id'], x['serial'], x['run'], x['kwh'], x['at'], x['receipt'], 'retired'))
    return {'decision': 'certificate_retired', 'remaining_kwh': remaining - x['kwh']}


def _cert_review(db, x):
    cert, remaining = _cert_remaining(db, x['serial'])
    if not cert:
        return {'decision': 'unknown_certificate'}
    chain = rows(db, 'SELECT * FROM certificate_transfers WHERE serial=? ORDER BY at', (x['serial'],))
    retirements = rows(db, 'SELECT * FROM certificate_retirements WHERE serial=? ORDER BY at',
                       (x['serial'],))
    return {'decision': 'certificate_reviewed', 'serial': x['serial'], 'status': cert['status'],
            'owner': cert['current_owner'], 'kwh': cert['kwh'], 'remaining_kwh': remaining,
            'chain': chain, 'retirements': retirements}


# ---------------------------------------------------------------------------
# Customer claims: two independent bases, versioned, append-only on impacts
# ---------------------------------------------------------------------------
def _claim(db, x):
    if one(db, 'SELECT 1 FROM green_claim_versions WHERE claim=?', (x['id'],)):
        return {'decision': 'claim_identity_conflict'}
    # The environmental benefit of one run can only be claimed once; a second
    # live claim on the same run would re-spend the same rights.
    if one(db, "SELECT 1 FROM green_claim_versions WHERE run=? AND superseded_by IS NULL",
           (x['run'],)):
        return {'decision': 'run_already_claimed'}
    run = one(db, 'SELECT * FROM energy_runs WHERE id=?', (x['run'],))
    if not run or run['state'] != 'finished':
        return {'decision': 'run_not_finished'}
    if run['customer'] != x['customer']:
        return {'decision': 'claim_customer_mismatch'}
    basis = x['basis']
    if basis not in ('grid_source', 'market'):
        return {'decision': 'invalid_basis'}
    physical = x.get('physical_kwh', 0)
    certificate_kwh = x.get('certificate_kwh', 0)
    if physical < 0 or certificate_kwh < 0 or physical + certificate_kwh <= 0:
        return {'decision': 'invalid_claim_kwh'}
    if physical > run['measured_kwh']:
        return {'decision': 'claim_exceeds_measurement'}
    if physical > run['low_carbon_kwh']:
        # Physical attribution only up to verifiable grid low-carbon share.
        return {'decision': 'claim_exceeds_physical_low_carbon'}
    if basis == 'grid_source' and certificate_kwh != 0:
        return {'decision': 'grid_basis_forbids_certificates'}
    picked = []
    if certificate_kwh:
        available = _valid_retirements(db, x['run'])
        need = certificate_kwh
        for retirement in available:
            take = min(need, retirement['kwh'])
            if take:
                picked.append((retirement, take))
                need -= take
            if need == 0:
                break
        if need:
            return {'decision': 'claim_exceeds_retired_attributes'}
        # No double green: certificates only cover the non-physical remainder.
        if physical + certificate_kwh > run['measured_kwh']:
            return {'decision': 'double_counted_green_kwh'}
    db.execute('INSERT INTO green_claim_versions VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               ('%s-v%s' % (x['id'], 1), x['id'], 1, x['run'], x['customer'], basis,
                physical, certificate_kwh, x.get('reading'), 'draft', None))
    for retirement, take in picked:
        db.execute('INSERT INTO claim_certificates VALUES(?,?,?,?)',
                   (x['id'], 1, retirement['id'], take))
    return {'decision': 'draft_claim', 'claim': x['id'], 'version': 1,
            'physical_kwh': physical, 'certificate_kwh': certificate_kwh}


def _claim_publish(db, x):
    current = one(db, 'SELECT * FROM green_claim_versions WHERE claim=? AND superseded_by IS NULL',
                  (x['id'],))
    if not current:
        return {'decision': 'unknown_claim'}
    if current['state'] == 'published':
        return {'decision': 'claim_already_published'}
    if current['certificate_kwh']:
        for link in rows(db, 'SELECT * FROM claim_certificates WHERE claim=? AND version=?',
                         (x['id'], current['version'])):
            retirement = one(db, "SELECT * FROM certificate_retirements WHERE id=? AND status='retired'",
                             (link['retirement'],))
            cert = one(db, "SELECT * FROM green_certificates WHERE serial=? AND status='active'",
                       (retirement['serial'],)) if retirement else None
            if not retirement or not cert:
                return {'decision': 'retired_attribute_invalid'}
    db.execute("UPDATE green_claim_versions SET state='published' WHERE claim=? AND version=?",
               (x['id'], current['version']))
    return {'decision': 'claim_published', 'claim': x['id'], 'version': current['version']}


def _claim_new_version(db, x):
    current = one(db, 'SELECT * FROM green_claim_versions WHERE claim=? AND superseded_by IS NULL',
                  (x['id'],))
    if not current:
        return {'decision': 'unknown_claim'}
    if current['state'] != 'published':
        return {'decision': 'claim_not_published'}
    # Published statements and retirement receipts are never overwritten.
    version = current['version'] + 1
    db.execute('UPDATE green_claim_versions SET superseded_by=? WHERE claim=? AND version=?',
               (version, x['id'], current['version']))
    db.execute('INSERT INTO green_claim_versions VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               ('%s-v%s' % (x['id'], version), x['id'], version, current['run'],
                current['customer'], x['basis'], x.get('physical_kwh', 0),
                x.get('certificate_kwh', 0), x.get('reading'), 'draft', None))
    return {'decision': 'claim_version_drafted', 'claim': x['id'], 'version': version}


def _claim_review(db, x):
    versions = rows(db, 'SELECT * FROM green_claim_versions WHERE claim=? ORDER BY version',
                    (x['id'],))
    if not versions:
        return {'decision': 'unknown_claim'}
    current = next(v for v in versions if v['superseded_by'] is None)
    impacts = rows(db, 'SELECT * FROM claim_impacts WHERE claim=? ORDER BY rowid', (x['id'],))
    links = rows(db, 'SELECT * FROM claim_certificates WHERE claim=? AND version=?',
                 (x['id'], current['version']))
    return {'decision': 'claim_reviewed', 'claim': x['id'], 'current_version': current,
            'history': versions, 'certificates': links, 'impacts': impacts}


def _rights_review(db, x):
    """Unused entitlements: meter headroom plus un-retired certificate kwh."""
    out = {'decision': 'rights_reviewed', 'meters': [], 'certificates': []}
    for device in rows(db, 'SELECT * FROM meter_devices ORDER BY id'):
        out['meters'].append(_meter_review(db, {'id': device['id']}))
    for cert in rows(db, 'SELECT serial FROM green_certificates ORDER BY serial'):
        _, remaining = _cert_remaining(db, cert['serial'])
        out['certificates'].append({'serial': cert['serial'], 'remaining_kwh': remaining})
    return out


_HANDLERS = {
    'meter_device': _meter_device,
    'meter_reading': _meter_reading,
    'meter_calibrate': _meter_calibrate,
    'meter_decertify': _meter_decertify,
    'meter_correct': _meter_correct,
    'meter_review': _meter_review,
    'build_start': _build_start,
    'build_pause': _build_pause,
    'build_retry': _build_retry,
    'build_standby': _build_standby,
    'build_finish': _build_finish,
    'build_rerun': _build_rerun,
    'build_review': _build_review,
    'cert_issue': _cert_issue,
    'cert_transfer': _cert_transfer,
    'cert_revoke_transfer': _cert_revoke_transfer,
    'cert_retire': _cert_retire,
    'cert_review': _cert_review,
    'claim_green': _claim,
    'claim_publish': _claim_publish,
    'claim_new_version': _claim_new_version,
    'claim_review': _claim_review,
    'rights_review': _rights_review,
}


def run(db, x):
    legacy = _legacy(db, x)
    if legacy is not None:
        return legacy
    handler = _HANDLERS.get(x['op'])
    if not handler:
        raise ValueError(x['op'])
    return handler(db, x)
