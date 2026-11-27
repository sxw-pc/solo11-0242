"""Scoped customer-data erasure, minimal judicial hold and replayable proof.

The seeded entry ops (``copy``/``hold``/``erase``) keep their exact legacy
decisions.  Fulfillment is modelled as distinct facts (physical purge, backup
destruction, judicial extraction, customer receipt); a complete deletion
certificate is only issued once every gate passes.

Everything is deterministic and JSON/SQLite only so ``store.replay`` can
rebuild state.  Raw customer bytes are carried by events until a confirmed
purge, after which the originating events are redacted under a commitment and
the purge event itself carries only the residual/evidence needed for replay.
"""
import base64
import hashlib
import json

from .store import one, rows, sha256_text

WIPE = '\x01'
WIPE_BYTE = WIPE.encode('utf-8')
CUSTODY_CONTEXT = 'imagecourt-isolated-custody-v1'

REGISTRATION_OPS = {'copy', 'cache', 'backup', 'runtime', 'runtime_artifact',
                    'register_cache', 'register_backup', 'mount'}
PHYSICAL_KINDS = [
    ('site_copy', 'artifact_copies'),
    ('cache', 'artifact_caches'),
    ('runtime', 'runtime_artifacts'),
]


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------

def jdumps(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def jloads(text, default):
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def commitment(text):
    return sha256_text(text if text is not None else '')


def evidence(x):
    ev = x.get('ev')
    if not isinstance(ev, dict):
        ev = {}
        x['ev'] = ev
    return ev


def merge_intervals(intervals):
    clean = sorted((max(0, int(s)), max(0, int(e))) for s, e in intervals if int(e) > int(s))
    merged = []
    for s, e in clean:
        if not merged or s > merged[-1][1]:
            merged.append([s, e])
        else:
            merged[-1][1] = max(merged[-1][1], e)
    return merged


def wipe_payload(payload, intervals):
    """Overwrite exactly the given byte intervals; preserve all other bytes."""
    if payload is None:
        return None
    data = payload.encode('utf-8')
    buf = bytearray(data)
    for s, e in merge_intervals(intervals):
        s = max(0, s)
        e = min(len(buf), e)
        if e > s:
            buf[s:e] = WIPE_BYTE * (e - s)
    return bytes(buf).decode('utf-8')


def slice_ranges(payload, ranges):
    data = payload.encode('utf-8')
    out = []
    for i, (s, e) in enumerate(merge_intervals(ranges)):
        out.append({'index': i, 'start': s, 'end': e,
                    'content': data[s:e].decode('utf-8'),
                    'commitment': hashlib.sha256(data[s:e]).hexdigest()})
    return out


def _key_seed(order_id, key_ref):
    return f'{CUSTODY_CONTEXT}::{order_id}::{key_ref}'


def seal_text(text, order_id, key_ref):
    """Simulation-grade envelope seal (NOT real cryptography; no real keys)."""
    seed = _key_seed(order_id, key_ref).encode('utf-8')
    data = text.encode('utf-8')
    stream = b''
    counter = 0
    while len(stream) < len(data):
        stream += hashlib.sha256(seed + counter.to_bytes(4, 'big')).digest()
        counter += 1
    blob = bytes(a ^ b for a, b in zip(data, stream[:len(data)]))
    return base64.b64encode(blob).decode('ascii')


def open_sealed(blob, order_id, key_ref):
    raw = base64.b64decode(blob.encode('ascii'))
    seed = _key_seed(order_id, key_ref).encode('utf-8')
    stream = b''
    counter = 0
    while len(stream) < len(raw):
        stream += hashlib.sha256(seed + counter.to_bytes(4, 'big')).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(raw, stream[:len(raw)])).decode('utf-8')


# ---------------------------------------------------------------------------
# scope / enumeration
# ---------------------------------------------------------------------------

def scope_from_x(x):
    copy_ids = x.get('copy_ids')
    if not copy_ids and x.get('copy_id'):
        copy_ids = [x['copy_id']]
    return {
        'categories': list(x['categories']) if x.get('categories') else None,
        'copy_ids': list(copy_ids) if copy_ids else None,
        'sites': list(x['sites']) if x.get('sites') else (
            [x['site']] if x.get('site') else None),
    }


def scope_matches(row, scope):
    if scope.get('sites') and row.get('site') not in scope['sites']:
        return False
    copy_ids = scope.get('copy_ids')
    if copy_ids:
        own = row['id']
        linked = row['copy_id'] if 'copy_id' in row.keys() else None
        if own not in copy_ids and linked not in copy_ids:
            return False
    return True


def physical_targets(db, tenant, digest, scope):
    out = []
    for kind, table in PHYSICAL_KINDS:
        for r in rows(db, f'SELECT * FROM {table} WHERE tenant=? AND digest=?',
                      (tenant, digest)):
            if scope_matches(r, scope):
                out.append({'kind': kind, 'table': table, 'row': r})
    return out


def backup_targets(db, tenant, digest, scope):
    return [r for r in rows(db, 'SELECT * FROM artifact_backups WHERE tenant=? AND digest=?',
                            (tenant, digest)) if scope_matches(r, scope)]


def segment_intervals(db, copy_id, categories):
    if categories:
        q = ('SELECT start_off,end_off FROM artifact_segments '
             'WHERE copy_id=? AND category IN (%s)' % ','.join('?' * len(categories)))
        found = rows(db, q, (copy_id, *categories))
    else:
        found = rows(db, 'SELECT start_off,end_off FROM artifact_segments WHERE copy_id=?',
                     (copy_id,))
    return [(r['start_off'], r['end_off']) for r in found
            if r['start_off'] is not None and r['end_off'] is not None]


def locked_ranges(order):
    return jloads(order['ranges_json'], []) if order and order.get('ranges_json') else []


def active_order(db, tenant, digest, order_id=None):
    if order_id:
        return one(db, 'SELECT * FROM preservation_orders WHERE id=?', (order_id,))
    # Only a validated, range-locking court order drives the judicial gate.
    return one(db,
               "SELECT * FROM preservation_orders WHERE tenant=? AND digest=? AND status='active' "
               "AND order_kind='court_order' AND ranges_json IS NOT NULL "
               'ORDER BY issued_at DESC, id DESC LIMIT 1', (tenant, digest))


def fault_reason(db, x, target_id):
    faults = x.get('faults')
    if isinstance(faults, dict) and target_id in faults:
        return str(faults[target_id])
    fail = x.get('fail_targets') or x.get('fail_ids') or []
    if target_id in fail:
        return x.get('fault_reason', 'injected_purge_failure')
    key = one(db, 'SELECT kind FROM retention_faults WHERE active=1 AND fault_key=?',
              (target_id,))
    if key:
        return key['kind']
    key = one(db, 'SELECT kind FROM retention_faults WHERE active=1 AND fault_key=?',
              ('*',))
    return key['kind'] if key else None


# ---------------------------------------------------------------------------
# event redaction (accountable erasure from the immutable log)
# ---------------------------------------------------------------------------

def redact_event_payload(db, seq, request_id, at, mutator, field_path='payload',
                         original_hash=None):
    row = one(db, 'SELECT payload,payload_hash FROM events WHERE seq=?', (seq,))
    if not row:
        return
    doc = jloads(row['payload'], None)
    if not isinstance(doc, dict):
        return
    mutator(doc)
    db.execute('UPDATE events SET payload=? WHERE seq=?', (jdumps(doc), seq))
    db.execute(
        'INSERT INTO event_redactions(seq,request_id,field_path,original_hash,redacted_at,certificate_id) '
        'VALUES(?,?,?,?,?,NULL) ON CONFLICT(seq) DO UPDATE SET field_path=excluded.field_path',
        (seq, request_id, field_path, original_hash or row['payload_hash'], at))


def registration_redaction_entries(db, target_id):
    """Commitment manifest for one purged target's registration event(s)."""
    entries = []
    for r in rows(db,
                  "SELECT seq,payload,payload_hash FROM events WHERE subsystem='retention' ORDER BY seq"):
        doc = jloads(r['payload'], None)
        if isinstance(doc, dict) and doc.get('id') == target_id \
                and doc.get('op') in REGISTRATION_OPS:
            entries.append({'seq': r['seq'], 'original_hash': r['payload_hash']})
    return entries


def redact_registration(db, request_id, target_id, at, entries):
    """Null the raw payload/segment text using a deterministic hash manifest."""
    def scrub(d):
        d['payload'] = None
        for seg in d.get('segments') or []:
            if isinstance(seg, dict):
                seg['text'] = None
                seg['content'] = None
        d['redacted'] = {'request': request_id, 'at': at, 'reason': 'customer_erasure'}

    for ent in entries or []:
        redact_event_payload(db, ent['seq'], request_id, at, scrub,
                             'payload,segments', ent.get('original_hash'))


def _walk_scrub_sealed(node):
    changed = False
    if isinstance(node, dict):
        for key in list(node.keys()):
            if key == 'sealed_blob' and node[key]:
                node[key] = None
                changed = True
            elif key == 'content' and isinstance(node[key], str) and node.get('commitment'):
                node[key] = None
                changed = True
            elif _walk_scrub_sealed(node[key]):
                changed = True
    elif isinstance(node, list):
        for item in node:
            if _walk_scrub_sealed(item):
                changed = True
    return changed


def sealed_redaction_manifest(db, order_id):
    """Sequences/commitments of old events carrying this order's sealed bytes."""
    manifest = []
    for r in rows(db, 'SELECT seq,payload,payload_hash FROM events ORDER BY seq'):
        if order_id not in (r['payload'] or ''):
            continue
        doc = jloads(r['payload'], None)
        if isinstance(doc, dict) and _walk_scrub_sealed(doc):
            manifest.append({'seq': r['seq'], 'original_hash': r['payload_hash']})
    return manifest


def apply_sealed_redactions(db, request_id, at, manifest):
    for ent in manifest or []:
        row = one(db, 'SELECT payload FROM events WHERE seq=?', (ent['seq'],))
        if not row:
            continue
        doc = jloads(row['payload'], None)
        if isinstance(doc, dict):
            _walk_scrub_sealed(doc)
            db.execute('UPDATE events SET payload=? WHERE seq=?', (jdumps(doc), ent['seq']))
        db.execute(
            'INSERT INTO event_redactions(seq,request_id,field_path,original_hash,redacted_at,certificate_id) '
            'VALUES(?,?,?,?,?,NULL) ON CONFLICT(seq) DO UPDATE SET field_path=excluded.field_path',
            (ent['seq'], request_id, 'sealed_material', ent.get('original_hash'), at))


# ---------------------------------------------------------------------------
# facts / certificates
# ---------------------------------------------------------------------------

def record_fact(db, request_id, at, kind, target_type, target_id,
                site=None, status='completed', detail=None, cert_commitment=None):
    fid = f'fact:{request_id}:{kind}:{target_type}:{target_id}'
    db.execute(
        'INSERT INTO erasure_facts(id,request_id,at,kind,target_type,target_id,site,status,'
        'detail_json,commitment) VALUES(?,?,?,?,?,?,?,?,?,?) '
        'ON CONFLICT(id) DO UPDATE SET status=excluded.status,detail_json=excluded.detail_json',
        (fid, request_id, at, kind, target_type, target_id, site, status,
         jdumps(detail or {}), cert_commitment))
    return fid


def fact_completed(db, request_id, kind, target_id):
    f = one(db,
            "SELECT status FROM erasure_facts WHERE request_id=? AND kind=? AND target_id=?",
            (request_id, kind, target_id))
    return bool(f and f['status'] == 'completed')


def request_row(db, request_id):
    return one(db, 'SELECT * FROM erase_requests WHERE id=?', (request_id,))


def gate_blockers(db, req, scope, order):
    rid = req['id']
    blockers = []
    for t in physical_targets(db, req['tenant'], req['digest'], scope):
        r = t['row']
        if not fact_completed(db, rid, 'physical', r['id']):
            blockers.append({'gate': 'physical', 'target_type': t['kind'], 'target': r['id']})
    for b in backup_targets(db, req['tenant'], req['digest'], scope):
        if not fact_completed(db, rid, 'backup', b['id']):
            blockers.append({'gate': 'backup', 'target_type': 'backup', 'target': b['id']})
    if order:
        mode = req['mode'] or order['mode'] or 'isolated_custody'
        extracted = one(db,
                        "SELECT id FROM judicial_extractions WHERE request_id=? AND status='delivered'",
                        (rid,))
        sealed = one(db,
                     "SELECT id FROM custody_items WHERE order_id=? AND status='sealed'",
                     (order['id'],))
        if mode == 'external_escrow':
            if not extracted:
                blockers.append({'gate': 'judicial', 'reason': 'escrow_extraction_not_delivered'})
        else:
            if not sealed:
                blockers.append({'gate': 'judicial', 'reason': 'isolated_custody_not_sealed'})
    receipt = one(db, "SELECT id FROM customer_receipts WHERE request_id=? AND status='issued'",
                  (rid,))
    if not receipt:
        blockers.append({'gate': 'receipt', 'reason': 'customer_receipt_missing'})
    return blockers


# ---------------------------------------------------------------------------
# registration ops
# ---------------------------------------------------------------------------

def _insert_segments(db, copy_id, x, payload):
    segs = x.get('segments') or []
    data = (payload or '').encode('utf-8')
    cursor = 0
    for i, seg in enumerate(segs):
        key = seg.get('id') or seg.get('key') or f'seg-{i}'
        text = seg.get('text') or seg.get('content') or ''
        if seg.get('start') is not None and seg.get('end') is not None:
            s, e = int(seg['start']), int(seg['end'])
        elif text:
            needle = text.encode('utf-8')
            pos = data.find(needle, cursor)
            if pos < 0:
                pos = cursor
            s, e = pos, pos + len(needle)
            cursor = e
        else:
            s = e = int(seg.get('offset', cursor))
        # Persist resolved offsets into the command so the event carries the
        # locked geometry even after segment text is later redacted.
        seg['start'], seg['end'] = s, e
        db.execute('INSERT OR REPLACE INTO artifact_segments VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                   (f'{copy_id}:{key}', copy_id, x.get('tenant'), x.get('digest'),
                    x.get('site'), key, seg.get('category', 'uncategorized'),
                    s, e, text or None, 'present'))


def _payload_from_copy(db, x):
    if x.get('payload') is not None:
        return x['payload']
    if x.get('copy_id'):
        c = one(db, 'SELECT payload FROM artifact_copies WHERE id=?', (x['copy_id'],))
        if c and c['payload'] is not None:
            x['payload'] = c['payload']
            return c['payload']
    return x.get('payload')


def _op_copy(db, x):
    if not one(db, 'SELECT 1 FROM manifests WHERE digest=?', (x['digest'],)):
        return {'decision': 'unknown_image'}
    old = one(db, 'SELECT id,digest,tenant,site FROM artifact_copies WHERE id=?', (x['id'],))
    if old:
        if (old['digest'], old['tenant'], old['site']) != (
                x['digest'], x['tenant'], x.get('site')):
            return {'decision': 'copy_identity_conflict'}
        return {'decision': 'reused', 'id': x['id']}
    payload = x.get('payload')
    if payload is None and x.get('segments'):
        payload = ''.join((s.get('text') or s.get('content') or '') for s in x['segments']) or None
        x['payload'] = payload  # persisted into the event by store.execute
    db.execute('INSERT INTO artifact_copies(id,digest,tenant,site,payload) VALUES(?,?,?,?,?)',
               (x['id'], x['digest'], x['tenant'], x['site'], payload))
    if x.get('segments'):
        _insert_segments(db, x['id'], x, payload)
    return {'decision': 'copy_recorded'}


def _op_location(db, x, table, columns, kind_label):
    old = one(db, f'SELECT id FROM {table} WHERE id=?', (x['id'],))
    if old:
        return {'decision': 'reused', 'id': x['id']}
    payload = _payload_from_copy(db, x)
    values = {'id': x['id'], 'tenant': x['tenant'], 'digest': x['digest'],
              'site': x.get('site'), 'copy_id': x.get('copy_id'),
              'payload': payload, 'state': x.get('state', 'warm' if kind_label == 'cache' else 'present')}
    if table == 'runtime_artifacts':
        lease_id = x.get('lease_id') or x.get('lease')
        workload_id = x.get('workload_id') or x.get('workload')
        if lease_id and not workload_id:
            lease = one(db, 'SELECT workload FROM leases WHERE id=?', (lease_id,))
            if lease:
                workload_id = lease['workload']
        db.execute(
            'INSERT INTO runtime_artifacts(id,tenant,digest,site,lease_id,workload_id,copy_id,payload,state) '
            'VALUES(?,?,?,?,?,?,?,?,?)',
            (values['id'], values['tenant'], values['digest'], values['site'],
             lease_id, workload_id, values['copy_id'], values['payload'],
             x.get('state', 'running')))
    elif table == 'artifact_caches':
        db.execute('INSERT INTO artifact_caches(id,tenant,digest,site,copy_id,payload,state) '
                   'VALUES(?,?,?,?,?,?,?)',
                   (values['id'], values['tenant'], values['digest'], values['site'],
                    values['copy_id'], values['payload'], values['state']))
    else:
        db.execute('INSERT INTO artifact_backups(id,tenant,digest,site,copy_id,payload,state) '
                   'VALUES(?,?,?,?,?,?,?)',
                   (values['id'], values['tenant'], values['digest'],
                    x.get('site') or x.get('location'), values['copy_id'],
                    values['payload'], x.get('state', 'backed_up')))
    return {'decision': f'{kind_label}_recorded', 'id': x['id']}


# ---------------------------------------------------------------------------
# court signers / escrow registry / faults
# ---------------------------------------------------------------------------

def _op_court_signer(db, x):
    db.execute('INSERT OR IGNORE INTO court_signers(signer,authority,accredited_at) VALUES(?,?,?)',
               (x['signer'], x.get('authority', 'court'), x.get('at')))
    return {'decision': 'court_signer_registered'}


def _op_escrow(db, x):
    old = one(db, 'SELECT id FROM judicial_escrows WHERE id=?', (x['id'],))
    reachable = 1 if x.get('reachable', True) else 0
    if old:
        db.execute('UPDATE judicial_escrows SET custodian=?,endpoint=?,reachable=?,updated_at=? WHERE id=?',
                   (x.get('custodian', old['id']), x.get('endpoint'), reachable, x.get('at'), x['id']))
        return {'decision': 'escrow_updated'}
    db.execute('INSERT INTO judicial_escrows(id,custodian,endpoint,reachable,updated_at) VALUES(?,?,?,?,?)',
               (x['id'], x.get('custodian', x['id']), x.get('endpoint'), reachable, x.get('at')))
    return {'decision': 'escrow_registered', 'reachable': bool(reachable)}


def _op_fault(db, x):
    key = x.get('key') or x.get('target_id') or x.get('fault_key')
    db.execute('INSERT INTO retention_faults(fault_key,kind,active,at) VALUES(?,?,1,?) '
               'ON CONFLICT(fault_key) DO UPDATE SET active=1,kind=excluded.kind',
               (key, x.get('kind', 'purge_failure'), x.get('at')))
    return {'decision': 'fault_recorded', 'key': key}


# ---------------------------------------------------------------------------
# court order / hold
# ---------------------------------------------------------------------------

def _resolve_order_ranges(db, x):
    """Return locked [[start,end], ...] and validation reasons."""
    tenant, digest = x['tenant'], x['digest']
    length = None
    canonical = None
    copy_id = x.get('copy_id')
    if copy_id:
        c = one(db, 'SELECT payload FROM artifact_copies WHERE id=? AND tenant=?',
                (copy_id, tenant))
        if c and c['payload'] is not None:
            canonical = c['payload']
    if canonical is None:
        c = one(db, 'SELECT payload FROM artifact_copies WHERE tenant=? AND digest=? '
                    'AND payload IS NOT NULL ORDER BY id LIMIT 1', (tenant, digest))
        if c:
            canonical = c['payload']
    if canonical is not None:
        length = len(canonical.encode('utf-8'))

    ranges = []
    for r in x.get('ranges') or []:
        if isinstance(r, dict):
            if r.get('segment') or r.get('seg_key') or r.get('id'):
                key = r.get('segment') or r.get('seg_key') or r.get('id')
                seg = one(db,
                          'SELECT start_off,end_off FROM artifact_segments '
                          'WHERE seg_key=? AND tenant=? AND digest=? LIMIT 1',
                          (key, tenant, digest))
                if seg:
                    ranges.append((seg['start_off'], seg['end_off']))
            elif r.get('category'):
                ranges += segment_intervals(db, r.get('copy_id') or copy_id
                                            or _first_copy(db, tenant, digest), [r['category']])
            elif r.get('start') is not None:
                ranges.append((r['start'], r['end']))
        elif isinstance(r, (list, tuple)) and len(r) == 2:
            ranges.append((r[0], r[1]))
    for key in x.get('segments') or x.get('range_segments') or []:
        seg = one(db,
                  'SELECT start_off,end_off FROM artifact_segments '
                  'WHERE seg_key=? AND tenant=? AND digest=? LIMIT 1',
                  (key, tenant, digest))
        if seg:
            ranges.append((seg['start_off'], seg['end_off']))
    for cat in x.get('range_categories') or x.get('hold_categories') or []:
        ranges += segment_intervals(db, copy_id or _first_copy(db, tenant, digest), [cat])

    locked = merge_intervals(ranges)
    reasons = []
    if not locked:
        reasons.append('empty_hold_range')
    if length is not None:
        for s, e in locked:
            if s < 0 or e > length or s >= e:
                reasons.append('range_out_of_bounds')
                break
    return locked, reasons


def _first_copy(db, tenant, digest):
    c = one(db, 'SELECT id FROM artifact_copies WHERE tenant=? AND digest=? ORDER BY id LIMIT 1',
            (tenant, digest))
    return c['id'] if c else None


def _op_hold(db, x):
    existing = one(db, 'SELECT id,tenant,digest,status FROM preservation_orders WHERE id=?',
                   (x['id'],))
    if existing:
        if (existing['tenant'], existing['digest']) != (x['tenant'], x['digest']):
            return {'decision': 'preservation_conflict'}
        return {'decision': 'reused', 'order': x['id'], 'status': existing['status'],
                'duplicate': True}
    # Legacy short form: {id,tenant,digest,scope} (an optional bare ``at`` or
    # case label does not by itself turn it into a validated court order).
    rich_markers = ('signer', 'signed_by', 'matter', 'dispute', 'case_matter',
                    'ranges', 'range_refs', 'segments', 'range_segments',
                    'range_categories', 'hold_categories', 'issued_at',
                    'order_kind', 'court_order', 'verify_signer')
    rich = x.get('court_order') is True or any(k in x for k in rich_markers)
    if not rich:
        db.execute('INSERT INTO preservation_orders(id,tenant,digest,scope,status) '
                   'VALUES(?,?,?,?,?)',
                   (x['id'], x['tenant'], x['digest'], x['scope'], 'active'))
        return {'decision': 'hold_recorded'}

    signer = x.get('signer') or x.get('signed_by')
    at = x.get('issued_at', x.get('at'))
    matter = x.get('matter') or x.get('dispute') or x.get('case_matter') or x.get('scope')
    reasons = []
    if not signer:
        reasons.append('missing_signer')
    if at is None:
        reasons.append('missing_time')
    if not matter:
        reasons.append('missing_matter')
    locked, range_reasons = _resolve_order_ranges(db, x)
    reasons += range_reasons
    if x.get('verify_signer') and signer and not one(
            db, 'SELECT 1 FROM court_signers WHERE signer=?', (signer,)):
        reasons.append('signer_not_accredited')
    if reasons:
        return {'decision': 'invalid_order', 'reasons': sorted(set(reasons))}

    mode = x.get('mode') or x.get('custody_mode') or 'isolated_custody'
    custodian = x.get('custodian') or (
        'external-judicial-escrow' if mode == 'external_escrow' else 'platform-isolated-custody')
    key_ref = x.get('key_ref') or f'key:{x["id"]}'
    purpose = x.get('purpose') or f'judicial-preservation:{x.get("case_ref") or matter}'
    x['locked_ranges'] = locked  # carried in the event for replay
    db.execute(
        'INSERT INTO preservation_orders(id,tenant,digest,scope,status,order_kind,signer,'
        'issued_at,matter,ranges_json,mode,custodian,key_ref,purpose,case_ref) '
        'VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
        (x['id'], x['tenant'], x['digest'], x.get('scope', matter), 'active',
         x.get('order_kind', 'court_order'), signer, at, matter, jdumps(locked),
         mode, custodian, key_ref, purpose, x.get('case_ref') or x.get('case')))
    return {'decision': 'hold_recorded', 'order': x['id'], 'ranges': locked,
            'mode': mode, 'minimal_bytes': sum(e - s for s, e in locked)}


def _op_erase(db, x):
    existing = request_row(db, x['id'])
    if existing:
        cert = one(db, 'SELECT id,status FROM erasure_certificates WHERE request_id=?', (x['id'],))
        return {'decision': 'reused', 'request': x['id'], 'status': existing['status'],
                'certificate': cert['id'] if cert else None,
                'certificate_status': cert['status'] if cert else None,
                'duplicate': True}
    if x.get('idempotency_key'):
        prior = one(db, 'SELECT id FROM erase_requests WHERE idempotency_key=?',
                    (x['idempotency_key'],))
        if prior:
            return {'decision': 'reused', 'request': prior['id'], 'duplicate': True,
                    'original_request': prior['id']}
    scope = scope_from_x(x)
    copies = rows(db, 'SELECT id FROM artifact_copies WHERE digest=? AND tenant=? '
                      + ('AND id IN (%s)' % ','.join('?' * len(scope['copy_ids']))
                         if scope['copy_ids'] else ''),
                  (x['digest'], x['tenant'], *(scope['copy_ids'] or [])))
    snap = evidence(x)
    if 'snapshot' not in snap:
        snap['snapshot'] = []
        for c in rows(db, 'SELECT * FROM artifact_copies WHERE digest=? AND tenant=?',
                      (x['digest'], x['tenant'])):
            if scope['copy_ids'] and c['id'] not in scope['copy_ids']:
                continue
            snap['snapshot'].append({'id': c['id'], 'site': c['site'],
                                     'length': len((c['payload'] or '').encode('utf-8')),
                                     'commitment': commitment(c['payload'])})
    db.execute(
        'INSERT INTO erase_requests(id,tenant,digest,at,status,scope_json,commitments_json,'
        'mode,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?)',
        (x['id'], x['tenant'], x['digest'], x['at'], 'requested', jdumps(scope),
         jdumps(snap['snapshot']), x.get('mode'), x.get('idempotency_key')))
    base = {'decision': 'erase_requested', 'copies': len(copies), 'request': x['id']}
    if x.get('fulfill') or x.get('fulfil') or x.get('execute_erasure') or x.get('complete') \
            or x.get('process') or x.get('run_erasure') or x.get('execute') \
            or x.get('now') or x.get('immediate') or x.get('auto_fulfill') \
            or x.get('mode') or x.get('certify') or x.get('purge') is True:
        report = fulfill(db, x, x['id'], x['at'])
        base.update({k: v for k, v in report.items() if k != 'decision'})
        base['decision'] = report['decision']
    return base


# ---------------------------------------------------------------------------
# fulfillment phases
# ---------------------------------------------------------------------------

def _escrow_dir(db, x):
    if x.get('escrow_dir'):
        return x['escrow_dir']
    escrow_id = x.get('escrow') or x.get('escrow_id')
    if escrow_id:
        e = one(db, 'SELECT endpoint FROM judicial_escrows WHERE id=?', (escrow_id,))
        if e and e['endpoint']:
            ep = e['endpoint']
            if ep.startswith('file://'):
                return ep[7:]
            if ep.startswith('dir:'):
                return ep[4:]
            if ep.startswith('/'):
                return ep
    import os
    return os.environ.get('IMAGECOURT_ESCROW_DIR')


def _escrow_reachable(db, x):
    if x.get('escrow_unreachable') or x.get('reachable') is False \
            or x.get('escrow_reachable') is False:
        return False
    escrow_id = x.get('escrow') or x.get('escrow_id')
    reason = fault_reason(db, x, 'escrow') or (
        fault_reason(db, x, escrow_id) if escrow_id else None)
    if reason == 'unreachable' or (isinstance(reason, str) and 'unreachable' in reason):
        return False
    if escrow_id:
        e = one(db, 'SELECT reachable FROM judicial_escrows WHERE id=?', (escrow_id,))
        if e and not e['reachable']:
            return False
    return True


def _canonical_payload(db, req):
    copies = rows(db,
                  'SELECT payload FROM artifact_copies WHERE tenant=? AND digest=? '
                  'AND payload IS NOT NULL ORDER BY id', (req['tenant'], req['digest']))
    # Prefer a still-unwiped copy so a retry cannot slice wipe markers.
    for c in copies:
        if any(b != ord(WIPE) for b in c['payload'].encode('utf-8')):
            return c['payload']
    return copies[0]['payload'] if copies else None


def _existing_preservation(db, plan_mode, req, order):
    """Adopt already-sealed/delivered state so retries never re-derive it."""
    if not order:
        return None
    sealed = rows(db,
                  "SELECT range_index,start_off,end_off,commitment,sealed_blob,status "
                  "FROM custody_items WHERE order_id=? AND status='sealed' ORDER BY range_index",
                  (order['id'],))
    pending = rows(db,
                   "SELECT range_index,start_off,end_off,commitment,sealed_blob "
                   "FROM custody_items WHERE order_id=? AND status='pending_escrow' "
                   'ORDER BY range_index', (order['id'],))
    if plan_mode == 'isolated_custody' and sealed:
        return {'order_id': order['id'], 'mode': 'isolated_custody',
                'ranges': locked_ranges(order), 'status': 'sealed',
                'items': [{'index': r['range_index'], 'start': r['start_off'],
                           'end': r['end_off'], 'commitment': r['commitment'],
                           'sealed_blob': r['sealed_blob']} for r in sealed]}
    if pending:
        return {'order_id': order['id'], 'mode': 'external_escrow',
                'ranges': locked_ranges(order), 'status': 'escrow_unreachable',
                'escrow_id': None,
                'items': [{'index': r['range_index'], 'start': r['start_off'],
                           'end': r['end_off'], 'commitment': r['commitment'],
                           'sealed_blob': r['sealed_blob'], 'pending': True} for r in pending]}
    delivered = one(db,
                    "SELECT id,escrow_id FROM judicial_extractions WHERE request_id=? "
                    "AND status='delivered'", (req['id'],))
    if delivered:
        items = rows(db,
                     'SELECT id,range_index,start_off,end_off,commitment,content '
                     'FROM escrow_deliveries WHERE extraction_id=? ORDER BY range_index',
                     (delivered['id'],))
        return {'order_id': order['id'], 'mode': 'external_escrow',
                'ranges': locked_ranges(order), 'status': 'delivered',
                'escrow_id': delivered['escrow_id'], 'dir_sink': False,
                'items': [{'index': i['range_index'], 'start': i['start_off'],
                           'end': i['end_off'], 'commitment': i['commitment'],
                           'delivery_id': i['id'], 'content': i['content']} for i in items]}
    return None


def phase_preservation(db, x, evd, req, scope, order, at, force_mode=None):
    """Extract the locked slice to escrow or seal it into isolated custody."""
    plan = evd.get('pres')
    if plan is None:
        mode = force_mode or x.get('mode') or req['mode'] or (
            order['mode'] if order else None) or 'isolated_custody'
        adopted = _existing_preservation(db, mode, req, order)
        if adopted is not None:
            plan = adopted
            evd['pres'] = plan
        else:
            ranges = locked_ranges(order) if order else []
            plan = {'order_id': order['id'] if order else None, 'mode': mode,
                    'ranges': ranges, 'items': [], 'status': 'not_required'}
            if order and ranges:
                canonical = _canonical_payload(db, req)
                slices = slice_ranges(canonical or '', ranges) if canonical is not None else []
                if mode == 'external_escrow':
                    escrow_id = x.get('escrow') or x.get('escrow_id') or 'court-escrow'
                    if not _escrow_reachable(db, x):
                        plan['status'] = 'escrow_unreachable'
                        plan['escrow_id'] = escrow_id
                        # Safe fallback: seal minimally inside platform pending delivery.
                        key_ref = order['key_ref']
                        for sl in slices:
                            plan['items'].append({
                                'index': sl['index'], 'start': sl['start'], 'end': sl['end'],
                                'commitment': sl['commitment'],
                                'sealed_blob': seal_text(sl['content'], order['id'], key_ref),
                                'pending': True})
                    else:
                        directory = _escrow_dir(db, x)
                        plan['status'] = 'delivered'
                        plan['escrow_id'] = escrow_id
                        plan['dir_sink'] = bool(directory)
                        for sl in slices:
                            item = {'index': sl['index'], 'start': sl['start'], 'end': sl['end'],
                                    'commitment': sl['commitment'], 'delivery_id':
                                    f'delivery:{req["id"]}:{sl["index"]}'}
                            if directory:
                                import json as _json
                                from pathlib import Path
                                Path(directory).mkdir(parents=True, exist_ok=True)
                                Path(directory, item['delivery_id'] + '.json').write_text(
                                    _json.dumps({'delivery_id': item['delivery_id'],
                                                 'order_id': order['id'], **sl},
                                                ensure_ascii=False), encoding='utf-8')
                            else:
                                item['content'] = sl['content']  # in-DB simulation sink
                            plan['items'].append(item)
                else:
                    plan['status'] = 'sealed'
                    key_ref = order['key_ref']
                    for sl in slices:
                        plan['items'].append({
                            'index': sl['index'], 'start': sl['start'], 'end': sl['end'],
                            'commitment': sl['commitment'],
                            'sealed_blob': seal_text(sl['content'], order['id'], key_ref)})
            evd['pres'] = plan

    # ---- apply plan to tables (runs on original and replay alike) ----
    order_id = plan['order_id']
    if order_id:
        ord_row = one(db, 'SELECT * FROM preservation_orders WHERE id=?', (order_id,))
        key_ref = ord_row['key_ref'] if ord_row else f'key:{order_id}'
        custodian = ord_row['custodian'] if ord_row else 'isolated-custody'
        db.execute(
            'INSERT INTO custody_keys(key_ref,order_id,custodian,purpose,fingerprint,status,'
            'created_at,destroyed_at) VALUES(?,?,?,?,?,?,?,NULL) '
            'ON CONFLICT(key_ref) DO UPDATE SET status=excluded.status',
            (key_ref, order_id, custodian, ord_row['purpose'] if ord_row else 'judicial',
             sha256_text(_key_seed(order_id, key_ref)),
             'active' if plan['status'] in ('sealed', 'escrow_unreachable') else 'active', at))

    if plan['mode'] == 'isolated_custody' and order_id:
        for it in plan['items']:
            item_id = f'custody:{order_id}:{it["index"]}'
            db.execute(
                'INSERT INTO custody_items(id,order_id,tenant,digest,range_index,start_off,'
                'end_off,sealed_blob,commitment,source_copy_id,status,created_at) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                'sealed_blob=excluded.sealed_blob,status=excluded.status',
                (item_id, order_id, req['tenant'], req['digest'], it['index'], it['start'],
                 it['end'], it['sealed_blob'], it['commitment'], None, 'sealed', at))
        record_fact(db, req['id'], at, 'judicial', 'custody', order_id,
                    status='completed', detail={'mode': 'isolated_custody',
                                               'ranges': plan['ranges']})

    if plan['mode'] == 'external_escrow' and order_id:
        escrow_id = plan.get('escrow_id')
        extraction_id = f'extract:{req["id"]}'
        if plan['status'] == 'delivered':
            combined = sha256_text(''.join(i['commitment'] for i in plan['items']))
            db.execute(
                'INSERT INTO judicial_extractions(id,request_id,order_id,escrow_id,custodian,'
                'at,mode,ranges_json,receipt,commitment,status,reason) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                'status=excluded.status,receipt=excluded.receipt',
                (extraction_id, req['id'], order_id, escrow_id,
                 x.get('custodian', 'independent-judicial-escrow'), at, 'external_escrow',
                 jdumps(plan['ranges']), f'receipt:{extraction_id}', combined,
                 'delivered', None))
            for it in plan['items']:
                db.execute(
                    'INSERT INTO escrow_deliveries(id,extraction_id,order_id,range_index,'
                    'start_off,end_off,content,commitment,at,status) VALUES(?,?,?,?,?,?,?,?,?,?) '
                    'ON CONFLICT(id) DO UPDATE SET content=excluded.content',
                    (it['delivery_id'], extraction_id, order_id, it['index'], it['start'],
                     it['end'], it.get('content'), it['commitment'], at, 'delivered'))
            record_fact(db, req['id'], at, 'judicial', 'escrow', escrow_id,
                        status='completed', detail={'delivery': extraction_id})
        elif plan['status'] == 'escrow_unreachable':
            db.execute(
                'INSERT INTO judicial_extractions(id,request_id,order_id,escrow_id,custodian,'
                'at,mode,ranges_json,receipt,commitment,status,reason) '
                'VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                'status=excluded.status,reason=excluded.reason',
                (extraction_id, req['id'], order_id, escrow_id,
                 x.get('custodian', 'independent-judicial-escrow'), at, 'external_escrow',
                 jdumps(plan['ranges']), None, None, 'failed', 'escrow_unreachable'))
            for it in plan['items']:  # pending fallback custody
                item_id = f'custody:{order_id}:pending:{it["index"]}'
                db.execute(
                    'INSERT INTO custody_items(id,order_id,tenant,digest,range_index,start_off,'
                    'end_off,sealed_blob,commitment,source_copy_id,status,created_at) '
                    'VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET '
                    'sealed_blob=excluded.sealed_blob',
                    (item_id, order_id, req['tenant'], req['digest'], it['index'], it['start'],
                     it['end'], it['sealed_blob'], it['commitment'], None,
                     'pending_escrow', at))
            record_fact(db, req['id'], at, 'judicial', 'escrow', escrow_id,
                        status='failed', detail={'reason': 'escrow_unreachable'})
    return plan


def phase_purge(db, x, evd, req, scope, order, at):
    """Physically overwrite every in-scope site copy, cache and runtime image."""
    plan = evd.get('purge')
    if plan is None:
        held = locked_ranges(order) if order else []
        categories = scope.get('categories')
        targets = []
        for t in physical_targets(db, req['tenant'], req['digest'], scope):
            r = t['row']
            reason = fault_reason(db, x, r['id']) or fault_reason(db, x, t['kind'])
            source_copy = r['id'] if t['table'] == 'artifact_copies' else (
                r['copy_id'] or r['id'])
            if categories:
                cat_iv = segment_intervals(db, source_copy, categories)
                if not cat_iv:
                    targets.append({'kind': t['kind'], 'table': t['table'], 'id': r['id'],
                                    'site': r['site'], 'status': 'failed',
                                    'reason': 'category_not_located', 'residual': None})
                    continue
            elif r['payload'] is not None:
                # Whole-customer erasure covers every byte, segment-labelled or not.
                cat_iv = [(0, len(r['payload'].encode('utf-8')))]
            else:
                cat_iv = []
            intervals = merge_intervals(list(cat_iv) + list(held))
            residual = wipe_payload(r['payload'], intervals)
            if reason:
                # Never copy raw bytes into the event evidence: a failed target
                # is rebuilt from its own unredacted registration event.
                targets.append({'kind': t['kind'], 'table': t['table'], 'id': r['id'],
                                'site': r['site'], 'status': 'failed', 'reason': reason,
                                'residual': None, 'source_copy': source_copy})
            else:
                targets.append({'kind': t['kind'], 'table': t['table'], 'id': r['id'],
                                'site': r['site'], 'status': 'completed',
                                'residual': residual, 'source_copy': source_copy})
        for tt in targets:
            tt['redact'] = registration_redaction_entries(db, tt['id'])
        plan = {'targets': targets}
        evd['purge'] = plan

    completed, failed = [], []
    for t in plan['targets']:
        if t['status'] == 'completed':
            db.execute(f"UPDATE {t['table']} SET payload=?, state='purged' WHERE id=?",
                       (t['residual'], t['id']))
            # Mark located segments scrubbed; their content is never retained
            # in business tables (held bytes live only in judicial custody).
            db.execute("UPDATE artifact_segments SET content=NULL, state='scrubbed' "
                       'WHERE copy_id=?', (t.get('source_copy') or t['id'],))
            record_fact(db, req['id'], at, 'physical', t['kind'], t['id'], t.get('site'),
                        status='completed', detail={'table': t['table']})
            redact_registration(db, req['id'], t['id'], at, t.get('redact'))
            completed.append(t['id'])
        else:
            record_fact(db, req['id'], at, 'physical', t['kind'], t['id'], t.get('site'),
                        status='failed', detail={'reason': t.get('reason')})
            failed.append({'id': t['id'], 'reason': t.get('reason')})
    return {'completed': completed, 'failed': failed}


def phase_backups(db, x, evd, req, scope, at):
    plan = evd.get('backups')
    if plan is None:
        items = []
        for b in backup_targets(db, req['tenant'], req['digest'], scope):
            reason = fault_reason(db, x, b['id']) or fault_reason(db, x, 'backup')
            items.append({'id': b['id'], 'site': b['site'],
                          'status': 'failed' if reason else 'destroyed',
                          'reason': reason,
                          'redact': registration_redaction_entries(db, b['id'])})
        plan = {'items': items}
        evd['backups'] = plan
    destroyed, failed = [], []
    for b in plan['items']:
        if b['status'] == 'destroyed':
            db.execute("UPDATE artifact_backups SET payload=NULL, state='destroyed' WHERE id=?",
                       (b['id'],))
            record_fact(db, req['id'], at, 'backup', 'backup', b['id'], b.get('site'),
                        status='completed')
            redact_registration(db, req['id'], b['id'], at, b.get('redact'))
            destroyed.append(b['id'])
        else:
            record_fact(db, req['id'], at, 'backup', 'backup', b['id'], b.get('site'),
                        status='failed', detail={'reason': b.get('reason')})
            failed.append({'id': b['id'], 'reason': b.get('reason')})
    return {'destroyed': destroyed, 'failed': failed}


def phase_receipt(db, x, evd, req, at):
    receipt_id = x.get('receipt_id') or f"rcpt:{req['id']}"
    channel = x.get('channel', 'customer-notice')
    db.execute(
        'INSERT INTO customer_receipts(id,request_id,tenant,digest,at,channel,status,'
        'certificate_id,detail_json) VALUES(?,?,?,?,?,?,?,?,?) '
        'ON CONFLICT(id) DO UPDATE SET status=excluded.status',
        (receipt_id, req['id'], req['tenant'], req['digest'], at, channel, 'issued',
         x.get('certificate_id') or f"cert:{req['id']}", jdumps({'delivered_at': at})))
    record_fact(db, req['id'], at, 'receipt', 'customer', receipt_id,
                status='completed', detail={'channel': channel})
    return receipt_id


def issue_certificate(db, x, evd, req, scope, order, at, mode_override=None):
    cert_id = x.get('certificate_id') or f"cert:{req['id']}"
    prior = one(db, 'SELECT status FROM erasure_certificates WHERE id=?', (cert_id,))
    blockers = gate_blockers(db, req, scope, order)
    # A complete deletion proof is a durable historical fact: later events
    # (e.g. hold revocation) must not retroactively downgrade it.
    complete_before = bool(prior and prior['status'] == 'complete')
    if complete_before:
        blockers = []
    mode = mode_override or req['mode'] or (order['mode'] if order else None) \
        or 'zero_retention'
    if not blockers:
        status = 'complete'
        if order and mode != 'external_escrow':
            mode = 'isolated_custody'
        elif order and mode == 'external_escrow':
            mode = 'zero_retention_external_escrow'
        elif not order:
            mode = 'zero_retention'
    else:
        status = 'incomplete'
    fact_rows = rows(db, 'SELECT kind,target_type,target_id,site,status FROM erasure_facts '
                         'WHERE request_id=? ORDER BY id', (req['id'],))
    retained = None
    if order:
        retained = {'order': order['id'], 'signer': order['signer'], 'matter': order['matter'],
                    'ranges': locked_ranges(order),
                    'minimal_bytes': sum(e - s for s, e in locked_ranges(order)),
                    'destination': (order['custodian'] if mode == 'isolated_custody'
                                    else 'external-judicial-escrow'),
                    'custodian': order['custodian'], 'key_ref': order['key_ref'],
                    'purpose': order['purpose']}
    if 'chain_head' not in x:
        head = one(db, 'SELECT record_hash FROM events ORDER BY seq DESC LIMIT 1')
        x['chain_head'] = head['record_hash'] if head and head['record_hash'] else 'genesis'
    db.execute(
        'INSERT INTO erasure_certificates(id,request_id,tenant,digest,at,status,mode,scope_json,'
        'ranges_json,commitments_json,retained_json,facts_json,receipt_id,chain_head,'
        'blockers_json,issued_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) '
        'ON CONFLICT(id) DO UPDATE SET status=excluded.status,mode=excluded.mode,'
        'blockers_json=excluded.blockers_json,facts_json=excluded.facts_json',
        (cert_id, req['id'], req['tenant'], req['digest'], at, status, mode,
         req['scope_json'] or jdumps(scope),
         jdumps(locked_ranges(order) if order else []),
         req['commitments_json'], jdumps(retained), jdumps(fact_rows),
         f"rcpt:{req['id']}", x['chain_head'], jdumps(blockers),
         at if status == 'complete' else None))
    db.execute('UPDATE erase_requests SET status=?, completed_at=?, certificate_id=? WHERE id=?',
               ('completed' if status == 'complete' else 'fulfilling',
                at if status == 'complete' else None, cert_id, req['id']))
    return {'id': cert_id, 'status': status, 'mode': mode, 'blockers': blockers,
            'retained': retained}


def fulfill(db, x, request_id, at):
    req = request_row(db, request_id)
    if not req:
        return {'decision': 'unknown_request', 'request': request_id}
    evd = evidence(x)
    scope = jloads(req['scope_json'], None) or scope_from_x(x)
    order = active_order(db, req['tenant'], req['digest'], x.get('order_id'))
    mode = x.get('mode') or req['mode'] or (order['mode'] if order else None)
    if mode and not req['mode']:
        db.execute('UPDATE erase_requests SET mode=? WHERE id=?', (mode, request_id))
        req = request_row(db, request_id)

    pres = phase_preservation(db, x, evd, req, scope, order, at)
    purge = phase_purge(db, x, evd, req, scope, order, at)
    backups = phase_backups(db, x, evd, req, scope, at)
    receipt_id = phase_receipt(db, x, evd, req, at)
    cert = issue_certificate(db, x, evd, req, scope, order, at)

    judicial_status = pres['status']
    complete = cert['status'] == 'complete'
    return {
        'decision': 'erasure_completed' if complete else 'erasure_incomplete',
        'request': request_id, 'certificate': cert['id'],
        'certificate_status': cert['status'], 'mode': cert['mode'],
        'physical_completed': purge['completed'], 'physical_failed': purge['failed'],
        'backups_destroyed': backups['destroyed'], 'backups_failed': backups['failed'],
        'judicial': judicial_status, 'receipt': receipt_id,
        'blockers': cert['blockers'], 'retained': cert['retained'],
        'complete': complete}


# ---------------------------------------------------------------------------
# granular ops
# ---------------------------------------------------------------------------

def _loaded_request(db, x):
    rid = x.get('request_id') or x.get('request') or x.get('erase_id') or x.get('id')
    return rid, request_row(db, rid)


def _op_fulfill(db, x):
    rid = x.get('request_id') or x.get('request') or x.get('erase_id')
    if not rid:
        return {'decision': 'missing_request'}
    if not request_row(db, rid):
        return {'decision': 'unknown_request', 'request': rid}
    return fulfill(db, x, rid, x.get('at'))


def _op_purge(db, x):
    rid, req = _loaded_request(db, x)
    if not req:
        return {'decision': 'unknown_request'}
    evd = evidence(x)
    scope = jloads(req['scope_json'], None) or scope_from_x(x)
    order = active_order(db, req['tenant'], req['digest'], x.get('order_id'))
    out = phase_purge(db, x, evd, req, scope, order, x['at'])
    failed = out['failed']
    return {'decision': 'purge_partial' if failed else 'physical_purged',
            'request': rid, **out}


def _op_backups(db, x):
    rid, req = _loaded_request(db, x)
    if not req:
        return {'decision': 'unknown_request'}
    out = phase_backups(db, x, evidence(x), req,
                        jloads(req['scope_json'], None) or scope_from_x(x), x['at'])
    return {'decision': 'backup_partial' if out['failed'] else 'backups_destroyed',
            'request': rid, **out}


def _op_preservation_only(db, x, force_mode=None):
    rid, req = _loaded_request(db, x)
    if not req:
        return {'decision': 'unknown_request'}
    order = active_order(db, req['tenant'], req['digest'], x.get('order_id'))
    plan = phase_preservation(db, x, evidence(x), req,
                              jloads(req['scope_json'], None) or scope_from_x(x),
                              order, x['at'], force_mode=force_mode)
    decision = {'delivered': 'extracted_to_escrow', 'sealed': 'custody_sealed',
                'escrow_unreachable': 'escrow_unreachable',
                'not_required': 'preservation_not_required'}[plan['status']]
    return {'decision': decision, 'request': rid, 'status': plan['status'],
            'items': [{'index': i['index'], 'commitment': i['commitment']}
                      for i in plan['items']]}


def _op_receipt(db, x):
    rid, req = _loaded_request(db, x)
    if not req:
        return {'decision': 'unknown_request'}
    receipt_id = phase_receipt(db, x, evidence(x), req, x['at'])
    return {'decision': 'receipt_issued', 'receipt': receipt_id, 'request': rid}


def _op_certify(db, x):
    rid, req = _loaded_request(db, x)
    if not req:
        return {'decision': 'unknown_request'}
    scope = jloads(req['scope_json'], None) or scope_from_x(x)
    order = active_order(db, req['tenant'], req['digest'], x.get('order_id'))
    cert = issue_certificate(db, x, evidence(x), req, scope, order, x['at'])
    return {'decision': 'erasure_certified' if cert['status'] == 'complete'
            else 'certificate_blocked', **cert}


def _op_revoke(db, x):
    order_id = x.get('order_id') or x.get('id')
    rev_id = x.get('revocation_id') or x.get('id')
    at = x['at']
    order = one(db, 'SELECT * FROM preservation_orders WHERE id=?', (order_id,))
    if not order:
        return {'decision': 'unknown_order'}
    if order['status'] == 'revoked':
        return {'decision': 'reused', 'order': order_id, 'duplicate': True}
    locked = locked_ranges(order)
    requested = x.get('ranges')
    if requested:
        wanted = merge_intervals(
            [(r['start'], r['end']) if isinstance(r, dict) else (r[0], r[1])
             for r in requested])
        allowed = merge_intervals(locked)
        if any(not any(s >= a[0] and e <= a[1] for a in allowed) for s, e in wanted):
            return {'decision': 'range_exceeds_hold'}
    items = rows(db, "SELECT id FROM custody_items WHERE order_id=? AND status IN "
                     "('sealed','pending_escrow') ORDER BY id", (order_id,))
    destroyed = [i['id'] for i in items]
    db.execute("UPDATE custody_items SET sealed_blob=NULL, status='destroyed' "
               "WHERE order_id=? AND status IN ('sealed','pending_escrow')", (order_id,))
    db.execute("UPDATE custody_keys SET status='destroyed', destroyed_at=? WHERE order_id=?",
               (at, order_id))
    db.execute("UPDATE preservation_orders SET status='revoked', revoked_at=?, "
               'disposition=? WHERE id=?',
               (at, x.get('disposition', 'destroy_retained'), order_id))
    db.execute("UPDATE escrow_deliveries SET content=NULL, status='destroyed' "
               'WHERE order_id=?', (order_id,))
    db.execute("UPDATE judicial_extractions SET status='revoked_destroyed' WHERE order_id=?",
               (order_id,))
    rid = x.get('request_id') or f'revocation:{rev_id}'
    record_fact(db, rid, at, 'hold_revocation', 'order', order_id,
                status='completed', detail={'destroyed_items': destroyed})
    manifest = x.get('rev_manifest')
    if manifest is None:
        manifest = sealed_redaction_manifest(db, order_id)
        x['rev_manifest'] = manifest
    apply_sealed_redactions(db, rid, at, manifest)
    return {'decision': 'hold_revoked', 'order': order_id,
            'destroyed_custody_items': destroyed,
            'note': 'only actually retained minimal bytes were disposable; '
                    'already-erased bytes cannot be restored from redacted events'}


def _op_deliver_escrow(db, x):
    """Recover an unreachable escrow delivery from the pending sealed slice."""
    rid, req = _loaded_request(db, x)
    if not req:
        return {'decision': 'unknown_request'}
    order = active_order(db, req['tenant'], req['digest'], x.get('order_id'))
    escrow_id = x.get('escrow') or x.get('escrow_id') or 'court-escrow'
    if not _escrow_reachable(db, x):
        record_fact(db, rid, x['at'], 'judicial', 'escrow', escrow_id,
                    status='failed', detail={'reason': 'escrow_unreachable'})
        return {'decision': 'escrow_unreachable'}
    pending = rows(db, "SELECT * FROM custody_items WHERE order_id=? AND status='pending_escrow' "
                       'ORDER BY range_index', (order['id'] if order else x.get('order_id'),))
    if not pending:
        existing = one(db,
                       "SELECT id FROM judicial_extractions WHERE request_id=? AND status='delivered'",
                       (rid,))
        return {'decision': 'reused' if existing else 'nothing_pending'}
    key = one(db, 'SELECT key_ref FROM custody_keys WHERE order_id=?', (pending[0]['order_id'],))
    key_ref = key['key_ref'] if key else order['key_ref']
    directory = _escrow_dir(db, x)
    extraction_id = f'extract:{rid}'
    items_meta = []
    for it in pending:
        plain = open_sealed(it['sealed_blob'], it['order_id'], key_ref) if it['sealed_blob'] else ''
        delivery_id = f'delivery:{rid}:{it["range_index"]}'
        if directory:
            from pathlib import Path
            Path(directory).mkdir(parents=True, exist_ok=True)
            (Path(directory) / (delivery_id + '.json')).write_text(
                jdumps({'delivery_id': delivery_id, 'order_id': it['order_id'],
                        'start': it['start_off'], 'end': it['end_off'],
                        'content': plain, 'commitment': it['commitment']}),
                encoding='utf-8')
            content_col = None
        else:
            content_col = plain
        db.execute(
            'INSERT INTO escrow_deliveries(id,extraction_id,order_id,range_index,start_off,'
            'end_off,content,commitment,at,status) VALUES(?,?,?,?,?,?,?,?,?,?) '
            'ON CONFLICT(id) DO UPDATE SET content=excluded.content,status=excluded.status',
            (delivery_id, extraction_id, it['order_id'], it['range_index'], it['start_off'],
             it['end_off'], content_col, it['commitment'], x['at'], 'delivered'))
        db.execute("UPDATE custody_items SET sealed_blob=NULL, status='transferred' WHERE id=?",
                   (it['id'],))
        items_meta.append({'index': it['range_index'], 'commitment': it['commitment']})
    combined = sha256_text(''.join(i['commitment'] or '' for i in items_meta))
    db.execute(
        'INSERT INTO judicial_extractions(id,request_id,order_id,escrow_id,custodian,at,mode,'
        'ranges_json,receipt,commitment,status,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) '
        'ON CONFLICT(id) DO UPDATE SET status=\'delivered\',reason=NULL',
        (extraction_id, rid, pending[0]['order_id'], escrow_id,
         x.get('custodian', 'independent-judicial-escrow'), x['at'], 'external_escrow',
         order['ranges_json'] if order else '[]', f'receipt:{extraction_id}', combined,
         'delivered', None))
    record_fact(db, rid, x['at'], 'judicial', 'escrow', escrow_id, status='completed',
                detail={'delivery': extraction_id, 'recovered': True})
    scope = jloads(req['scope_json'], None) or scope_from_x(x)
    cert = issue_certificate(db, x, evidence(x), req, scope, order, x['at'],
                             mode_override='external_escrow')
    return {'decision': 'extracted_to_escrow', 'request': rid,
            'items': items_meta, 'certificate': cert['id'],
            'certificate_status': cert['status'], 'blockers': cert['blockers']}


def _op_access(db, x):
    access_id = x['id']
    order_id = x.get('order_id')
    item_id = x.get('item_id')
    accessor = x.get('accessor') or x.get('custodian')
    purpose = x.get('purpose')
    if not accessor or not purpose:
        return {'decision': 'custody_denied', 'reason': 'accessor_and_purpose_required'}
    if order_id:
        key = one(db, 'SELECT status FROM custody_keys WHERE order_id=?', (order_id,))
        order = one(db, 'SELECT status FROM preservation_orders WHERE id=?', (order_id,))
        if (key and key['status'] == 'destroyed') or (order and order['status'] == 'revoked'):
            db.execute('INSERT INTO custody_access(id,order_id,item_id,at,accessor,purpose,result) '
                       'VALUES(?,?,?,?,?,?,?)',
                       (access_id, order_id, item_id, x['at'], accessor, purpose, 'denied'))
            return {'decision': 'custody_denied', 'reason': 'custody_destroyed_or_revoked'}
    db.execute('INSERT INTO custody_access(id,order_id,item_id,at,accessor,purpose,result) '
               'VALUES(?,?,?,?,?,?,?)',
               (access_id, order_id, item_id, x['at'], accessor, purpose, 'granted'))
    return {'decision': 'custody_access_logged', 'access': access_id, 'result': 'granted'}


def read_custody(db, access_id):
    """Non-event read path: only after a purpose-bound granted access record."""
    log = one(db, "SELECT * FROM custody_access WHERE id=? AND result='granted'", (access_id,))
    if not log:
        return None
    item = one(db, 'SELECT * FROM custody_items WHERE id=?', (log['item_id'],)) if log['item_id'] \
        else one(db, "SELECT * FROM custody_items WHERE order_id=? AND status='sealed' "
                     'ORDER BY range_index LIMIT 1', (log['order_id'],))
    if not item or item['status'] != 'sealed' or not item['sealed_blob']:
        return None
    key = one(db, 'SELECT key_ref FROM custody_keys WHERE order_id=?', (item['order_id'],))
    return open_sealed(item['sealed_blob'], item['order_id'], key['key_ref'])


def production_view(db, tenant, digest):
    """What production image read paths can still see after erasure."""
    out = []
    for kind, table in PHYSICAL_KINDS:
        for r in rows(db, f'SELECT id,site,payload,state FROM {table} '
                          'WHERE tenant=? AND digest=? ORDER BY id', (tenant, digest)):
            out.append({'kind': kind, **r})
    return out


def scan_needles(db, needles):
    """Return {needle: [ {table,rowid,column}, ... ]} across every table/log."""
    hits = {n: [] for n in needles}
    tables = [r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    for table in tables:
        cols = [c[1] for c in db.execute(f'PRAGMA table_info({table})')]
        for col in cols:
            try:
                for rowid, val in db.execute(
                        f'SELECT rowid, {col} FROM {table} WHERE CAST({col} AS TEXT) IS NOT NULL'):
                    text = val if isinstance(val, str) else (
                        val.decode('utf-8', 'ignore') if isinstance(val, bytes) else str(val))
                    for n in needles:
                        if n and n in text:
                            hits[n].append({'table': table, 'rowid': rowid, 'column': col})
            except Exception:
                continue
    return {n: h for n, h in hits.items() if h}


ALIASES = {
    'copy': _op_copy,
    'hold': _op_hold,
    'legal_hold': _op_hold,
    'court_order': _op_hold,
    'order': _op_hold,
    'judicial_hold': _op_hold,
    'preservation_order': _op_hold,
    'preserve': _op_hold,
    'erase': _op_erase,
    'erase_request': _op_erase,
    'court_signer': _op_court_signer,
    'signer': _op_court_signer,
    'authorize_signer': _op_court_signer,
    'escrow': _op_escrow,
    'register_escrow': _op_escrow,
    'fault': _op_fault,
    'inject_fault': _op_fault,
    'cache': lambda db, x: _op_location(db, x, 'artifact_caches', None, 'cache'),
    'register_cache': lambda db, x: _op_location(db, x, 'artifact_caches', None, 'cache'),
    'backup': lambda db, x: _op_location(db, x, 'artifact_backups', None, 'backup'),
    'register_backup': lambda db, x: _op_location(db, x, 'artifact_backups', None, 'backup'),
    'runtime': lambda db, x: _op_location(db, x, 'runtime_artifacts', None, 'runtime'),
    'runtime_artifact': lambda db, x: _op_location(db, x, 'runtime_artifacts', None, 'runtime'),
    'mount': lambda db, x: _op_location(db, x, 'runtime_artifacts', None, 'runtime'),
    'fulfill': _op_fulfill,
    'fulfill_erasure': _op_fulfill,
    'execute_erasure': _op_fulfill,
    'complete_erasure': _op_fulfill,
    'process_erasure': _op_fulfill,
    'purge': _op_purge,
    'physical_erase': _op_purge,
    'physical_purge': _op_purge,
    'destroy_backups': _op_backups,
    'backup_purge': _op_backups,
    'purge_backups': _op_backups,
    'extract': lambda db, x: _op_preservation_only(db, x, 'external_escrow'),
    'judicial_extract': lambda db, x: _op_preservation_only(db, x, 'external_escrow'),
    'escrow_extract': lambda db, x: _op_preservation_only(db, x, 'external_escrow'),
    'deliver_escrow': _op_deliver_escrow,
    'retry_extraction': _op_deliver_escrow,
    'escrow_recover': _op_deliver_escrow,
    'seal_custody': lambda db, x: _op_preservation_only(db, x, 'isolated_custody'),
    'retain': lambda db, x: _op_preservation_only(db, x, 'isolated_custody'),
    'receipt': _op_receipt,
    'issue_receipt': _op_receipt,
    'customer_receipt': _op_receipt,
    'certify': _op_certify,
    'issue_certificate': _op_certify,
    'certificate': _op_certify,
    'revoke_hold': _op_revoke,
    'release_hold': _op_revoke,
    'withdraw_hold': _op_revoke,
    'lift_hold': _op_revoke,
    'revoke_order': _op_revoke,
    'access_custody': _op_access,
    'custody_access': _op_access,
}


def run(db, x):
    op = x['op']
    handler = ALIASES.get(op)
    if handler is None:
        raise ValueError(op)
    return handler(db, x)
