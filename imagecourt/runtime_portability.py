"""Runtime contract portability across infrastructure platforms.

A target that returns ``imported`` for a configuration bundle has only
acknowledged the fields; it has not promised to honour the runtime
contract.  The customer contract pinned in ``tenant_config`` (digest,
resource units, egress isolation, secret references, replicas) is only
delivered when the target's per-request decisions are probed and proven
no broader than the source contract.

Two delivery modes are supported, neither of which expands the source
egress set:

* ``hosted``: an independently operated egress/secret enforcement layer
  keeps the original automatic reachable set; target workloads depend on
  the platform continuing to operate that layer.
* ``narrow``: locally enforced, customer-signed narrower rules.  Some
  destinations move to manual admission with independently injected and
  revoked credentials; operations and revocation responsibility transfer
  to the target side and the original platform can eventually be exited.

Every state transition is recorded so that create, restrict, revoke and
destroy really happen on the target side and can be re-verified, and so
that a rollback preserves which side produced real traffic rather than
restoring a mere configuration pointer.
"""

import json

from .store import one, rows
from .tenant_config import export as export_config
from .foreign_runtime import import_bundle, permits_egress

UNIT_BYTES = {'MiB': 1024 ** 2, 'GiB': 1024 ** 3}

SCHEMA = '''
CREATE TABLE IF NOT EXISTS port_bundles(
    id TEXT PRIMARY KEY, config_id TEXT, customer TEXT, digest TEXT,
    replicas INTEGER, paid_concurrency INTEGER, document TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS targets(
    id TEXT PRIMARY KEY, memory_unit TEXT, supported_groups TEXT,
    secret_slot_mode TEXT, node_online INTEGER
);
CREATE TABLE IF NOT EXISTS hosted_layers(
    id TEXT PRIMARY KEY, online INTEGER
);
CREATE TABLE IF NOT EXISTS target_workloads(
    id TEXT PRIMARY KEY, bundle_id TEXT, target TEXT, mode TEXT,
    layer_id TEXT, delta_id TEXT, replicas INTEGER, running_replicas INTEGER,
    memory_bytes INTEGER, egress_state TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS port_trials(
    seq INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT, capability TEXT,
    probe TEXT, expected TEXT, observed TEXT, verdict TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS secret_grants(
    id TEXT PRIMARY KEY, bundle_id TEXT, target TEXT, customer TEXT,
    credential_id TEXT, slot_mode TEXT, holder TEXT, status TEXT
);
CREATE TABLE IF NOT EXISTS delta_signoffs(
    id TEXT PRIMARY KEY, bundle_id TEXT, customer TEXT,
    removed_groups TEXT, manual_groups TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS cutover_receipts(
    seq INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT, at INTEGER,
    source_active INTEGER, target_active INTEGER, total INTEGER,
    paid_limit INTEGER, within_limit INTEGER, note TEXT
);
CREATE TABLE IF NOT EXISTS port_traffic(
    seq INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT, side TEXT,
    destination TEXT, result TEXT, at INTEGER
);
CREATE TABLE IF NOT EXISTS rollback_records(
    id TEXT PRIMARY KEY, bundle_id TEXT, reason TEXT, at INTEGER,
    source_served INTEGER, target_served INTEGER, attempts TEXT,
    restored_side TEXT, state TEXT
);
CREATE TABLE IF NOT EXISTS port_events(
    seq INTEGER PRIMARY KEY AUTOINCREMENT, bundle_id TEXT,
    event TEXT, detail TEXT
);
'''


def _init(db):
    db.executescript(SCHEMA)


def _event(db, bundle_id, event, detail=''):
    db.execute('INSERT INTO port_events(bundle_id,event,detail) VALUES(?,?,?)',
               (bundle_id, event, detail))


def _bundle(db, bundle_id):
    return one(db, 'SELECT * FROM port_bundles WHERE id=?', (bundle_id,))


def _doc(db, bundle_id):
    return json.loads(_bundle(db, bundle_id)['document'])


def _workload(db, bundle_id):
    return one(db, 'SELECT * FROM target_workloads WHERE bundle_id=?',
               (bundle_id,))


def _target(db, target_id):
    return one(db, 'SELECT * FROM targets WHERE id=?', (target_id,))


# ---------------------------------------------------------------------------
# Pinned export and target capability registry
# ---------------------------------------------------------------------------

def build_bundle(db, bundle_id, config_id):
    """Pin the accepted runtime contract into an export document.

    Units are spelled out explicitly, egress is an allow-list with a
    default deny, and secret references travel as names only -- never as
    key material or another tenant's cached slot.
    """
    _init(db)
    row = one(db, 'SELECT * FROM tenant_configs WHERE id=?', (config_id,))
    if not row:
        return {'decision': 'unknown_config'}
    export_config(db, bundle_id, config_id)  # base document, reused id
    memory_bytes = row['memory_mb'] * UNIT_BYTES['MiB']
    document = {
        'bundle_id': bundle_id,
        'config_id': config_id,
        'customer': row['customer'],
        'digest': row['digest'],
        'memory': {'value': row['memory_mb'], 'unit': 'MiB',
                   'bytes': memory_bytes},
        'cpu_units': row['cpu_units'],
        'replicas': row['replicas'],
        'paid_concurrency': row['replicas'],
        'egress': {'mode': 'allowlist', 'allow': [row['egress_group']],
                   'default': 'deny'},
        'secrets': [{'ref': row['secret_ref'], 'material_included': False}],
    }
    db.execute('INSERT INTO port_bundles VALUES(?,?,?,?,?,?,?,?)',
               (bundle_id, config_id, row['customer'], row['digest'],
                row['replicas'], row['replicas'],
                json.dumps(document, sort_keys=True), 'drafted'))
    _event(db, bundle_id, 'bundle_drafted')
    return {'decision': 'bundle_drafted', 'document': document}


def register_target(db, target_id, memory_unit='GiB',
                    supported_groups=(), secret_slot_mode='shared',
                    node_online=True):
    _init(db)
    if memory_unit not in UNIT_BYTES:
        return {'decision': 'unknown_memory_unit'}
    db.execute('INSERT OR REPLACE INTO targets VALUES(?,?,?,?,?)',
               (target_id, memory_unit, json.dumps(sorted(supported_groups)),
                secret_slot_mode, 1 if node_online else 0))
    return {'decision': 'target_registered', 'target': target_id}


def set_node_online(db, target_id, online):
    _init(db)
    db.execute('UPDATE targets SET node_online=? WHERE id=?',
               (1 if online else 0, target_id))
    return {'decision': 'node_online' if online else 'node_offline',
            'target': target_id}


def register_layer(db, layer_id, online=True):
    _init(db)
    db.execute('INSERT OR REPLACE INTO hosted_layers VALUES(?,?)',
               (layer_id, 1 if online else 0))
    return {'decision': 'layer_registered', 'layer': layer_id}


def set_layer_online(db, layer_id, online):
    _init(db)
    db.execute('UPDATE hosted_layers SET online=? WHERE id=?',
               (1 if online else 0, layer_id))
    return {'decision': 'layer_online' if online else 'layer_offline',
            'layer': layer_id}


def acknowledge_import(db, bundle_id, target, import_id=None):
    """Run the foreign importer and mark its verdict as untrusted.

    Receiving the fields is not understanding them: the same import that
    returns ``imported`` still permits the unapproved group.
    """
    _init(db)
    import_id = import_id or 'imp-' + bundle_id
    status = import_bundle(db, import_id, bundle_id, target)
    if status != 'imported':
        return {'decision': 'import_failed', 'status': status}
    over_privileged = permits_egress(db, import_id, 'unapproved')
    db.execute("UPDATE port_bundles SET state='imported_untrusted' WHERE id=?",
               (bundle_id,))
    _event(db, bundle_id, 'import_acknowledged_untrusted',
           json.dumps({'target': target, 'import': import_id,
                       'bare_allows_unapproved': bool(over_privileged)}))
    return {'decision': 'import_acknowledged_untrusted',
            'import': import_id,
            'bare_import_allows_unapproved': bool(over_privileged)}


# ---------------------------------------------------------------------------
# Real target-side provisioning: create with explicit unit conversion
# ---------------------------------------------------------------------------

def provision_workload(db, workload_id, bundle_id, target):
    _init(db)
    bundle = _bundle(db, bundle_id)
    tgt = _target(db, target)
    if not bundle or not tgt:
        return {'decision': 'unknown_bundle_or_target'}
    if _workload(db, bundle_id):
        return {'decision': 'workload_identity_conflict'}
    if not tgt['node_online']:
        return {'decision': 'target_node_offline'}
    document = json.loads(bundle['document'])
    pinned_bytes = document['memory']['bytes']
    unit_bytes = UNIT_BYTES[tgt['memory_unit']]
    if pinned_bytes % unit_bytes:
        return {'decision': 'memory_unit_indivisible'}
    target_value = pinned_bytes // unit_bytes
    db.execute('INSERT INTO target_workloads VALUES(?,?,?,?,?,?,?,?,?,?,?)',
               (workload_id, bundle_id, target, None, None, None,
                document['replicas'], 0, pinned_bytes, 'unbound', 'created'))
    _event(db, bundle_id, 'workload_created',
           json.dumps({'workload': workload_id, 'target': target,
                       'target_memory_value': target_value,
                       'target_memory_unit': tgt['memory_unit'],
                       'effective_bytes': pinned_bytes}))
    return {'decision': 'workload_provisioned', 'workload': workload_id,
            'memory': {'value': target_value,
                       'unit': tgt['memory_unit'],
                       'bytes': pinned_bytes}}


# ---------------------------------------------------------------------------
# Independent secret injection with its own authorization and revocation
# ---------------------------------------------------------------------------

def inject_secret(db, grant_id, bundle_id, target):
    _init(db)
    bundle = _bundle(db, bundle_id)
    tgt = _target(db, target)
    wl = _workload(db, bundle_id)
    if not bundle or not tgt or not wl:
        return {'decision': 'unknown_bundle_target_or_workload'}
    if tgt['secret_slot_mode'] == 'shared':
        _event(db, bundle_id, 'secret_injection_rejected',
               json.dumps({'target': target, 'reason': 'cross_tenant_slot'}))
        return {'decision': 'cross_tenant_secret_slot'}
    if one(db, 'SELECT id FROM secret_grants WHERE id=?', (grant_id,)):
        return {'decision': 'grant_identity_conflict'}
    holder = ('hosted-layer:' + wl['layer_id']) if wl['mode'] == 'hosted' \
        else 'customer-local'
    credential_id = 'cred-' + grant_id  # freshly minted, no material stored
    db.execute('INSERT INTO secret_grants VALUES(?,?,?,?,?,?,?,?)',
               (grant_id, bundle_id, target, bundle['customer'],
                credential_id, 'tenant', holder, 'authorized'))
    _event(db, bundle_id, 'secret_authorized',
           json.dumps({'grant': grant_id, 'credential': credential_id,
                       'holder': holder}))
    return {'decision': 'secret_authorized', 'grant': grant_id,
            'credential_id': credential_id, 'holder': holder}


def revoke_secret(db, grant_id):
    _init(db)
    grant = one(db, 'SELECT * FROM secret_grants WHERE id=?', (grant_id,))
    if not grant:
        return {'decision': 'unknown_grant'}
    db.execute("UPDATE secret_grants SET status='revoked' WHERE id=?",
               (grant_id,))
    _event(db, grant['bundle_id'], 'secret_revoked', grant_id)
    return {'decision': 'secret_revoked', 'grant': grant_id}


# ---------------------------------------------------------------------------
# Narrowing delta: only the customer may sign away reachable business
# ---------------------------------------------------------------------------

def propose_delta(db, delta_id, bundle_id, removed_groups, manual_groups):
    _init(db)
    bundle = _bundle(db, bundle_id)
    if not bundle:
        return {'decision': 'unknown_bundle'}
    document = json.loads(bundle['document'])
    allowed = set(document['egress']['allow'])
    removed = set(removed_groups)
    manual = set(manual_groups)
    if (removed | manual) - allowed:
        return {'decision': 'delta_outside_source_scope'}
    if removed & manual:
        return {'decision': 'delta_group_overlap'}
    db.execute('INSERT INTO delta_signoffs VALUES(?,?,?,?,?,?)',
               (delta_id, bundle_id, bundle['customer'],
                json.dumps(sorted(removed)), json.dumps(sorted(manual)),
                'proposed'))
    _event(db, bundle_id, 'delta_proposed', delta_id)
    return {'decision': 'delta_proposed', 'delta': delta_id}


def sign_delta(db, delta_id):
    _init(db)
    delta = one(db, 'SELECT * FROM delta_signoffs WHERE id=?', (delta_id,))
    if not delta:
        return {'decision': 'unknown_delta'}
    if delta['state'] != 'proposed':
        return {'decision': 'delta_not_open'}
    db.execute("UPDATE delta_signoffs SET state='signed' WHERE id=?",
               (delta_id,))
    _event(db, delta['bundle_id'], 'delta_signed', delta_id)
    return {'decision': 'delta_signed', 'delta': delta_id}


def reject_delta(db, delta_id):
    _init(db)
    delta = one(db, 'SELECT * FROM delta_signoffs WHERE id=?', (delta_id,))
    if not delta:
        return {'decision': 'unknown_delta'}
    db.execute("UPDATE delta_signoffs SET state='rejected' WHERE id=?",
               (delta_id,))
    _event(db, delta['bundle_id'], 'delta_rejected', delta_id)
    return {'decision': 'delta_rejected', 'delta': delta_id}


def _local_allow_set(document, delta):
    allowed = set(document['egress']['allow'])
    if delta is None:
        return allowed
    removed = set(json.loads(delta['removed_groups']))
    manual = set(json.loads(delta['manual_groups']))
    return allowed - removed - manual


# ---------------------------------------------------------------------------
# Egress binding and the target's actual per-request decision
# ---------------------------------------------------------------------------

def bind_egress(db, bundle_id, target, mode, layer_id=None, delta_id=None):
    _init(db)
    bundle = _bundle(db, bundle_id)
    tgt = _target(db, target)
    wl = _workload(db, bundle_id)
    if not bundle or not tgt or not wl:
        return {'decision': 'unknown_bundle_target_or_workload'}
    if wl['state'] == 'destroyed':
        return {'decision': 'workload_destroyed'}
    document = json.loads(bundle['document'])
    if mode == 'hosted':
        layer = one(db, 'SELECT * FROM hosted_layers WHERE id=?', (layer_id,))
        if not layer:
            return {'decision': 'layer_unregistered'}
        db.execute('UPDATE target_workloads SET mode=?,layer_id=?,delta_id=?,'
                   "egress_state='restricted',state='restricted' WHERE bundle_id=?",
                   (mode, layer_id, None, bundle_id))
        _event(db, bundle_id, 'egress_bound', json.dumps({'mode': mode}))
        return {'decision': 'egress_bound', 'mode': mode,
                'allow': document['egress']['allow']}
    if mode == 'narrow':
        delta = one(db, 'SELECT * FROM delta_signoffs WHERE id=?',
                    (delta_id,))
        if not delta or delta['bundle_id'] != bundle_id:
            return {'decision': 'unknown_delta'}
        if delta['state'] != 'signed':
            return {'decision': 'delta_not_signed'}
        local_allow = _local_allow_set(document, delta)
        # Hard invariant: local automatic reach may only shrink.
        if not local_allow <= set(document['egress']['allow']):
            return {'decision': 'egress_expansion_blocked'}
        supported = set(json.loads(tgt['supported_groups']))
        unsupported = local_allow - supported
        if unsupported:
            return {'decision': 'target_unsupported_group',
                    'groups': sorted(unsupported)}
        db.execute('UPDATE target_workloads SET mode=?,layer_id=?,delta_id=?,'
                   "egress_state='restricted',state='restricted' WHERE bundle_id=?",
                   (mode, None, delta_id, bundle_id))
        _event(db, bundle_id, 'egress_bound',
               json.dumps({'mode': mode, 'allow': sorted(local_allow)}))
        return {'decision': 'egress_bound', 'mode': mode,
                'allow': sorted(local_allow)}
    return {'decision': 'unknown_mode'}


def evaluate_egress(db, bundle_id, destination):
    """The target runner's real decision for one egress request."""
    wl = _workload(db, bundle_id)
    if not wl:
        return {'decision': 'workload_missing'}
    tgt = _target(db, wl['target'])
    if not tgt['node_online']:
        return {'decision': 'node_offline', 'destination': destination}
    if wl['state'] == 'destroyed':
        return {'decision': 'workload_destroyed', 'destination': destination}
    document = _doc(db, bundle_id)
    if wl['egress_state'] != 'restricted':
        # Bare imported runner: acknowledges fields, enforces nothing.
        return {'decision': 'allow', 'enforcement': 'none',
                'destination': destination}
    if wl['mode'] == 'hosted':
        layer = one(db, 'SELECT * FROM hosted_layers WHERE id=?',
                    (wl['layer_id'],))
        if not layer or not layer['online']:
            return {'decision': 'enforcement_unreachable',
                    'destination': destination}  # fail closed
        allowed = destination in document['egress']['allow']
        return {'decision': 'allow' if allowed else 'deny',
                'enforcement': 'hosted', 'destination': destination}
    # narrow local rules
    delta = one(db, 'SELECT * FROM delta_signoffs WHERE id=?',
                (wl['delta_id'],))
    manual = set(json.loads(delta['manual_groups']))
    if destination in manual:
        return {'decision': 'manual_admission', 'enforcement': 'local',
                'destination': destination}
    if destination in _local_allow_set(document, delta):
        return {'decision': 'allow', 'enforcement': 'local',
                'destination': destination}
    return {'decision': 'deny', 'enforcement': 'local',
            'destination': destination}


def target_request(db, bundle_id, destination, at=0):
    """Drive one real target-side request and record the customer result."""
    _init(db)
    result = evaluate_egress(db, bundle_id, destination)
    db.execute('INSERT INTO port_traffic(bundle_id,side,destination,result,at)'
               ' VALUES(?,?,?,?,?)',
               (bundle_id, 'target', destination, result['decision'], at))
    return result


def source_request(db, bundle_id, destination, at=0):
    """Record traffic still served by the original platform's leases."""
    _init(db)
    document = _doc(db, bundle_id)
    decision = ('allow' if destination in document['egress']['allow']
                else 'deny')
    db.execute('INSERT INTO port_traffic(bundle_id,side,destination,result,at)'
               ' VALUES(?,?,?,?,?)',
               (bundle_id, 'source', destination, decision, at))
    return {'decision': decision, 'enforcement': 'source',
            'destination': destination}


# ---------------------------------------------------------------------------
# Trial runs: every capability needs both an allow and a deny result
# ---------------------------------------------------------------------------

def run_trials(db, bundle_id):
    _init(db)
    bundle = _bundle(db, bundle_id)
    wl = _workload(db, bundle_id)
    if not bundle or not wl:
        return {'decision': 'unknown_bundle_or_workload'}
    tgt = _target(db, wl['target'])
    document = json.loads(bundle['document'])
    db.execute('DELETE FROM port_trials WHERE bundle_id=?', (bundle_id,))
    trials = []

    def record(capability, probe, expected, observed, detail=''):
        verdict = 'pass' if str(expected) == str(observed) else 'fail'
        db.execute('INSERT INTO port_trials'
                   '(bundle_id,capability,probe,expected,observed,verdict,detail)'
                   ' VALUES(?,?,?,?,?,?,?)',
                   (bundle_id, capability, probe, str(expected),
                    str(observed), verdict, detail))
        trials.append({'capability': capability, 'probe': probe,
                       'expected': str(expected), 'observed': str(observed),
                       'verdict': verdict})

    if not tgt['node_online']:
        record('node', 'online', 'online', 'offline')
        return {'decision': 'trials_failed',
                'failures': [t for t in trials if t['verdict'] == 'fail']}

    # Egress: paired allow/deny probes against the real target decision.
    probes = []
    narrow = wl['mode'] == 'narrow' and wl['delta_id']
    if narrow:
        delta = one(db, 'SELECT * FROM delta_signoffs WHERE id=?',
                    (wl['delta_id'],))
        manual = set(json.loads(delta['manual_groups']))
        removed = set(json.loads(delta['removed_groups']))
    else:
        delta = manual = removed = None
    for group in _local_allow_set(document, delta):
        probes.append((group, 'allow'))
    probes.append(('unapproved', 'deny'))
    if narrow:
        for group in manual:
            probes.append((group, 'manual_admission'))
        for group in removed:
            probes.append((group, 'deny'))
    for destination, expected in probes:
        observed = evaluate_egress(db, bundle_id, destination)['decision']
        record('egress', destination, expected, observed)

    # Memory: evidence of the bare misread, then the effective limit.
    pinned = document['memory']['bytes']
    imported = one(db, 'SELECT imported_memory FROM foreign_runtimes '
                       'WHERE bundle=? ORDER BY rowid DESC LIMIT 1',
                   (bundle_id,))
    if imported:
        bare_bytes = imported['imported_memory'] * UNIT_BYTES[tgt['memory_unit']]
        record('memory_evidence', 'bare_import_interpretation', pinned,
               bare_bytes, 'field accepted but interpreted in target units')
    record('memory', 'effective_bytes', pinned, wl['memory_bytes'])

    # Secrets: independent grant in a tenant-isolated slot.
    grants = rows(db, 'SELECT * FROM secret_grants WHERE bundle_id=?',
                  (bundle_id,))
    if not grants:
        record('secret', 'independent_grant', 'authorized', 'missing')
    for grant in grants:
        record('secret', grant['id'], 'tenant/authorized',
               '%s/%s' % (grant['slot_mode'], grant['status']))

    failures = [t for t in trials
                if t['verdict'] == 'fail' and t['capability'] != 'memory_evidence']
    decision = 'trials_passed' if not failures else 'trials_failed'
    if decision == 'trials_passed':
        db.execute("UPDATE port_bundles SET state='trials_passed' WHERE id=?",
                   (bundle_id,))
    _event(db, bundle_id, decision, json.dumps({'failures': failures}))
    return {'decision': decision, 'trials': trials, 'failures': failures}


def accept_target(db, bundle_id):
    _init(db)
    bundle = _bundle(db, bundle_id)
    wl = _workload(db, bundle_id)
    if not bundle or not wl:
        return {'decision': 'unknown_bundle_or_workload'}
    tgt = _target(db, wl['target'])
    reasons = []
    if not tgt['node_online']:
        reasons.append('target_node_offline')
    if wl['egress_state'] != 'restricted':
        reasons.append('egress_not_restricted')
    if wl['mode'] == 'hosted':
        layer = one(db, 'SELECT * FROM hosted_layers WHERE id=?',
                    (wl['layer_id'],))
        if not layer or not layer['online']:
            reasons.append('hosted_layer_unreachable')
    if wl['mode'] == 'narrow':
        delta = one(db, 'SELECT * FROM delta_signoffs WHERE id=?',
                    (wl['delta_id'],))
        if not delta or delta['state'] != 'signed':
            reasons.append('delta_not_signed')
    grants = rows(db, 'SELECT * FROM secret_grants WHERE bundle_id=?',
                  (bundle_id,))
    if not grants or any(g['status'] != 'authorized'
                         or g['slot_mode'] != 'tenant' for g in grants):
        reasons.append('secret_grant_invalid')
    latest = rows(db, 'SELECT * FROM port_trials WHERE bundle_id=?',
                  (bundle_id,))
    if not latest:
        reasons.append('no_trials')
    elif any(t['verdict'] == 'fail' and t['capability'] != 'memory_evidence'
             for t in latest):
        reasons.append('trials_failed')
    if reasons:
        _event(db, bundle_id, 'acceptance_blocked', json.dumps(reasons))
        return {'decision': 'acceptance_blocked', 'reasons': reasons}
    db.execute("UPDATE port_bundles SET state='accepted' WHERE id=?",
               (bundle_id,))
    _event(db, bundle_id, 'target_accepted')
    return {'decision': 'target_accepted'}


# ---------------------------------------------------------------------------
# Cutover: paid concurrency holds on both sides, source stays until accepted
# ---------------------------------------------------------------------------

def _concurrency(db, bundle):
    source = one(db, "SELECT COUNT(*) AS n FROM leases WHERE digest=? "
                     "AND status='active'", (bundle['digest'],))['n']
    wl = _workload(db, bundle['id'])
    target = wl['running_replicas'] if wl else 0
    return source, target


def _receipt(db, bundle, at, note, planned_source=None, planned_target=None):
    if planned_source is None and planned_target is None:
        source, target = _concurrency(db, bundle)
    else:
        source, target = planned_source, planned_target
    total = source + target
    within = 1 if total <= bundle['paid_concurrency'] else 0
    db.execute('INSERT INTO cutover_receipts'
               '(bundle_id,at,source_active,target_active,total,paid_limit,'
               'within_limit,note) VALUES(?,?,?,?,?,?,?,?)',
               (bundle['id'], at, source, target, total,
                bundle['paid_concurrency'], within, note))
    return {'seq': one(db, 'SELECT MAX(seq) AS s FROM cutover_receipts')['s'],
            'source_active': source, 'target_active': target,
            'total': total, 'paid_limit': bundle['paid_concurrency'],
            'within_limit': bool(within), 'note': note}


def begin_cutover(db, bundle_id, at=0):
    _init(db)
    bundle = _bundle(db, bundle_id)
    if not bundle:
        return {'decision': 'unknown_bundle'}
    if bundle['state'] != 'accepted':
        return {'decision': 'target_not_accepted'}
    db.execute("UPDATE port_bundles SET state='cutover_in_progress' WHERE id=?",
               (bundle_id,))
    receipt = _receipt(db, bundle, at, 'cutover_started')
    _event(db, bundle_id, 'cutover_started')
    return {'decision': 'cutover_started', 'receipt': receipt}


def cutover_step(db, bundle_id, at=0, retire=0, activate=0):
    _init(db)
    bundle = _bundle(db, bundle_id)
    wl = _workload(db, bundle_id)
    if not bundle or not wl:
        return {'decision': 'unknown_bundle_or_workload'}
    if bundle['state'] != 'cutover_in_progress':
        return {'decision': 'target_not_accepted'}
    source, target = _concurrency(db, bundle)
    if retire > source or activate < 0 or target + activate > wl['replicas']:
        return {'decision': 'invalid_replica_move'}
    planned_total = (source - retire) + (target + activate)
    if planned_total > bundle['paid_concurrency']:
        receipt = _receipt(db, bundle, at, 'double_occupancy_rejected',
                           planned_source=source, planned_target=target + activate)
        _event(db, bundle_id, 'concurrency_exceeded',
               json.dumps({'planned_total': planned_total}))
        return {'decision': 'concurrency_exceeded', 'receipt': receipt}
    if retire:
        ids = [r['id'] for r in rows(
            db, "SELECT id FROM leases WHERE digest=? AND status='active' "
                "ORDER BY id LIMIT ?", (bundle['digest'], retire))]
        db.executemany(
            "UPDATE leases SET status='retired' WHERE id=?",
            [(lease_id,) for lease_id in ids])
    db.execute('UPDATE target_workloads SET running_replicas=? WHERE bundle_id=?',
               (target + activate, bundle_id))
    receipt = _receipt(db, bundle, at,
                       'retired=%d activated=%d' % (retire, activate))
    _event(db, bundle_id, 'cutover_step', receipt['note'])
    return {'decision': 'cutover_step', 'receipt': receipt}


def complete_cutover(db, bundle_id, at=0):
    _init(db)
    bundle = _bundle(db, bundle_id)
    wl = _workload(db, bundle_id)
    if not bundle or not wl:
        return {'decision': 'unknown_bundle_or_workload'}
    if bundle['state'] != 'cutover_in_progress':
        return {'decision': 'cutover_not_in_progress'}
    source, target = _concurrency(db, bundle)
    if source != 0 or target != wl['replicas']:
        return {'decision': 'cutover_incomplete',
                'source_active': source, 'target_active': target}
    db.execute("UPDATE port_bundles SET state='completed' WHERE id=?",
               (bundle_id,))
    receipt = _receipt(db, bundle, at, 'cutover_completed')
    _event(db, bundle_id, 'cutover_completed')
    return {'decision': 'cutover_completed', 'receipt': receipt}


def renew_source_lease(db, bundle_id, lease_id, expires, at=0):
    """A source lease renewed after cutover is a late, double-occupying lease."""
    _init(db)
    bundle = _bundle(db, bundle_id)
    lease = one(db, 'SELECT * FROM leases WHERE id=?', (lease_id,))
    if not bundle or not lease:
        return {'decision': 'unknown_bundle_or_lease'}
    if bundle['state'] in ('cutover_in_progress', 'completed', 'rolled_back'):
        receipt = _receipt(db, bundle, at, 'late_renewal_rejected')
        _event(db, bundle_id, 'late_renewal_rejected', lease_id)
        return {'decision': 'late_renewal_rejected', 'lease': lease_id,
                'receipt': receipt}
    if lease['status'] != 'active':
        return {'decision': 'lease_unavailable'}
    db.execute('UPDATE leases SET expires=? WHERE id=?', (expires, lease_id))
    _event(db, bundle_id, 'lease_renewed', lease_id)
    return {'decision': 'lease_renewed', 'lease': lease_id}


# ---------------------------------------------------------------------------
# Rollback: restore real serving capacity and keep traffic attribution
# ---------------------------------------------------------------------------

def rollback(db, rollback_id, bundle_id, reason, at=0):
    _init(db)
    bundle = _bundle(db, bundle_id)
    wl = _workload(db, bundle_id)
    if not bundle:
        return {'decision': 'unknown_bundle'}
    if bundle['state'] == 'rolled_back':
        return {'decision': 'rollback_already_recorded'}
    traffic = rows(db, 'SELECT * FROM port_traffic WHERE bundle_id=?',
                   (bundle_id,))
    source_served = sum(1 for t in traffic
                        if t['side'] == 'source' and t['result'] == 'allow')
    target_served = sum(1 for t in traffic
                        if t['side'] == 'target' and t['result'] == 'allow')
    attempts = [{'side': t['side'], 'destination': t['destination'],
                 'result': t['result'], 'at': t['at']} for t in traffic]
    # Restore real source serving capacity, not a configuration pointer.
    restored = db.execute(
        "UPDATE leases SET status='active' WHERE digest=? AND status='retired'",
        (bundle['digest'],)).rowcount
    db.execute("UPDATE secret_grants SET status='revoked' WHERE bundle_id=? "
               "AND status='authorized'", (bundle_id,))
    if wl:
        db.execute("UPDATE target_workloads SET running_replicas=0,"
                   "egress_state='unbound',state='destroyed' WHERE bundle_id=?",
                   (bundle_id,))
    source_after = one(db, "SELECT COUNT(*) AS n FROM leases WHERE digest=? "
                           "AND status='active'", (bundle['digest'],))['n']
    restored_side = 'source' if source_after else 'none'
    db.execute('INSERT INTO rollback_records VALUES(?,?,?,?,?,?,?,?,?)',
               (rollback_id, bundle_id, reason, at, source_served,
                target_served, json.dumps(attempts, sort_keys=True),
                restored_side, 'rolled_back'))
    db.execute("UPDATE port_bundles SET state='rolled_back' WHERE id=?",
               (bundle_id,))
    _event(db, bundle_id, 'rolled_back',
           json.dumps({'reason': reason, 'restored_leases': restored,
                       'restored_side': restored_side}))
    return {'decision': 'rolled_back', 'rollback': rollback_id,
            'source_served': source_served, 'target_served': target_served,
            'customer_results': attempts,
            'restored_leases': restored, 'restored_side': restored_side}
