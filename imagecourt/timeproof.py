"""Independent time evidence and release-window proofs.

The legacy ``source``/``stamp``/``certificate`` operations stay byte-for-byte
compatible with the first time-proof slice: a certificate without a ``scope``
still records the earliest ``claimed_utc`` as a ``provisional`` value.

The release-proof layer added here never mistakes that earliest self-report for
UTC.  Every clock original carries an operator, signing chain, calibration
period, deviation interval and a non-reusable witness sequence number.  Times
are intervals (``true_utc = claimed_utc + delta`` with
``offset_min <= delta <= offset_max``); witnesses sharing an operator or an
upstream source are correlated and count as one independence root.

The pure functions (:func:`reconstruct_release` and friends) only depend on
plain JSON originals, so an independent reviewer can recompute every interval,
independence group and window verdict without trusting the database or any
issued certificate.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .store import one, rows

# ---------------------------------------------------------------------------
# Verdict vocabulary
# ---------------------------------------------------------------------------

PROVABLY_WITHIN = 'provably_within'
PROVABLY_OUTSIDE = 'provably_outside'
INSUFFICIENT_EVIDENCE = 'insufficient_evidence'

# Certificate statuses.
ORDER_PROVEN = 'order_proven'
TIME_CERTIFIED = 'time_certified'
TIME_CERTIFIED_OUTSIDE = 'time_certified_outside'
TIME_UNPROVEN = 'time_unproven'
PROVISIONAL = 'provisional'

# Interval-to-window status mapping (three-valued; never back-fills an instant).
WINDOW_STATUS = {
    PROVABLY_WITHIN: TIME_CERTIFIED,
    PROVABLY_OUTSIDE: TIME_CERTIFIED_OUTSIDE,
    INSUFFICIENT_EVIDENCE: TIME_UNPROVEN,
}

SEQ_ONLY_CLOCK_VERSION = 'seq-only:events-v1'


# ---------------------------------------------------------------------------
# Canonical digests
# ---------------------------------------------------------------------------

def canonical_json(value):
    """Same canonical text ``store.execute`` writes into ``events.payload``."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def digest_text(text):
    if not isinstance(text, str):
        text = str(text)
    return 'sha256:' + hashlib.sha256(text.encode('utf-8')).hexdigest()


def digest_payload(value):
    """Digest a JSON-able object.

    For the exact command dict passed to :func:`imagecourt.store.execute` this
    equals ``digest_text(events.payload)`` for the recorded event row.
    """
    if isinstance(value, str):
        return digest_text(value)
    return digest_text(canonical_json(value))


def short_digest(value, length=16):
    digest = digest_payload(value) if not str(value).startswith('sha256:') else value
    return digest[:7 + length]


# ---------------------------------------------------------------------------
# Pure interval mathematics
# ---------------------------------------------------------------------------

def clean_interval(interval):
    if interval is None:
        return None
    low, high = interval[0], interval[1]
    if low is None or high is None:
        return None
    low, high = int(low), int(high)
    if low > high:  # defensive ordering; strict registration validates this
        low, high = high, low
    return [low, high]


def claim_interval(claimed_utc, offset_min, offset_max, extra_offset=None):
    """Absolute UTC interval for one self-report.

    ``offset_*`` are corrections added to the claimed reading.  ``extra_offset``
    is an optional common-mode (shared upstream) interval added on top.
    """
    if claimed_utc is None or offset_min is None or offset_max is None:
        return None
    low = int(claimed_utc) + int(offset_min)
    high = int(claimed_utc) + int(offset_max)
    if extra_offset:
        low += int(extra_offset[0])
        high += int(extra_offset[1])
    return clean_interval([low, high])


# Friendly aliases.
stamp_interval = claim_interval
time_interval = claim_interval


def combine_intervals(intervals):
    """Intersection of guaranteed intervals; ``None`` when absent/contradictory."""
    usable = [clean_interval(iv) for iv in intervals]
    usable = [iv for iv in usable if iv is not None]
    if not usable:
        return None
    low = max(iv[0] for iv in usable)
    high = min(iv[1] for iv in usable)
    if low > high:
        return None
    return [low, high]


intersect_intervals = combine_intervals
merge_intervals = combine_intervals


def interval_conflict(intervals):
    """Intersection endpoints even when empty, to report contradictory evidence."""
    usable = [clean_interval(iv) for iv in intervals]
    usable = [iv for iv in usable if iv is not None]
    if len(usable) < 2:
        return None
    low = max(iv[0] for iv in usable)
    high = min(iv[1] for iv in usable)
    if low > high:
        return [low, high]
    return None


def window_verdict(interval, start, expires):
    """Three-valued boundary verdict for the half-open window ``[start, expires)``.

    Returns :data:`PROVABLY_WITHIN`, :data:`PROVABLY_OUTSIDE` or
    :data:`INSUFFICIENT_EVIDENCE`.  An interval crossing either boundary can
    never be collapsed to a chosen instant.
    """
    iv = clean_interval(interval)
    if iv is None or expires is None:
        return INSUFFICIENT_EVIDENCE
    low, high = iv
    expires = int(expires)
    if start is not None:
        start = int(start)
        if high < start:
            return PROVABLY_OUTSIDE  # every possible instant precedes opening
        if low >= expires:
            return PROVABLY_OUTSIDE  # every possible instant is at/after close
        if low >= start and high < expires:
            return PROVABLY_WITHIN
        return INSUFFICIENT_EVIDENCE
    if low >= expires:
        return PROVABLY_OUTSIDE
    if high < expires:
        return PROVABLY_WITHIN
    return INSUFFICIENT_EVIDENCE


classify_window = window_verdict
boundary_verdict = window_verdict


def verdict_status(verdict):
    return WINDOW_STATUS.get(verdict, TIME_UNPROVEN)


def compare_intervals(a, b):
    """Qualitative relation of two intervals: before/after/overlapping/..."""
    a = clean_interval(a)
    b = clean_interval(b)
    if not a or not b:
        return 'unknown'
    if a[1] < b[0]:
        return 'before'
    if b[1] < a[0]:
        return 'after'
    if a == b:
        return 'coincident'
    return 'overlapping'


interval_relation = compare_intervals


def order_labels(relation, first='propose', second='publish'):
    if relation == 'before':
        return f'{first}_before_{second}'
    if relation == 'after':
        return f'{second}_before_{first}'
    if relation == 'coincident':
        return 'coincident'
    if relation == 'overlapping':
        return 'overlapping'
    return 'unknown'


# ---------------------------------------------------------------------------
# Witness independence
# ---------------------------------------------------------------------------

def _pick(d, *keys):
    for key in keys:
        value = d.get(key)
        if value is not None:
            return value
    return None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]


def normalize_witness(w):
    if not isinstance(w, dict):
        try:
            w = dict(w)  # sqlite3.Row and mapping-like originals
        except (TypeError, ValueError):
            w = {}
    return {
        'id': _pick(w, 'id', 'witness_id', 'source', 'source_id'),
        'operator': _pick(w, 'operator', 'operating_entity', 'entity'),
        'kind': _pick(w, 'kind', 'source_kind', 'type') or 'unspecified',
        'witness_seq': _pick(w, 'witness_seq', 'witness_number', 'serial', 'nonce'),
        'signing_chain': _as_list(_pick(w, 'signing_chain', 'chain', 'signers')),
        'calibration_start': _pick(w, 'calibration_start', 'calibrated_at',
                                   'valid_from', 'calibration_from'),
        'calibration_end': _pick(w, 'calibration_end', 'valid_until',
                                 'calibrated_until', 'calibration_to'),
        'offset_min': _pick(w, 'offset_min', 'error_min', 'lower_error'),
        'offset_max': _pick(w, 'offset_max', 'error_max', 'upper_error'),
        'upstream_group': _pick(w, 'upstream_group', 'shared_upstream',
                                'upstream', 'upstream_source'),
        'absolute': bool(w.get('absolute', True)),
        'calibrations': list(w.get('calibrations') or []),
    }


def independence_report(witnesses):
    """Group correlated witnesses by shared operator OR shared upstream.

    Two records from one operator can never count as two independent witnesses,
    and distinct operators fed by one upstream source sit in one correlation
    component as well.
    """
    items = [normalize_witness(w) for w in witnesses]
    items = [w for w in items if w.get('id') is not None]
    n = len(items)

    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i, j):
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    for i in range(n):
        for j in range(i + 1, n):
            same_operator = items[i]['operator'] and items[i]['operator'] == items[j]['operator']
            same_upstream = (items[i]['upstream_group'] and
                             items[i]['upstream_group'] == items[j]['upstream_group'])
            if same_operator or same_upstream:
                union(i, j)

    components = {}
    for i, w in enumerate(items):
        components.setdefault(find(i), []).append(str(w['id']))
    groups = [sorted(ids) for ids in components.values()]
    groups.sort(key=lambda ids: ids[0])

    operator_groups = {}
    upstream_groups = {}
    for w in items:
        if w['operator']:
            operator_groups.setdefault(str(w['operator']), []).append(str(w['id']))
        if w['upstream_group']:
            upstream_groups.setdefault(str(w['upstream_group']), []).append(str(w['id']))

    same_operator = any(len(ids) > 1 for ids in operator_groups.values())
    shared_upstream = any(len(ids) > 1 for ids in upstream_groups.values())
    root_count = len(groups)
    return {
        'witness_count': n,
        'independence_groups': root_count,
        'independent_root_count': root_count,
        'all_roots_distinct': root_count == n,
        'fully_independent': n >= 2 and root_count == n,
        'same_operator': same_operator,
        'shared_upstream': shared_upstream,
        'operator_groups': {k: sorted(v) for k, v in sorted(operator_groups.items())},
        'upstream_groups': {k: sorted(v) for k, v in sorted(upstream_groups.items())},
        'groups': groups,
        'witnesses': [
            {'id': str(w['id']), 'operator': w['operator'], 'kind': w['kind'],
             'witness_seq': w['witness_seq'], 'upstream_group': w['upstream_group'],
             'independence_group': find(i)}
            for i, w in enumerate(items)
        ],
    }


witness_independence = independence_report
check_independence = independence_report


# ---------------------------------------------------------------------------
# Calibration resolution
# ---------------------------------------------------------------------------

def _as_int(value):
    return None if value is None else int(value)


def calibration_map(witness, extra_calibrations):
    """version -> calibration dict for one witness (base offsets are version 1)."""
    w = normalize_witness(witness)
    cals = {
        1: {
            'version': 1,
            'offset_min': _as_int(w['offset_min']),
            'offset_max': _as_int(w['offset_max']),
            'calibration_start': w['calibration_start'],
            'calibration_end': w['calibration_end'],
            'absolute': w['absolute'],
            'upstream_group': w['upstream_group'],
        }
    }
    incoming = list(w['calibrations'])
    for c in extra_calibrations or []:
        if _pick(c, 'source', 'source_id', 'witness_id') == w['id']:
            incoming.append(c)
    auto = 1
    for c in incoming:
        version = c.get('version')
        if version is None:
            auto += 1
            version = auto
        version = int(version)
        cals[version] = {
            'version': version,
            'offset_min': _as_int(_pick(c, 'offset_min', 'error_min')),
            'offset_max': _as_int(_pick(c, 'offset_max', 'error_max')),
            'calibration_start': _pick(c, 'calibration_start', 'calibrated_at',
                                       'valid_from'),
            'calibration_end': _pick(c, 'calibration_end', 'valid_until',
                                     'calibrated_until'),
            'absolute': bool(c.get('absolute', True)),
            'upstream_group': _pick(c, 'upstream_group', 'upstream') or w['upstream_group'],
            'reason': c.get('reason'),
            'recorded_at': c.get('recorded_at'),
        }
    return cals


def _upstream_map(bundle):
    upstreams = {}
    for u in bundle.get('upstreams') or []:
        uid = _pick(u, 'id', 'upstream_id')
        if uid is not None:
            upstreams[str(uid)] = {
                'offset_min': _as_int(_pick(u, 'offset_min', 'error_min')),
                'offset_max': _as_int(_pick(u, 'offset_max', 'error_max')),
            }
    return upstreams


def _resolved_offsets(cal, upstreams):
    omin, omax = cal['offset_min'], cal['offset_max']
    if omin is None or omax is None:
        return None
    if not cal.get('absolute', True):
        upstream = upstreams.get(str(cal.get('upstream_group')))
        if not upstream or upstream['offset_min'] is None:
            return None  # common-mode error is uncalibrated: no absolute interval
        omin += upstream['offset_min']
        omax += upstream['offset_max']
    return omin, omax


def _clock_version(used):
    material = sorted(used, key=lambda c: (str(c.get('source')), int(c.get('version') or 0)))
    return 'clock-v-' + hashlib.sha256(canonical_json(material).encode('utf-8')).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Pure release reconstruction
# ---------------------------------------------------------------------------

def _seq_map(bundle):
    seqs = {}
    for entry in bundle.get('commit_order') or []:
        if entry.get('event_key') is not None:
            seqs[entry['event_key']] = entry.get('seq')
    for entry in bundle.get('events') or []:
        key = entry.get('event_key')
        if key is not None and entry.get('seq') is not None:
            seqs[key] = entry['seq']
    for key, seq in (bundle.get('event_seqs') or {}).items():
        seqs[key] = seq
    return seqs


def _window(bundle):
    window = bundle.get('window') or {}
    start = _pick(window, 'start', 'window_start', 'start_minute')
    expires = _pick(window, 'expires', 'window_expires', 'close', 'closes_at')
    if start is None:
        start = bundle.get('window_start')
    if expires is None:
        expires = _pick(bundle, 'window_expires', 'expires', 'close')
    environment = window.get('environment') or bundle.get('environment')
    generation = window.get('generation') or bundle.get('window_generation')
    return {
        'start': _as_int(start) if start is not None else None,
        'expires': _as_int(expires) if expires is not None else None,
        'environment': environment,
        'generation': generation,
    }


def _release(bundle):
    release = bundle.get('release') or {}
    return {
        'release_ref': _pick(release, 'release_ref', 'id', 'name') or bundle.get('release_ref'),
        'digest': _pick(release, 'digest', 'image_digest') or bundle.get('digest'),
        'generation': _pick(release, 'generation') if release.get('generation') is not None
        else bundle.get('generation'),
    }


def reconstruct_release(bundle=None, *args, **kwargs):
    """Recompute intervals, order and window verdict from raw clock originals.

    The input is a plain JSON-able bundle (see
    ``fixtures/release_time_cross_clock.json``).  Nothing here reads the
    database or trusts a prior certificate, which is what lets an independent
    reviewer replay the judgement from the originals.

    Also tolerates the positional forms
    ``reconstruct_release(witnesses, stamps)`` and
    ``reconstruct_release(witnesses, stamps, window)``.
    """
    if bundle is None:
        bundle = {}
    elif isinstance(bundle, list):
        bundle = {'witnesses': bundle}
        if args:
            bundle['stamps'] = args[0]
        if len(args) > 1:
            bundle['window'] = args[1]
    if args and isinstance(args[0], dict) and 'stamps' not in bundle:
        bundle['stamps'] = args[0]
    if kwargs:
        merged = dict(bundle) if isinstance(bundle, dict) else {'witnesses': bundle}
        merged.update(kwargs)
        bundle = merged

    witnesses_raw = bundle.get('witnesses') or bundle.get('clock_sources') or []
    witnesses = {str(w['id']): w for w in (normalize_witness(w) for w in witnesses_raw)
                 if w.get('id') is not None}
    extra_cals = bundle.get('calibrations') or bundle.get('clock_calibrations') or []
    upstreams = _upstream_map(bundle)

    stamps = bundle.get('stamps') or bundle.get('time_stamps') or []
    version_map = bundle.get('version_map') or {}
    basis = bundle.get('basis', 'current')

    seq_map = _seq_map(bundle)
    window = _window(bundle)
    release = _release(bundle)

    # Latest calibration version per source.
    latest_version = {}
    cal_maps = {}
    for sid, w in witnesses.items():
        cmap = calibration_map(w, extra_cals)
        cal_maps[sid] = cmap
        latest_version[sid] = max(cmap)

    events_report = {}
    all_keys = []
    for s in stamps:
        key = s.get('event_key')
        if key is not None and key not in all_keys:
            all_keys.append(key)

    used_clock_records = []

    for key in all_keys:
        key_stamps = [s for s in stamps if s.get('event_key') == key]
        stamp_reports = []
        then_intervals = []
        primary_intervals = []
        current_intervals = []
        digest_values = []
        contributor_ids = []

        for s in key_stamps:
            sid = str(_pick(s, 'source', 'source_id', 'witness'))
            w = witnesses.get(sid)
            claimed = _as_int(_pick(s, 'claimed_utc', 'claimed', 'utc'))
            local_at = _as_int(s.get('local_at'))
            base = {
                'stamp_id': s.get('id'),
                'source': sid,
                'claimed_utc': claimed,
                'local_at': local_at,
                'backfill': bool(s.get('backfill', False)),
                'rollback': bool(s.get('rollback', False)),
            }
            if s.get('original_digest'):
                digest_values.append(s['original_digest'])
                base['original_digest'] = s['original_digest']
            if w is None:
                base['interval'] = None
                base['problem'] = 'unknown_clock_source'
                stamp_reports.append(base)
                continue
            contributor_ids.append(sid)
            cmap = cal_maps[sid]

            then_version = int(s.get('calibration_version') or 1)
            then_cal = cmap.get(then_version)
            then_iv = None
            if then_cal:
                offsets = _resolved_offsets(then_cal, upstreams)
                if offsets:
                    then_iv = claim_interval(claimed, offsets[0], offsets[1])
            base['known_then_version'] = then_version
            base['known_then_interval'] = then_iv
            if then_iv:
                then_intervals.append(then_iv)

            current_version = latest_version[sid]
            current_cal = cmap[current_version]
            cur_offsets = _resolved_offsets(current_cal, upstreams)
            current_iv = claim_interval(claimed, *cur_offsets) if cur_offsets else None
            base['current_version'] = current_version
            base['current_interval'] = current_iv
            if current_iv:
                current_intervals.append(current_iv)

            if sid in version_map:
                primary_version = int(version_map[sid])
            elif basis == 'known_then':
                primary_version = then_version
            else:
                primary_version = current_version
            primary_cal = cmap.get(primary_version)
            primary_iv = None
            if primary_cal:
                offsets = _resolved_offsets(primary_cal, upstreams)
                if offsets:
                    primary_iv = claim_interval(claimed, offsets[0], offsets[1])
                    used_clock_records.append({
                        'source': sid,
                        'witness_seq': w['witness_seq'],
                        'signing_chain': w['signing_chain'],
                        'kind': w['kind'],
                        'operator': w['operator'],
                        'upstream_group': w['upstream_group'],
                        'absolute': bool(primary_cal.get('absolute', True)),
                        'version': int(primary_version),
                        'offset_min': primary_cal['offset_min'],
                        'offset_max': primary_cal['offset_max'],
                        'calibration_start': primary_cal.get('calibration_start'),
                        'calibration_end': primary_cal.get('calibration_end'),
                        'resolved_offset_min': offsets[0],
                        'resolved_offset_max': offsets[1],
                    })
            base['calibration_version'] = primary_version
            base['interval'] = primary_iv
            if primary_iv:
                primary_intervals.append(primary_iv)
            else:
                base['problem'] = base.get('problem') or 'uncalibrated_absolute_error'
            stamp_reports.append(base)

        primary_iv = combine_intervals(primary_intervals)
        then_iv = combine_intervals(then_intervals)
        current_iv = combine_intervals(current_intervals)
        envelope = ([min(iv[0] for iv in primary_intervals),
                     max(iv[1] for iv in primary_intervals)]
                    if primary_intervals else None)
        conflict = interval_conflict(primary_intervals)
        digest_set = sorted(set(digest_values))
        contributor_witnesses = [witnesses[sid] for sid in dict.fromkeys(contributor_ids)
                                 if sid in witnesses]
        independence = independence_report(contributor_witnesses)
        events_report[key] = {
            'event_key': key,
            'seq': seq_map.get(key),
            'stamp_count': len(key_stamps),
            'interval': primary_iv,
            'interval_envelope': envelope,
            'known_then_interval': then_iv,
            'current_interval': current_iv,
            'interval_conflict': conflict,
            'consistent': conflict is None,
            'original_digest': digest_set[0] if len(digest_set) == 1 else None,
            'original_digests': digest_set,
            'original_digest_consistent': len(digest_set) <= 1,
            'independence': independence,
            'stamps': stamp_reports,
        }

    propose_key = bundle.get('propose_event_key') or bundle.get('propose_key')
    publish_key = (_pick(bundle, 'publish_event_key', 'publish_key') or
                   bundle.get('event_key'))
    if propose_key is None:
        propose_key = next((k for k in all_keys if 'propos' in str(k) or 'apply' in str(k)),
                           'propose')
    if publish_key is None:
        publish_key = next((k for k in all_keys if 'publish' in str(k)), 'publish')

    propose = events_report.get(propose_key)
    publish = events_report.get(publish_key)

    propose_seq = _as_int(bundle.get('propose_seq'))
    publish_seq = _as_int(bundle.get('publish_seq'))
    if propose is not None and propose.get('seq') is not None and propose_seq is None:
        propose_seq = propose['seq']
    if publish is not None and publish.get('seq') is not None and publish_seq is None:
        publish_seq = publish['seq']

    if propose_seq is not None and publish_seq is not None:
        if propose_seq < publish_seq:
            seq_relation = 'before'
        elif propose_seq > publish_seq:
            seq_relation = 'after'
        else:
            seq_relation = 'coincident'
    else:
        seq_relation = 'unknown'

    propose_iv = propose['interval'] if propose else None
    publish_iv = publish['interval'] if publish else None
    interval_relation_raw = compare_intervals(propose_iv, publish_iv)
    interval_order = order_labels(interval_relation_raw, 'propose', 'publish')
    seq_order = order_labels(seq_relation, 'propose', 'publish')
    order_proven = seq_relation == 'before'

    verdict = window_verdict(publish_iv, window['start'], window['expires'])
    status = verdict_status(verdict)
    if publish_iv is None:
        status = TIME_UNPROVEN
        verdict = INSUFFICIENT_EVIDENCE

    reasons = []
    if publish is None or publish['stamp_count'] == 0:
        reasons.append('no_time_stamps')
    elif publish_iv is None:
        reasons.append('no_bounded_absolute_interval')
        if publish.get('interval_conflict'):
            reasons.append('witness_interval_conflict')
    elif verdict == INSUFFICIENT_EVIDENCE:
        if window['expires'] is not None and publish_iv[0] < window['expires'] <= publish_iv[1]:
            reasons.append('interval_crosses_close')
        if window['start'] is not None and (publish_iv[0] < window['start'] <= publish_iv[1]):
            reasons.append('interval_crosses_start')
    if publish and not publish['independence']['fully_independent']:
        if publish['independence']['same_operator']:
            reasons.append('same_operator_witnesses_correlated')
        if publish['independence']['shared_upstream']:
            reasons.append('shared_upstream_correlation')

    registry_independence = independence_report(list(witnesses.values()))
    clock_version = _clock_version(used_clock_records) if used_clock_records else None

    return {
        'release': release,
        'window': window,
        'basis': basis if not version_map else 'pinned_versions',
        'version_map': dict(sorted(version_map.items())) or None,
        'clock_version': clock_version,
        'seq_order': seq_order,
        'seq_relation': seq_relation,
        'interval_order': interval_order,
        'interval_relation': interval_relation_raw,
        'order_proven': order_proven,
        'propose_seq': propose_seq,
        'publish_seq': publish_seq,
        'propose': propose,
        'publish': {
            'event_key': publish_key,
            'seq': publish_seq,
            'interval': publish_iv,
            'interval_envelope': publish.get('interval_envelope') if publish else None,
            'known_then_interval': publish['known_then_interval'] if publish else None,
            'current_interval': publish['current_interval'] if publish else None,
            'window_verdict': verdict,
            'verdict': verdict,
            'status': status,
            'production_window_met': {
                PROVABLY_WITHIN: True,
                PROVABLY_OUTSIDE: False,
                INSUFFICIENT_EVIDENCE: None,
            }[verdict],
            'independence': publish['independence'] if publish else independence_report([]),
            'reasons': reasons,
        },
        'events': events_report,
        'independence': publish['independence'] if publish else independence_report([]),
        'registry_independence': registry_independence,
        'conclusion': status,
    }


reconstruct = reconstruct_release
build_release_proof = reconstruct_release
prove_release = reconstruct_release
evaluate_release = reconstruct_release


def review_fixture(path):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    return reconstruct_release(data)


# ---------------------------------------------------------------------------
# Certificate binding verification (pure)
# ---------------------------------------------------------------------------

def verify_certificate_binding(cert, expected=None, recomputed=None):
    """Check a certificate cannot be re-posted for another release/window."""
    expected = expected or {}
    checks = {}

    def check(name, actual, wanted):
        if wanted is None:
            return True
        ok = actual == wanted
        checks[name] = {'ok': ok, 'actual': actual, 'expected': wanted}
        return ok

    ok = True
    ok &= check('image_digest', cert.get('image_digest'),
                _pick(expected, 'digest', 'image_digest'))
    ok &= check('generation', cert.get('generation'), expected.get('generation'))
    ok &= check('propose_seq', cert.get('propose_seq'), expected.get('propose_seq'))
    ok &= check('publish_seq', cert.get('publish_seq'), expected.get('publish_seq'))
    ok &= check('clock_version', cert.get('clock_version'), expected.get('clock_version'))
    ok &= check('window_expires', cert.get('window_expires'),
                _pick(expected, 'expires', 'window_expires'))
    ok &= check('window_start', cert.get('window_start'),
                _pick(expected, 'start', 'window_start'))

    if recomputed is not None:
        pub = recomputed.get('publish') or {}
        ok &= check('recomputed_interval', cert.get('interval_low') is not None and
                    [cert.get('interval_low'), cert.get('interval_high')],
                    pub.get('interval'))
        ok &= check('recomputed_verdict', cert.get('verdict'), pub.get('window_verdict'))
        ok &= check('recomputed_clock_version', cert.get('clock_version'),
                    recomputed.get('clock_version'))

    mismatches = [name for name, detail in checks.items() if not detail['ok']]
    return {'valid': ok, 'checks': checks, 'mismatches': mismatches,
            'reason': 'scope_ok' if ok else 'certificate_scope_mismatch'}


verify_binding = verify_certificate_binding


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _witness_problems(x):
    missing = []
    if not x.get('id'):
        missing.append('id')
    if not _pick(x, 'operator', 'operating_entity', 'entity'):
        missing.append('operator')
    if not _pick(x, 'witness_seq', 'witness_number', 'serial', 'nonce'):
        missing.append('witness_seq')
    if not _as_list(_pick(x, 'signing_chain', 'chain', 'signers')):
        missing.append('signing_chain')
    start = _pick(x, 'calibration_start', 'calibrated_at', 'valid_from')
    end = _pick(x, 'calibration_end', 'valid_until', 'calibrated_until')
    if start is None:
        missing.append('calibration_start')
    if end is None:
        missing.append('calibration_end')
    omin = _pick(x, 'offset_min', 'error_min')
    omax = _pick(x, 'offset_max', 'error_max')
    if omin is None:
        missing.append('offset_min')
    if omax is None:
        missing.append('offset_max')
    if omin is not None and omax is not None and int(omin) > int(omax):
        missing.append('ordered_offset_interval')
    return missing


def _insert_source(db, x, strict):
    sid = x.get('id')
    old = one(db, 'SELECT * FROM clock_sources WHERE id=?', (sid,))
    if old:
        same = (old['operator'] == _pick(x, 'operator', 'operating_entity', 'entity')
                and old['offset_min'] == x.get('offset_min')
                and old['offset_max'] == x.get('offset_max')
                and (old['witness_seq'] or None) ==
                (str(_pick(x, 'witness_seq', 'witness_number', 'serial', 'nonce'))
                 if _pick(x, 'witness_seq', 'witness_number', 'serial', 'nonce') is not None
                 else None))
        return {'decision': 'reused'} if same else {'decision': 'clock_source_conflict'}

    witness_seq = _pick(x, 'witness_seq', 'witness_number', 'serial', 'nonce')
    if witness_seq is not None:
        reused = one(db, 'SELECT id FROM clock_sources WHERE witness_seq=?', (str(witness_seq),))
        if reused:
            return {'decision': 'witness_seq_reused', 'existing_id': reused['id']}

    missing = _witness_problems(x)
    complete = 0 if missing else 1
    if strict and missing:
        return {'decision': 'incomplete_clock_original', 'missing': missing}

    kind = _pick(x, 'kind', 'source_kind', 'type') or ('node' if strict else 'unspecified')
    chain = _as_list(_pick(x, 'signing_chain', 'chain', 'signers'))
    db.execute(
        """INSERT INTO clock_sources
           (id,operator,offset_min,offset_max,status,kind,signing_chain,
            calibration_start,calibration_end,witness_seq,upstream_group,absolute,
            registered_at,clock_version,complete)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
        (sid, _pick(x, 'operator', 'operating_entity', 'entity'),
         x.get('offset_min'), x.get('offset_max'), 'active', kind,
         json.dumps(chain, ensure_ascii=False) if chain else None,
         _pick(x, 'calibration_start', 'calibrated_at', 'valid_from'),
         _pick(x, 'calibration_end', 'valid_until', 'calibrated_until'),
         str(witness_seq) if witness_seq is not None else None,
         _pick(x, 'upstream_group', 'shared_upstream', 'upstream', 'upstream_source'),
         1 if x.get('absolute', True) else 0,
         x.get('registered_at'), complete))
    # Every registered original opens calibration version 1 in the
    # append-only calibration ledger; later corrections are added, never
    # overwritten.
    db.execute(
        """INSERT INTO clock_calibrations
           (id,source,version,offset_min,offset_max,calibration_start,calibration_end,
            absolute,upstream_group,reason,recorded_at,supersedes)
           VALUES(?,?,1,?,?,?,?,?,?,?,?,NULL)""",
        (f'cal-{sid}-v1', sid, x.get('offset_min'), x.get('offset_max'),
         _pick(x, 'calibration_start', 'calibrated_at', 'valid_from'),
         _pick(x, 'calibration_end', 'valid_until', 'calibrated_until'),
         1 if x.get('absolute', True) else 0,
         _pick(x, 'upstream_group', 'shared_upstream', 'upstream', 'upstream_source'),
         'initial_registration', x.get('registered_at')))
    return {'decision': 'witness_recorded' if strict else 'clock_recorded',
            'complete': complete}


def _next_event_seq(db):
    row = one(db, 'SELECT COALESCE(MAX(seq),0)+1 AS next_seq FROM events')
    return row['next_seq'] if row else 1


def _stamp(db, x, rich=False):
    sid = _pick(x, 'source', 'source_id', 'witness')
    source = one(db, 'SELECT * FROM clock_sources WHERE id=?', (sid,))
    if not source or source['status'] != 'active':
        return {'decision': 'clock_unavailable'}

    stamp_id = x.get('id')
    if stamp_id and one(db, 'SELECT id FROM time_stamps WHERE id=?', (stamp_id,)):
        return {'decision': 'stamp_id_conflict'}

    latest = one(db, 'SELECT MAX(version) AS v FROM clock_calibrations WHERE source=?', (sid,))
    cal_version = x.get('calibration_version')
    if cal_version is None:
        cal_version = latest['v'] if latest and latest['v'] else source['clock_version'] or 1
    cal_version = int(cal_version)

    backfill = bool(x.get('backfill') or x.get('offline') or x.get('late_report'))
    rollback = 0
    reason = None
    anomaly_id = None

    if not backfill:
        prev = one(db,
                   'SELECT * FROM time_stamps WHERE source=? AND backfill=0 '
                   'ORDER BY rowid DESC LIMIT 1', (sid,))
        if prev:
            new_claimed = x.get('claimed_utc')
            new_local = x.get('local_at')
            backwards_utc = (new_claimed is not None and prev['claimed_utc'] is not None
                             and int(new_claimed) < int(prev['claimed_utc']))
            backwards_local = (new_local is not None and prev['local_at'] is not None
                               and int(new_local) < int(prev['local_at']))
            if backwards_utc or backwards_local:
                rollback = 1
                reason = ('claimed_utc_went_backwards' if backwards_utc
                           else 'local_reading_went_backwards')
                anomaly_id = f"anom-{stamp_id}"
                db.execute(
                    'INSERT INTO clock_anomalies(id,source,kind,stamp,detail,recorded_seq) '
                    'VALUES(?,?,?,?,?,?)',
                    (anomaly_id, sid, 'clock_rollback', stamp_id, reason, _next_event_seq(db)))

    db.execute(
        """INSERT INTO time_stamps
           (id,event_key,source,local_at,claimed_utc,original_digest,
            calibration_version,backfill,received_at,rollback,rollback_reason)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (stamp_id, x.get('event_key'), sid, x.get('local_at'), x.get('claimed_utc'),
         x.get('original_digest'), cal_version, 1 if backfill else 0,
         x.get('received_at'), rollback, reason))

    if rich:
        return {'decision': 'stamp_recorded', 'id': stamp_id,
                'calibration_version': cal_version,
                'backfill': backfill, 'rollback_detected': bool(rollback),
                'rollback_reason': reason, 'anomaly_id': anomaly_id}
    result = {'decision': 'stamp_recorded'}
    if rollback:
        result.update({'rollback_detected': True, 'rollback_reason': reason,
                       'anomaly_id': anomaly_id})
    return result


def _add_calibration(db, x):
    sid = _pick(x, 'source', 'source_id', 'witness')
    source = one(db, 'SELECT id FROM clock_sources WHERE id=?', (sid,))
    if not source:
        return {'decision': 'clock_unavailable'}
    missing = [k for k in ('offset_min', 'offset_max') if x.get(k) is None]
    if missing:
        return {'decision': 'incomplete_calibration', 'missing': missing}

    latest = one(db, 'SELECT MAX(version) AS v FROM clock_calibrations WHERE source=?', (sid,))
    version = int(x.get('version') or ((latest['v'] or 0) + 1))
    if one(db, 'SELECT 1 FROM clock_calibrations WHERE source=? AND version=?', (sid, version)):
        return {'decision': 'calibration_version_exists'}
    cid = x.get('id') or f'cal-{sid}-v{version}'
    if one(db, 'SELECT id FROM clock_calibrations WHERE id=?', (cid,)):
        return {'decision': 'calibration_id_conflict'}
    prior = latest['v']
    db.execute(
        """INSERT INTO clock_calibrations
           (id,source,version,offset_min,offset_max,calibration_start,calibration_end,
            absolute,upstream_group,reason,recorded_at,supersedes)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cid, sid, version, x.get('offset_min'), x.get('offset_max'),
         _pick(x, 'calibration_start', 'calibrated_at', 'valid_from'),
         _pick(x, 'calibration_end', 'valid_until'),
         1 if x.get('absolute', True) else 0,
         _pick(x, 'upstream_group', 'upstream'),
         x.get('reason'), x.get('recorded_at'), prior))
    return {'decision': 'calibration_recorded', 'source': sid, 'version': version,
            'supersedes': prior}


def _source_to_bundle(row):
    d = dict(row)
    d['signing_chain'] = json.loads(d['signing_chain']) if d.get('signing_chain') else []
    d['absolute'] = bool(d.get('absolute', 1))
    return d


def _db_bundle(db, x):
    source_rows = rows(db, 'SELECT * FROM clock_sources ORDER BY id')
    witnesses = [_source_to_bundle(r) for r in source_rows if r['kind'] != 'upstream']
    upstreams = [_source_to_bundle(r) for r in source_rows if r['kind'] == 'upstream']
    calibrations = [dict(r) for r in rows(db, 'SELECT * FROM clock_calibrations ORDER BY source,version')]
    stamps = [dict(r) for r in rows(db, 'SELECT * FROM time_stamps ORDER BY rowid')]

    window = x.get('window') if isinstance(x.get('window'), dict) else None
    if window is None and (x.get('window_start') is not None or x.get('window_expires') is not None):
        window = {'start': x.get('window_start'), 'expires': x.get('window_expires'),
                  'generation': x.get('window_generation')}
    environment = x.get('environment') or (window or {}).get('environment')
    if window is None and environment:
        wrow = one(db, 'SELECT * FROM channel_windows WHERE environment=?', (environment,))
        if wrow:
            window = {'start': wrow['start'], 'expires': wrow['expires'],
                      'generation': wrow['generation'], 'environment': environment}

    propose_seq = x.get('propose_seq')
    publish_seq = x.get('publish_seq')
    return {
        'witnesses': witnesses,
        'upstreams': upstreams,
        'calibrations': calibrations,
        'stamps': stamps,
        'window': window or {},
        'digest': _pick(x, 'digest', 'image_digest'),
        'generation': x.get('generation'),
        'release_ref': x.get('release_ref') or x.get('id'),
        'propose_event_key': x.get('propose_event_key'),
        'publish_event_key': x.get('publish_event_key') or x.get('event_key'),
        'propose_seq': propose_seq,
        'publish_seq': publish_seq,
        'basis': x.get('basis', 'current'),
        'version_map': x.get('version_map'),
    }


def _event_binding(db, x):
    propose_seq = x.get('propose_seq')
    publish_seq = x.get('publish_seq')
    if propose_seq is None or publish_seq is None:
        return {'error': 'event_seq_required'}
    prow = one(db, 'SELECT seq,subsystem,payload FROM events WHERE seq=?', (propose_seq,))
    urow = one(db, 'SELECT seq,subsystem,payload FROM events WHERE seq=?', (publish_seq,))
    if not prow or not urow:
        return {'error': 'event_seq_not_found',
                'missing': [s for s, r in (('propose_seq', prow), ('publish_seq', urow)) if not r]}

    propose_digest = digest_text(prow['payload'])
    publish_digest = digest_text(urow['payload'])
    events_digest = digest_payload({
        'propose_event_digest': propose_digest,
        'publish_event_digest': publish_digest,
    })
    binding = {
        'propose_seq': propose_seq,
        'publish_seq': publish_seq,
        'propose_subsystem': prow['subsystem'],
        'publish_subsystem': urow['subsystem'],
        'propose_event_digest': propose_digest,
        'publish_event_digest': publish_digest,
        'events_digest': events_digest,
    }

    # Cross-check the release identity against the recorded channel commands.
    wanted_digest = _pick(x, 'digest', 'image_digest')
    checks = {}
    try:
        p_payload = json.loads(prow['payload'])
        u_payload = json.loads(urow['payload'])
    except (TypeError, ValueError):
        p_payload, u_payload = {}, {}

    if wanted_digest and p_payload.get('digest'):
        checks['propose_digest'] = p_payload['digest'] == wanted_digest
        if not checks['propose_digest']:
            binding['error'] = 'release_binding_mismatch'
    promotion_id = u_payload.get('id') if isinstance(u_payload, dict) else None
    if promotion_id and urow['subsystem'] == 'channel':
        promo = one(db, 'SELECT * FROM promotions WHERE id=?', (promotion_id,))
        if promo:
            binding['promotion_generation'] = promo['generation']
            binding['promotion_digest'] = promo['digest']
            if wanted_digest and promo['digest'] != wanted_digest:
                checks['promotion_digest'] = False
                binding['error'] = 'release_binding_mismatch'
            if x.get('generation') is not None and int(x['generation']) != int(promo['generation']):
                checks['generation'] = False
                binding['error'] = 'release_binding_mismatch'
    binding['checks'] = checks
    return binding


def _pinned_versions(db):
    return {r['source']: r['v'] for r in
            rows(db, 'SELECT source, MAX(version) AS v FROM clock_calibrations GROUP BY source')}


def _cert_row(db, cert_id):
    row = one(db, 'SELECT * FROM time_certificates WHERE id=?', (cert_id,))
    if not row:
        return None
    row = dict(row)
    if row.get('report'):
        row['report_json'] = row['report']
        row['report'] = json.loads(row['report'])
    if row.get('independence'):
        row['independence'] = json.loads(row['independence'])
    return row


def _issue_order_certificate(db, x):
    cert_id = x.get('id')
    if not cert_id:
        return {'decision': 'certificate_id_required'}
    existing = one(db, 'SELECT * FROM time_certificates WHERE id=?', (cert_id,))
    if existing:
        same = (existing['scope'] == 'order_only'
                and existing['propose_seq'] == x.get('propose_seq')
                and existing['publish_seq'] == x.get('publish_seq')
                and existing['image_digest'] == _pick(x, 'digest', 'image_digest'))
        return {'decision': 'reused'} if same else {'decision': 'certificate_id_conflict'}

    binding = _event_binding(db, x)
    if binding.get('error'):
        return {'decision': binding['error']}
    if int(x['publish_seq']) <= int(x['propose_seq']):
        return {'decision': 'order_not_proven',
                'seq_order': 'publish_not_after_propose'}

    digest = _pick(x, 'digest', 'image_digest')
    generation = x.get('generation')
    db.execute(
        """INSERT INTO time_certificates
           (id,event_key,certified_utc,status,scope,image_digest,generation,release_ref,
            propose_seq,publish_seq,propose_event_key,publish_event_key,
            propose_event_digest,publish_event_digest,events_digest,clock_version,
            verdict,report,issued_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cert_id, x.get('event_key'), None, ORDER_PROVEN, 'order_only', digest, generation,
         x.get('release_ref'), x['propose_seq'], x['publish_seq'],
         x.get('propose_event_key'), x.get('publish_event_key') or x.get('event_key'),
         binding['propose_event_digest'], binding['publish_event_digest'],
         binding['events_digest'], SEQ_ONLY_CLOCK_VERSION, ORDER_PROVEN,
         json.dumps({'scope': 'order_only', 'order_proven': True,
                     'window_claim': 'not_evaluated',
                     'production_window_met': None}, sort_keys=True),
         x.get('issued_at')))
    return {
        'decision': ORDER_PROVEN,
        'certificate_id': cert_id,
        'scope': 'order_only',
        'status': ORDER_PROVEN,
        'order_proven': True,
        'seq_order': 'propose_before_publish',
        'propose_seq': x['propose_seq'],
        'publish_seq': x['publish_seq'],
        'propose_event_digest': binding['propose_event_digest'],
        'publish_event_digest': binding['publish_event_digest'],
        'events_digest': binding['events_digest'],
        'clock_version': SEQ_ONLY_CLOCK_VERSION,
        'absolute_time_certified': False,
        'production_window_met': None,
        'window_claim': 'not_evaluated',
        'claims': ['local_commit_order_only'],
        'does_not_claim': ['absolute_utc', 'production_window_compliance'],
    }


def _issue_release_certificate(db, x):
    cert_id = x.get('id')
    if not cert_id:
        return {'decision': 'certificate_id_required'}
    existing = one(db, 'SELECT * FROM time_certificates WHERE id=?', (cert_id,))
    if existing:
        same = (existing['scope'] == 'release_interval'
                and existing['image_digest'] == _pick(x, 'digest', 'image_digest')
                and existing['generation'] == x.get('generation'))
        return {'decision': 'reused'} if same else {'decision': 'certificate_id_conflict'}

    binding = _event_binding(db, x)
    if binding.get('error'):
        return {'decision': binding['error']}

    bundle = _db_bundle(db, x)
    # Pin the concrete calibration versions available at issuance so the
    # certificate stays reproducible after late calibration arrives.
    if not bundle['version_map']:
        bundle['version_map'] = _pinned_versions(db)
    report = reconstruct_release(bundle)

    publish_report = report.get('publish') or {}
    if not report.get('events') or publish_report.get('event_key') not in report['events'] \
            or report['events'][publish_report['event_key']]['stamp_count'] == 0:
        return {'decision': 'unstamped'}

    # Time originals must commit to the same event original text as the seq.
    publish_event = report['events'][publish_report['event_key']]
    expected_event_digest = binding['publish_event_digest']
    for stamp in publish_event['stamps']:
        sd = stamp.get('original_digest')
        if sd and sd != expected_event_digest:
            return {'decision': 'event_original_mismatch',
                    'stamp_id': stamp.get('stamp_id')}
    if not publish_event['original_digest_consistent']:
        return {'decision': 'event_original_conflict'}

    min_groups = x.get('min_independent_groups')
    if min_groups is None and x.get('require_independent'):
        min_groups = 2
    independence = publish_report['independence']
    if min_groups is not None and independence['independence_groups'] < int(min_groups):
        return {'decision': 'independence_not_established',
                'independence': independence,
                'required_independent_groups': int(min_groups)}

    interval = publish_report['interval']
    verdict = publish_report['window_verdict']
    status = publish_report['status']
    window = report['window']
    clock_version = report['clock_version']

    db.execute(
        """INSERT INTO time_certificates
           (id,event_key,certified_utc,status,scope,image_digest,generation,release_ref,
            propose_seq,publish_seq,propose_event_key,publish_event_key,
            propose_event_digest,publish_event_digest,events_digest,clock_version,
            interval_low,interval_high,verdict,independence,report,
            window_start,window_expires,window_generation,issued_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (cert_id, publish_report['event_key'], None, status, 'release_interval',
         _pick(x, 'digest', 'image_digest'), x.get('generation'), x.get('release_ref'),
         x['propose_seq'], x['publish_seq'], x.get('propose_event_key'),
         publish_report['event_key'], binding['propose_event_digest'],
         binding['publish_event_digest'], binding['events_digest'], clock_version,
         interval[0] if interval else None, interval[1] if interval else None,
         verdict, json.dumps(independence, sort_keys=True, ensure_ascii=False),
         json.dumps(report, sort_keys=True, ensure_ascii=False),
         window.get('start'), window.get('expires'), window.get('generation'),
         x.get('issued_at')))

    return {
        'decision': status,
        'certificate_id': cert_id,
        'scope': 'release_interval',
        'status': status,
        'conclusion': status,
        'classification': verdict,
        'verdict': verdict,
        'window_verdict': verdict,
        'production_window_met': publish_report['production_window_met'],
        'interval': interval,
        'publish_interval': interval,
        'known_then_interval': publish_report.get('known_then_interval'),
        'current_interval': publish_report.get('current_interval'),
        'seq_order': report['seq_order'],
        'interval_order': report['interval_order'],
        'order_proven': report['order_proven'],
        'clock_version': clock_version,
        'events_digest': binding['events_digest'],
        'propose_event_digest': binding['propose_event_digest'],
        'publish_event_digest': binding['publish_event_digest'],
        'independence': independence,
        'reasons': publish_report['reasons'],
        'report': report,
    }


def _correct_certificate(db, x):
    cert_id = x.get('certificate_id') or x.get('certificate')
    cert = one(db, 'SELECT * FROM time_certificates WHERE id=?', (cert_id,))
    if not cert:
        return {'decision': 'certificate_not_found'}
    cid = x.get('id') or f"corr-{cert_id}-{_next_revision(db, cert_id) + 1}"
    if one(db, 'SELECT id FROM time_certificate_corrections WHERE id=?', (cid,)):
        return {'decision': 'correction_id_conflict'}

    revision = _next_revision(db, cert_id) + 1
    reason = x.get('reason')
    verdict = x.get('verdict')
    interval_low = interval_high = None
    clock_version = cert['clock_version']
    report = None

    if x.get('recompute', True):
        seed = _cert_review_request(cert)
        seed['basis'] = 'current'
        seed['version_map'] = _pinned_versions(db)  # includes late calibrations
        report = reconstruct_release(_db_bundle(db, seed))
        pub = report['publish']
        verdict = pub['window_verdict']
        status = pub['status']
        iv = pub['interval']
        if iv:
            interval_low, interval_high = iv
        clock_version = report['clock_version']
        conclusion = status
    else:
        conclusion = verdict or 'certificate_corrected'

    db.execute(
        """INSERT INTO time_certificate_corrections
           (id,certificate_id,revision,kind,reason,recorded_at,clock_version,
            verdict,interval_low,interval_high,report)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
        (cid, cert_id, revision, x.get('kind') or 'calibration_revision', reason,
         x.get('recorded_at'), clock_version, verdict or conclusion,
         interval_low, interval_high,
         json.dumps(report, sort_keys=True, ensure_ascii=False) if report is not None
         else json.dumps({'note': x.get('note')}, sort_keys=True)))

    return {'decision': 'certificate_corrected', 'correction_id': cid,
            'certificate_id': cert_id, 'revision': revision,
            'verdict': verdict or conclusion, 'status': conclusion,
            'interval': [interval_low, interval_high] if interval_low is not None else None,
            'clock_version': clock_version}


def _next_revision(db, cert_id):
    row = one(db,
              'SELECT COALESCE(MAX(revision),0) AS r FROM time_certificate_corrections '
              'WHERE certificate_id=?', (cert_id,))
    return row['r'] if row else 0


def _cert_review_request(cert):
    return {
        'digest': cert['image_digest'],
        'generation': cert['generation'],
        'propose_seq': cert['propose_seq'],
        'publish_seq': cert['publish_seq'],
        'propose_event_key': cert['propose_event_key'],
        'publish_event_key': cert['publish_event_key'] or cert['event_key'],
        'event_key': cert['event_key'],
        'window_start': cert['window_start'],
        'window_expires': cert['window_expires'],
        'window_generation': cert['window_generation'],
    }


def _verify_certificate(db, x):
    cert = _cert_row(db, x.get('id') or x.get('certificate_id'))
    if not cert:
        return {'decision': 'certificate_not_found', 'valid': False}

    recomputed = None
    if cert['scope'] == 'release_interval' and cert['propose_seq'] is not None:
        seed = _cert_review_request(cert)
        stored_report = cert.get('report') or {}
        if stored_report.get('version_map'):
            seed['version_map'] = stored_report['version_map']
        bundle = _db_bundle(db, seed)
        if stored_report.get('version_map'):
            bundle['version_map'] = stored_report['version_map']
        recomputed = reconstruct_release(bundle)

    expected = {k: v for k, v in x.items() if k not in ('op', 'id', 'certificate_id')}
    result = verify_certificate_binding(cert, expected, recomputed)

    corrections = rows(db,
                       'SELECT id,revision,verdict,clock_version,interval_low,interval_high '
                       'FROM time_certificate_corrections WHERE certificate_id=? ORDER BY revision',
                       (cert['id'],))
    result.update({
        'decision': 'certificate_verified' if result['valid'] else 'certificate_scope_mismatch',
        'certificate_id': cert['id'],
        'scope': cert['scope'],
        'status': cert['status'],
        'stored_verdict': cert['verdict'],
        'corrections': [dict(c) for c in corrections],
        'correction_count': len(corrections),
        'original_preserved': True,
    })
    return result


def _disclosure_package(db, x):
    """Two audit-protocol deliverables for the same release.

    ``audience='customer'`` returns the narrowed order proof without clock
    originals; ``audience='confidential_review'`` returns every clock original,
    calibration and correction needed to recompute the absolute interval.
    """
    cert = _cert_row(db, x.get('id') or x.get('certificate_id'))
    if not cert:
        return {'decision': 'certificate_not_found'}
    audience = x.get('audience', 'customer')
    corrections = rows(db,
                       'SELECT id,revision,kind,reason,verdict,clock_version,'
                       'interval_low,interval_high,recorded_at '
                       'FROM time_certificate_corrections WHERE certificate_id=? '
                       'ORDER BY revision', (cert['id'],))
    package = {
        'certificate_id': cert['id'],
        'audience': 'confidential_review' if audience in
                    ('confidential_review', 'reviewer', 'court') else 'customer',
        'scope': cert['scope'],
        'status': cert['status'],
        'image_digest': cert['image_digest'],
        'generation': cert['generation'],
        'release_ref': cert['release_ref'],
        'propose_seq': cert['propose_seq'],
        'publish_seq': cert['publish_seq'],
        'events_digest': cert['events_digest'],
        'correction_count': len(corrections),
    }

    if cert['scope'] == 'order_only':
        package.update({
            'decision': 'order_only_package',
            'order_proven': True,
            'seq_order': 'propose_before_publish',
            'absolute_time_certified': False,
            'production_window_met': None,
            'window_claim': 'not_evaluated',
            'claims': ['local_commit_order_only'],
            'does_not_claim': ['absolute_utc', 'production_window_compliance'],
        })
    else:
        package.update({
            'decision': 'interval_package',
            'verdict': cert['verdict'],
            'window_verdict': cert['verdict'],
            'interval': [cert['interval_low'], cert['interval_high']]
            if cert['interval_low'] is not None else None,
            'window': {'start': cert['window_start'], 'expires': cert['window_expires'],
                       'generation': cert['window_generation']},
            'clock_version': cert['clock_version'],
            'production_window_met': {
                PROVABLY_WITHIN: True,
                PROVABLY_OUTSIDE: False,
                INSUFFICIENT_EVIDENCE: None,
            }.get(cert['verdict']),
        })

    if package['audience'] == 'confidential_review':
        package['decision'] = 'confidential_package'
        package['originals_disclosed'] = True
        package['witnesses'] = [_source_to_bundle(r) for r in
                               rows(db, 'SELECT * FROM clock_sources ORDER BY id')]
        package['calibrations'] = [dict(r) for r in
                                   rows(db, 'SELECT * FROM clock_calibrations ORDER BY source,version')]
        package['stamps'] = [dict(r) for r in
                             rows(db, 'SELECT * FROM time_stamps ORDER BY rowid')]
        package['corrections'] = [dict(c) for c in corrections]
        package['report'] = cert.get('report')
    else:
        package['originals_disclosed'] = False
        package['witnesses'] = []
        package['corrections'] = [{'revision': c['revision'], 'kind': c['kind']}
                                 for c in corrections]
    return package


def _review_release(db, x):
    binding = None
    if x.get('propose_seq') is not None and x.get('publish_seq') is not None:
        binding = _event_binding(db, x)
        if binding.get('error'):
            return {'decision': binding['error']}
    report = reconstruct_release(_db_bundle(db, x))
    if binding:
        report['binding'] = binding
    report['decision'] = 'release_reviewed'
    return report


# ---------------------------------------------------------------------------
# Operation entry point
# ---------------------------------------------------------------------------

def run(db, x):
    op = x.get('op')

    # A raw reviewer bundle (e.g. the cross-clock JSON fixture) has no op:
    # recompute it purely from originals without writing state.
    if op is None:
        if any(k in x for k in ('witnesses', 'stamps', 'clock_sources', 'time_stamps')):
            report = reconstruct_release(x)
            report['decision'] = 'release_reviewed'
            return report
        raise ValueError('timeproof payload requires an op or a reviewer bundle')

    # --- Clock originals ---------------------------------------------------
    if op in ('source', 'clock_source', 'register_source', 'clock',
              'clock_original', 'register_clock'):
        result = _insert_source(db, x, strict=bool(x.get('strict')))
        # Legacy success contract is exactly {'decision': 'clock_recorded'}.
        if result.get('decision') in ('clock_recorded', 'witness_recorded'):
            return {'decision': 'clock_recorded'}
        return result
    if op in ('witness', 'register_witness', 'clock_witness'):
        return _insert_source(db, x, strict=True)
    if op in ('upstream', 'upstream_source'):
        x = dict(x)
        x.setdefault('kind', 'upstream')
        return _insert_source(db, x, strict=False)
    if op in ('calibrate', 'add_calibration', 'calibration_correction'):
        return _add_calibration(db, x)

    # --- Time stamps -------------------------------------------------------
    if op in ('stamp', 'time_stamp', 'timestamp'):
        return _stamp(db, x, rich=False)
    if op in ('witness_stamp', 'evidence', 'stamp_rich'):
        return _stamp(db, x, rich=True)

    # --- Certificates ------------------------------------------------------
    if op in ('order_certificate', 'limited_certificate', 'narrow_certificate',
              'order_only_certificate', 'order_proof', 'limited_cert'):
        return _issue_order_certificate(db, x)
    if op in ('release_certificate', 'formal_certificate', 'interval_certificate',
              'certify_release', 'time_certificate', 'release_time_certificate',
              'release_time_proof', 'formal_cert'):
        return _issue_release_certificate(db, x)
    if op in ('correct_certificate', 'append_correction', 'certificate_correction',
              'correction'):
        return _correct_certificate(db, x)
    if op in ('verify_certificate', 'verify'):
        return _verify_certificate(db, x)
    if op in ('disclosure_package', 'audit_package', 'package'):
        return _disclosure_package(db, x)
    if op in ('review_release', 'reconstruct_release', 'release_proof', 'review',
              'reconstruct', 'prove_release', 'evaluate_release'):
        return _review_release(db, x)

    if op == 'certificate':
        scope = str(x.get('scope') or '').strip().lower()
        if scope in ('order', 'order_only', 'limited', 'narrow') or 'order' in scope:
            return _issue_order_certificate(db, x)
        if scope in ('correct', 'correction'):
            return _correct_certificate(db, x)
        if scope in ('release', 'interval', 'formal', 'release_interval',
                     'time', 'window', 'absolute') or any(
                token in scope for token in ('release', 'interval', 'formal', 'window')):
            return _issue_release_certificate(db, x)

        # Legacy provisional path: earliest claimed_utc only. Kept for the
        # original 14-test slice; it is intentionally NOT a window proof.
        stamps = rows(db, 'SELECT claimed_utc FROM time_stamps WHERE event_key=? '
                          'ORDER BY claimed_utc', (x['event_key'],))
        if not stamps:
            return {'decision': 'unstamped'}
        existing = one(db, 'SELECT id FROM time_certificates WHERE id=?', (x['id'],))
        if existing:
            return {'decision': 'certificate_id_conflict'}
        db.execute(
            'INSERT INTO time_certificates(id,event_key,certified_utc,status,scope) '
            'VALUES(?,?,?,?,?)',
            (x['id'], x['event_key'], stamps[0]['claimed_utc'], 'provisional', 'provisional'))
        return {'decision': 'provisional_time', 'at': stamps[0]['claimed_utc']}

    raise ValueError(op)


if __name__ == '__main__':  # independent reviewer entry point
    import sys

    if len(sys.argv) != 2:
        print('usage: python -m imagecourt.timeproof <originals-bundle.json>', file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(review_fixture(sys.argv[1]), ensure_ascii=False, indent=2, sort_keys=True))
