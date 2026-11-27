from .store import one, rows
from .structure import review_element


def rack_load_ok(db, zone, mass, element_id=None):
    """New racks are checked against the shared load path, never against a
    per-rack copy of the zone's total allowance."""
    if element_id:
        el = one(db, 'SELECT * FROM structural_elements WHERE id=? AND zone=?', (element_id, zone['id']))
        if not el:
            return False, 'element_missing'
        review = review_element(db, el)
        if review['occupied'] + mass > review['effective_limit']:
            return False, 'element_overloaded'
        return True, el
    # Legacy zones without registered elements keep the original zone limit.
    if mass > zone['load_limit']:
        return False, 'element_overloaded'
    return True, None


def run(db, x):
    op = x['op']
    if op == 'rack':
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['zone'],))
        if not zone or zone['status'] not in ('open',):
            return {'decision': 'rack_denied'}
        ok, reason = rack_load_ok(db, zone, x['mass'], x.get('element'))
        if not ok:
            return {'decision': 'rack_denied', 'reason': reason}
        db.execute('INSERT INTO site_racks VALUES(?,?,?,?,?)',
                   (x['id'], x['zone'], x['mass'], x['function'], 'installed'))
        if x.get('element'):
            db.execute('INSERT INTO rack_anchors VALUES(?,?,?,?,?,?,?)',
                       (x['anchor'], x['id'], x['element'], x.get('at', 0), None, None, 'in_place'))
        return {'decision': 'rack_installed'}
    if op == 'anchor_check':
        anchor = one(db, 'SELECT * FROM rack_anchors WHERE rack=?', (x['rack'],))
        if not anchor:
            return {'decision': 'anchor_missing'}
        db.execute('UPDATE rack_anchors SET displacement=?, checked_at=?, status=? WHERE rack=?',
                   (x['displacement'], x['at'],
                    'displaced' if x['displacement'] > x['limit'] else 'in_place', x['rack'],))
        return {'decision': 'anchor_measured',
                'status': 'displaced' if x['displacement'] > x['limit'] else 'in_place'}
    if op == 'relocate':
        # A relocation is a physical fact: the rack leaves its old anchors and
        # is re-anchored in an independently accepted zone, then verified by
        # an engineer. Flipping site_racks.status alone never moves mass.
        rack = one(db, 'SELECT * FROM site_racks WHERE id=?', (x['rack'],))
        # A released-but-still-anchored cabinet can still be physically moved;
        # only a cabinet with a recorded relocation is already gone.
        if not rack:
            return {'decision': 'rack_missing'}
        if one(db, 'SELECT 1 FROM rack_relocations WHERE rack=?', (x['rack'],)):
            return {'decision': 'rack_not_in_place'}
        target = one(db, 'SELECT * FROM structural_zones WHERE id=?', (x['to_zone'],))
        if not target or target['status'] not in ('open', 'reentry_open'):
            return {'decision': 'relocation_target_not_accepted'}
        if x['to_zone'] == rack['zone']:
            return {'decision': 'invalid_relocation'}
        ok, reason = rack_load_ok(db, target, rack['mass'], x.get('element'))
        if not ok:
            return {'decision': 'relocation_denied', 'reason': reason}
        db.execute("UPDATE rack_anchors SET status='removed' WHERE rack=? AND status!='removed'",
                   (x['rack'],))
        db.execute('UPDATE site_racks SET zone=? WHERE id=?', (x['to_zone'], x['rack']))
        db.execute('INSERT INTO rack_anchors VALUES(?,?,?,?,?,?,?)',
                   (x['anchor'], x['rack'], x['element'], x['at'], None, None, 'in_place'))
        db.execute('INSERT INTO rack_relocations VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], x['rack'], rack['zone'], x['to_zone'], x['engineer'], x['at'], None, 'pending'))
        return {'decision': 'rack_relocated_pending_verification'}
    if op == 'verify_relocation':
        reloc = one(db, "SELECT * FROM rack_relocations WHERE rack=? AND status='pending'", (x['rack'],))
        if not reloc:
            return {'decision': 'relocation_missing'}
        rack = one(db, 'SELECT * FROM site_racks WHERE id=?', (x['rack'],))
        if not rack or rack['zone'] != reloc['to_zone']:
            return {'decision': 'relocation_unverified'}
        anchor = one(db, "SELECT * FROM rack_anchors WHERE rack=? AND status!='removed'", (x['rack'],))
        anchor_element = one(db, 'SELECT 1 FROM structural_elements WHERE id=? AND zone=?',
                             (anchor['element'], reloc['to_zone'],)) if anchor else None
        if not anchor or not anchor_element:
            return {'decision': 'relocation_unverified'}
        db.execute('UPDATE rack_relocations SET verified_at=?, status=? WHERE id=?',
                   (x['at'], 'verified', reloc['id']))
        db.execute("UPDATE site_racks SET status='installed' WHERE id=?", (x['rack'],))
        return {'decision': 'relocation_verified'}
    if op == 'release':
        # Administrative release does not move the cabinet: mass still bears
        # on the old anchors until an actual relocation or removal is proved.
        rack = one(db, 'SELECT * FROM site_racks WHERE id=?', (x['rack'],))
        if not rack:
            return {'decision': 'rack_missing'}
        if rack['status'] == 'released':
            return {'decision': 'already_released'}
        db.execute("UPDATE site_racks SET status='released' WHERE id=?", (x['rack'],))
        anchor = one(db, "SELECT * FROM rack_anchors WHERE rack=? AND status!='removed'", (x['rack'],))
        return {'decision': 'released_pending_removal',
                'still_anchored': bool(anchor), 'zone': rack['zone']}
    if op == 'mirror_service':
        rack = one(db, 'SELECT * FROM site_racks WHERE id=?', (x['rack'],))
        if not rack:
            return {'decision': 'rack_missing'}
        db.execute('INSERT INTO mirror_services VALUES(?,?,?,?)',
                   (x['id'], x['rack'], x.get('function', rack['function']),
                    'available' if rack['status'] == 'installed' else 'degraded'))
        return {'decision': 'mirror_registered'}
    if op == 'switch_mirror':
        service = one(db, 'SELECT * FROM mirror_services WHERE id=?', (x['service'],))
        if not service:
            return {'decision': 'service_missing'}
        target = one(db, 'SELECT * FROM site_racks WHERE id=?', (x['to_rack'],))
        if not target:
            return {'decision': 'rack_missing'}
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (target['zone'],))
        if zone['status'] not in ('open', 'reentry_open'):
            return {'decision': 'target_zone_restricted'}
        db.execute("UPDATE mirror_services SET status='switched' WHERE id=?", (x['service'],))
        db.execute('INSERT INTO mirror_switchovers VALUES(?,?,?,?,?,?,?)',
                   (x['id'], x['service'], service['rack'], x['to_rack'], x['at'],
                   x.get('check_ref'), 'pending'))
        return {'decision': 'switch_pending_verification'}
    if op == 'verify_switch':
        sw = one(db, "SELECT * FROM mirror_switchovers WHERE id=? AND status='pending'", (x['id'],))
        if not sw:
            return {'decision': 'switch_missing'}
        target = one(db, 'SELECT * FROM site_racks WHERE id=?', (sw['to_rack'],))
        if not target or target['status'] != 'installed':
            return {'decision': 'switch_unverified'}
        db.execute("UPDATE mirror_switchovers SET status='verified', check_ref=? WHERE id=?",
                   (x['check_ref'], x['id']))
        db.execute("UPDATE mirror_services SET rack=?, status='available' WHERE id=?",
                   (sw['to_rack'], sw['service']))
        return {'decision': 'switch_verified', 'rack': sw['to_rack']}
    if op == 'restore_service':
        service = one(db, 'SELECT * FROM mirror_services WHERE id=?', (x['service'],))
        if not service:
            return {'decision': 'service_missing'}
        rack = one(db, 'SELECT * FROM site_racks WHERE id=?', (service['rack'],))
        if not rack or rack['status'] != 'installed':
            return {'decision': 'service_not_restorable'}
        zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (rack['zone'],))
        if zone['status'] not in ('open', 'reentry_open'):
            return {'decision': 'zone_restricted'}
        db.execute("UPDATE mirror_services SET status='available' WHERE id=?", (x['service'],))
        db.execute('INSERT INTO service_restorations VALUES(?,?,?,?,?)',
                   (x['id'], x['service'], rack['id'], x['at'], 'restored'))
        return {'decision': 'service_restored', 'rack': rack['id'], 'zone': rack['zone']}
    if op == 'capability':
        # Customer-facing availability is derived from cabinets that are
        # physically present and in zones people and workloads may enter.
        # A shoring certificate keeps the racks but the zone entry-closed.
        services = rows(db, 'SELECT * FROM mirror_services')
        report = []
        for service in services:
            rack = one(db, 'SELECT * FROM site_racks WHERE id=?', (service['rack'],))
            if not rack:
                state = 'unavailable'
            else:
                zone = one(db, 'SELECT * FROM structural_zones WHERE id=?', (rack['zone'],))
                cert = one(db, "SELECT * FROM reentry_certificates WHERE zone=? AND status='active' "
                               "ORDER BY at DESC, rowid DESC", (rack['zone'],))
                entry_open = zone['status'] in ('open', 'reentry_open') and (not cert or cert['accessible'])
                if rack['status'] != 'installed' or not entry_open:
                    state = 'degraded'
                else:
                    state = 'available'
            report.append({'service': service['id'], 'rack': service['rack'],
                           'zone': rack['zone'] if rack else None, 'state': state})
        return {'decision': 'capability_report',
                'full_capability': bool(report) and all(r['state'] == 'available' for r in report),
                'services': report}
    raise ValueError(op)
