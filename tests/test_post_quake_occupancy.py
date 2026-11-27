import json
import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, replay

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'fixtures'


class PostQuakeCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'post_quake.sqlite'
        self.db = connect(str(self.path))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def step(self, sub, **payload):
        return execute(self.db, sub, payload)

    def load_fixture(self, sub, name):
        data = json.loads((FIXTURES / name).read_text(encoding='utf-8'))
        structure_ops = {'zone', 'element', 'sensor', 'sample', 'inspect', 'crack',
                         'shoring_record', 'assess', 'reentry', 'aftershock', 'notice',
                         'load_review'}
        rack_ops = {'rack', 'anchor_check', 'relocate', 'verify_relocation', 'release',
                    'mirror_service', 'switch_mirror', 'verify_switch', 'restore_service',
                    'capability'}
        results = []
        for item in data:
            if item['op'] in structure_ops:
                target = 'structure'
            elif item['op'] in rack_ops:
                target = 'rack'
            else:
                target = sub
            results.append(execute(self.db, target, item))
        return results

    def test_fixture_sequence_replays_decisions_and_table_state(self):
        # Business time order inside the structure fixture: pre-quake cabinets
        # and mirrors, quake record and crack survey, anchor measurements,
        # then the independent engineer's load ruling.
        self.load_fixture('structure', 'structure_post_quake.json')
        self.load_fixture('rack', 'rack_post_quake.json')
        review = self.step('structure', op='load_review', zone='zone-z')
        self.assertEqual(review['safe_load'], 6)
        self.assertEqual(review['occupied_total'], 9)
        self.assertTrue(review['overloaded'])
        result = replay(str(self.path))
        self.assertTrue(result['verified'], result['errors'])

    def test_aftershock_fixture_is_self_contained_and_replayable(self):
        # The aftershock fixture carries its own zone, element and sensor so it
        # can be replayed on a fresh database; its ruling references the last
        # observed aftershock sequence number.
        self.load_fixture('structure', 'aftershock_sequence.json')
        ruling = self.db.execute(
            "SELECT status FROM structural_zones WHERE id='zone-z'").fetchone()
        self.assertEqual(ruling['status'], 'restricted')
        result = replay(str(self.path))
        self.assertTrue(result['verified'], result['errors'])

    # ---- shared scenario: zone Z, beam B7, R1(5) + R2(9 total), engineer 6 ----
    def seed_quake(self):
        self.assertEqual(self.step('structure', op='zone', id='zone-z', site='site-a',
                                   load_limit=10, revision=1, drawing_revision='dwg-3')['decision'],
                         'zone_recorded')
        self.assertEqual(self.step('structure', op='element', id='beam-b7', zone='zone-z',
                                   kind='beam', shared=True, rated_limit=10)['decision'],
                         'element_recorded')
        self.assertEqual(self.step('structure', op='sensor', id='accel-a', location='zone-z/grid-c3',
                                   calibration='cal-2026-01', uncertainty=0.15)['decision'],
                         'sensor_recorded')
        self.assertEqual(self.step('rack', op='rack', id='r1', zone='zone-z', mass=5,
                                   function='mirror', element='beam-b7', anchor='anchor-r1',
                                   at=10)['decision'], 'rack_installed')
        self.assertEqual(self.step('rack', op='rack', id='r2', zone='zone-z', mass=4,
                                   function='mirror', element='beam-b7', anchor='anchor-r2',
                                   at=11)['decision'], 'rack_installed')
        # Quake record keeps sensor position, calibration, uncertainty and order.
        self.assertEqual(self.step('structure', op='sample', id='main-shock', zone='zone-z',
                                   sensor='accel-a', at=100, acceleration=8)['decision'],
                         'shaking_recorded')
        # Threshold inspection alone restricts the zone but cannot adjudicate load.
        self.assertEqual(self.step('structure', op='inspect', id='peak-only', zone='zone-z',
                                   engineer='engineer-a', at=101, threshold=5)['decision'],
                         'restricted')
        # Field facts: crack survey and per-anchor bolt displacement.
        self.assertEqual(self.step('structure', op='crack', id='crack-1', zone='zone-z',
                                   engineer='engineer-b', at=110, location='beam-b7/midspan',
                                   measurement='width=2.1mm', severity='major')['decision'],
                         'crack_recorded')
        self.assertEqual(self.step('rack', op='anchor_check', rack='r1', displacement=1.2,
                                   limit=2.0, at=115)['decision'], 'anchor_measured')
        self.assertEqual(self.step('rack', op='anchor_check', rack='r2', displacement=3.4,
                                   limit=2.0, at=116)['status'], 'displaced')
        for sid, rid in (('svc-1', 'r1'), ('svc-2', 'r2')):
            self.assertEqual(self.step('rack', op='mirror_service', id=sid, rack=rid)['decision'],
                             'mirror_registered')
        # Assessment rejected while any evidence class is missing would happen
        # before the crack/anchor facts; here the full packet yields safe_load 6.
        result = self.step('structure', op='assess', id='assess-1', zone='zone-z',
                           engineer='engineer-b', at=120, drawing_revision='dwg-3',
                           safe_load=6, basis='crack_width_and_anchor_survey')
        self.assertEqual(result['decision'], 'assessment_recorded')
        self.assertEqual(result['overloaded_elements'], ['beam-b7'])
        return result

    def test_shared_beam_load_path_is_counted_once_and_found_overloaded(self):
        self.seed_quake()
        review = self.step('structure', op='load_review', zone='zone-z')
        self.assertEqual(review['decision'], 'load_review')
        self.assertEqual(review['safe_load'], 6)
        self.assertEqual(review['occupied_total'], 9)
        beam = next(e for e in review['elements'] if e['element'] == 'beam-b7')
        self.assertTrue(beam['shared'])
        # Both racks share one allowance: not 10 per rack, and 9 > 6.
        self.assertEqual(beam['effective_limit'], 6)
        self.assertTrue(beam['overloaded'])
        # New cabinet is barred from the restricted zone regardless of mass.
        denied = self.step('rack', op='rack', id='r3', zone='zone-z', mass=1,
                           function='mirror', element='beam-b7', anchor='anchor-r3', at=130)
        self.assertEqual(denied['decision'], 'rack_denied')

    def test_relocation_strategy_requires_physical_move_switch_and_verification(self):
        self.seed_quake()
        # Accepted independent zone Y with its own slab and headroom.
        self.step('structure', op='zone', id='zone-y', site='site-a', load_limit=12,
                  revision=1, drawing_revision='dwg-4')
        self.step('structure', op='element', id='slab-y2', zone='zone-y', kind='slab',
                  shared=False, rated_limit=12)
        # A database-only status flip does not move mass or free the beam.
        flip = self.step('rack', op='release', rack='r2')
        self.assertEqual(flip['decision'], 'released_pending_removal')
        self.assertTrue(flip['still_anchored'])
        review = self.step('structure', op='load_review', zone='zone-z')
        self.assertEqual(review['occupied_total'], 9)
        # Released-but-present racks cannot be claimed as retained service.
        bad = self.step('structure', op='reentry', id='cert-bad', zone='zone-z',
                        engineer='engineer-b', at=140, strategy='relocation',
                        accessible=True, occupant_limit=2, retained_racks=['r1', 'r2'],
                        removed_racks=[], deload_deadline=200)
        self.assertEqual(bad['decision'], 'rack_not_in_place')
        # Physically relocate R2, re-anchor in Y, then engineer verification.
        self.assertEqual(self.step('rack', op='relocate', id='reloc-r2', rack='r2',
                                   to_zone='zone-y', element='slab-y2', anchor='anchor-r2-y',
                                   engineer='engineer-b', at=150)['decision'],
                         'rack_relocated_pending_verification')
        unverified = self.step('structure', op='reentry', id='cert-pending', zone='zone-z',
                               engineer='engineer-b', at=151, strategy='relocation',
                               accessible=True, occupant_limit=2, retained_racks=['r1'],
                               removed_racks=['r2'], deload_deadline=200)
        self.assertEqual(unverified['decision'], 'relocation_unverified')
        self.assertEqual(self.step('rack', op='verify_relocation', rack='r2', element='slab-y2',
                                   at=155)['decision'], 'relocation_verified')
        # Mirror traffic must switch to the rack that is actually in Y and be checked.
        self.assertEqual(self.step('rack', op='switch_mirror', id='sw-2', service='svc-2',
                                   to_rack='r2', at=160)['decision'], 'switch_pending_verification')
        no_check = self.step('structure', op='reentry', id='cert-noswitch', zone='zone-z',
                             engineer='engineer-b', at=161, strategy='relocation',
                             accessible=True, occupant_limit=2, retained_racks=['r1'],
                             removed_racks=['r2'], deload_deadline=200)
        self.assertEqual(no_check['decision'], 'mirror_switch_unverified')
        self.assertEqual(self.step('rack', op='verify_switch', id='sw-2',
                                   check_ref='migration-check-77')['decision'], 'switch_verified')
        # Beam now carries only R1's 5 units against the engineer's 6.
        review = self.step('structure', op='load_review', zone='zone-z')
        self.assertEqual(review['occupied_total'], 5)
        self.assertFalse(review['overloaded'])
        cert = self.step('structure', op='reentry', id='cert-reloc', zone='zone-z',
                         engineer='engineer-b', at=170, strategy='relocation',
                         accessible=True, occupant_limit=2, retained_racks=['r1'],
                         removed_racks=['r2'], deload_deadline=240)
        self.assertEqual(cert['decision'], 'reentry_certified')
        self.assertEqual(cert['retained_racks'], ['r1'])
        self.assertEqual(cert['removed_racks'], ['r2'])
        self.assertEqual(cert['occupant_limit'], 2)
        # Inventory must be exhaustive: dropping a rack invalidates the proof.
        self.assertEqual(self.step('structure', op='reentry', id='cert-partial', zone='zone-z',
                                   engineer='engineer-b', at=171, strategy='relocation',
                                   accessible=True, occupant_limit=2, retained_racks=['r1'],
                                   removed_racks=[], deload_deadline=240)['decision'],
                         'rack_inventory_mismatch')
        # Customer service restoration is a separate fact, after the move.
        self.assertEqual(self.step('rack', op='restore_service', id='rest-2', service='svc-2',
                                   at=180)['decision'], 'service_restored')
        capability = self.step('rack', op='capability')
        self.assertTrue(capability['full_capability'])
        svc2 = next(s for s in capability['services'] if s['service'] == 'svc-2')
        self.assertEqual(svc2['zone'], 'zone-y')
        self.assertTrue(replay(str(self.path))['verified'])

    def test_shoring_strategy_keeps_both_racks_with_restricted_entry_and_monitoring(self):
        self.seed_quake()
        # Certificate impossible before shoring exists and passes its load test.
        premature = self.step('structure', op='reentry', id='cert-premature', zone='zone-z',
                              engineer='engineer-b', at=130, strategy='shoring',
                              accessible=False, occupant_limit=0,
                              retained_racks=['r1', 'r2'], removed_racks=[],
                              deload_deadline=200, monitoring_cycle=7)
        self.assertEqual(premature['decision'], 'shoring_incomplete')
        # Temporary support designed by independent engineer, completed and
        # load-tested: braced allowance rises above the actual 9 units.
        self.assertEqual(self.step('structure', op='shoring_record', id='shore-1', zone='zone-z',
                                   element='beam-b7', engineer='engineer-b', completed_at=140,
                                   measured_load=10, monitoring_cycle=7)['decision'],
                         'shoring_completed')
        # Shoring strategy forbids open human entry.
        self.assertEqual(self.step('structure', op='reentry', id='cert-open', zone='zone-z',
                                   engineer='engineer-b', at=145, strategy='shoring',
                                   accessible=True, occupant_limit=1,
                                   retained_racks=['r1', 'r2'], removed_racks=[],
                                   deload_deadline=200, monitoring_cycle=7)['decision'],
                         'restricted_entry_violation')
        cert = self.step('structure', op='reentry', id='cert-shore', zone='zone-z',
                         engineer='engineer-b', at=150, strategy='shoring',
                         accessible=False, occupant_limit=0,
                         retained_racks=['r1', 'r2'], removed_racks=[],
                         deload_deadline=200, monitoring_cycle=7)
        self.assertEqual(cert['decision'], 'reentry_certified')
        self.assertEqual(cert['retained_racks'], ['r1', 'r2'])
        self.assertEqual(cert['occupant_limit'], 0)
        review = self.step('structure', op='load_review', zone='zone-z')
        beam = next(e for e in review['elements'] if e['element'] == 'beam-b7')
        self.assertEqual(beam['shoring'], 'shore-1')
        self.assertFalse(beam['overloaded'])
        # Cabinets remain physically on the shared beam; mirror stays in Z but
        # entry-bound, so the site must not advertise ordinary full service.
        capability = self.step('rack', op='capability')
        self.assertFalse(capability['full_capability'])
        self.assertTrue(replay(str(self.path))['verified'])

    def test_aftershock_voids_old_certificate_and_requires_reproof(self):
        self.seed_quake()
        self.step('structure', op='shoring_record', id='shore-1', zone='zone-z',
                  element='beam-b7', engineer='engineer-b', completed_at=140,
                  measured_load=10, monitoring_cycle=7)
        first = self.step('structure', op='reentry', id='cert-1', zone='zone-z',
                          engineer='engineer-b', at=150, strategy='shoring',
                          accessible=False, occupant_limit=0,
                          retained_racks=['r1', 'r2'], removed_racks=[],
                          deload_deadline=200, monitoring_cycle=7)
        self.assertEqual(first['decision'], 'reentry_certified')
        # Aftershock samples keep an explicit sequence; out-of-order is rejected.
        self.assertEqual(self.step('structure', op='sample', id='as1', zone='zone-z',
                                   sensor='accel-a', at=210, acceleration=6,
                                   aftershock_seq=1)['decision'], 'shaking_recorded')
        self.assertEqual(self.step('structure', op='sample', id='as1-dup', zone='zone-z',
                                   sensor='accel-a', at=211, acceleration=5,
                                   aftershock_seq=1)['decision'], 'aftershock_order_violation')
        ruling = self.step('structure', op='aftershock', id='as1-ruling', zone='zone-z',
                           aftershock_seq=1)
        self.assertEqual(ruling['decision'], 'certificates_voided')
        # Old certificate is preserved as void rather than overwritten.
        old = self.db.execute("SELECT status, void_reason FROM reentry_certificates WHERE id='cert-1'").fetchone()
        self.assertEqual(old['status'], 'void')
        self.assertEqual(old['void_reason'], 'aftershock_1')
        # Shoring tested under the old conditions is voided too.
        shore = self.db.execute("SELECT status FROM shoring_works WHERE id='shore-1'").fetchone()
        self.assertEqual(shore['status'], 'voided')
        review = self.step('structure', op='load_review', zone='zone-z')
        self.assertTrue(review['overloaded'])
        # The old proof cannot be re-used; a fresh one needs new evidence and work.
        self.assertEqual(self.step('structure', op='reentry', id='cert-reuse', zone='zone-z',
                                   engineer='engineer-b', at=230, strategy='shoring',
                                   accessible=False, occupant_limit=0,
                                   retained_racks=['r1', 'r2'], removed_racks=[],
                                   deload_deadline=300, monitoring_cycle=7)['decision'],
                         'shoring_incomplete')
        self.assertTrue(replay(str(self.path))['verified'])

    def test_regulator_corrections_append_and_supersede_without_overwriting(self):
        self.seed_quake()
        first = self.step('structure', op='notice', id='notice-1', recipient='regulator',
                          zone='zone-z', engineer='engineer-a', at=105,
                          subject='preliminary-peak-clear',
                          body='single-sensor peak under initial threshold')
        self.assertEqual(first['decision'], 'notice_issued')
        correction = self.step('structure', op='notice', id='notice-2', recipient='regulator',
                               zone='zone-z', engineer='engineer-b', at=125,
                               supersedes='notice-1', subject='post-quake-restriction',
                               body='cracks and anchor displacement reduce safe load to 6')
        self.assertEqual(correction['decision'], 'notice_issued')
        rows = self.db.execute('SELECT id, status FROM structural_notices ORDER BY at').fetchall()
        self.assertEqual([(r['id'], r['status']) for r in rows],
                         [('notice-1', 'superseded'), ('notice-2', 'issued')])
        # A correction citing a nonexistent earlier conclusion is invalid.
        self.assertEqual(self.step('structure', op='notice', id='notice-3', recipient='customer',
                                   zone='zone-z', engineer='engineer-b', at=126,
                                   supersedes='ghost', subject='x', body='y')['decision'],
                         'superseded_notice_missing')

    def test_customer_capability_tracks_cabinets_physically_in_place(self):
        self.seed_quake()
        # Restricted zone: no full-service claims while cabinets sit in Z.
        capability = self.step('rack', op='capability')
        self.assertFalse(capability['full_capability'])
        self.assertTrue(all(s['state'] == 'degraded' for s in capability['services']))
        # Releasing the row changes nothing physically: still degraded.
        self.step('rack', op='release', rack='r2')
        capability = self.step('rack', op='capability')
        self.assertFalse(capability['full_capability'])

    def test_assessment_requires_cracks_anchors_and_calibrated_traceable_sensors(self):
        # Fresh zone with a peak but no field evidence.
        self.step('structure', op='zone', id='zone-q', site='site-a', load_limit=8,
                  revision=1, drawing_revision='dwg-9')
        self.step('structure', op='element', id='beam-q1', zone='zone-q', kind='beam',
                  shared=True, rated_limit=8)
        self.step('structure', op='sensor', id='accel-q', location='zone-q/p1',
                  calibration='cal-2026-02', uncertainty=0.2)
        self.step('structure', op='sample', id='q-shock', zone='zone-q', sensor='accel-q',
                  at=50, acceleration=9)
        missing = self.step('structure', op='assess', id='q-assess', zone='zone-q',
                            engineer='engineer-b', at=60, safe_load=4)
        self.assertEqual(missing['decision'], 'field_evidence_incomplete')
        self.assertFalse(missing['evidence']['cracks'])
        self.assertFalse(missing['evidence']['anchor_checks'])
        # Uncalibrated sensor readings cannot support the adjudication chain.
        self.assertEqual(self.step('structure', op='sensor', id='accel-bad', location='zone-q/p2',
                                   calibration='unknown', uncertainty=0.9,
                                   status='uncalibrated')['decision'], 'sensor_recorded')
        self.assertEqual(self.step('structure', op='sample', id='q-shock-2', zone='zone-q',
                                   sensor='accel-bad', at=51, acceleration=7)['decision'],
                         'sensor_uncalibrated')

    def test_fixture_sequence_replays_decisions_and_table_state(self):
        # Business time order inside the structure fixture: pre-quake cabinets
        # and mirrors, quake record and crack survey, anchor measurements,
        # then the independent engineer's load ruling.
        self.load_fixture('structure', 'structure_post_quake.json')
        self.load_fixture('rack', 'rack_post_quake.json')
        review = self.step('structure', op='load_review', zone='zone-z')
        self.assertEqual(review['safe_load'], 6)
        self.assertEqual(review['occupied_total'], 9)
        self.assertTrue(review['overloaded'])
        result = replay(str(self.path))
        self.assertTrue(result['verified'], result['errors'])

    def test_aftershock_fixture_is_self_contained_and_replayable(self):
        # The aftershock fixture carries its own zone, element and sensor so it
        # can be replayed on a fresh database; its ruling references the last
        # observed aftershock sequence number.
        self.load_fixture('structure', 'aftershock_sequence.json')
        ruling = self.db.execute(
            "SELECT status FROM structural_zones WHERE id='zone-z'").fetchone()
        self.assertEqual(ruling['status'], 'restricted')
        result = replay(str(self.path))
        self.assertTrue(result['verified'], result['errors'])


if __name__ == '__main__':
    unittest.main()
