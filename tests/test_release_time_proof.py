"""Acceptance tests for release time proofs (image D cross-clock case).

These tests prove that:

* proposal/publish/window interval relations are rebuilt from raw originals;
* witness sequence numbers are non-reusable and correlated operators/upstreams
  never masquerade as two independent witnesses;
* clock rollback and offline backfill are preserved as distinct evidence;
* late calibration revises conclusions without rewriting issued certificates;
* certificates are bound to image digest, generation, event originals and a
  pinned clock version and cannot be transferred to another release;
* the narrow order-only certificate and the formal interval certificate are
  both compliant deliverables for the same release;
* every conclusion survives event replay.

Run from the repository root:

    python -B -m unittest discover -s tests -q
"""

import json
import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, one, rows, replay
from imagecourt.timeproof import (
    INSUFFICIENT_EVIDENCE,
    PROVABLY_OUTSIDE,
    PROVABLY_WITHIN,
    digest_text,
    independence_report,
    reconstruct_release,
    review_fixture,
    window_verdict,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / 'fixtures' / 'release_time_cross_clock.json'
DIGEST_D = 'sha256:' + 'd' * 64
OTHER_DIGEST = 'sha256:' + 'e' * 64


def load_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding='utf-8'))


class ReleaseTimeProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'release-time.sqlite')
        self.db = connect(self.path)

    def tearDown(self):
        try:
            self.db.close()
        except Exception:
            pass
        self.tmp.cleanup()

    def step(self, subsystem='timeproof', **payload):
        return execute(self.db, subsystem, payload)

    # -- shared scenario builders -----------------------------------------

    def channel_d_flow(self, digest=DIGEST_D, close=30, start=20):
        """Trusted image D promoted dev -> stage -> prod; self-reports 24/29."""
        self.step('provenance', op='scope', signer='builder-a', source='repo-a')
        self.step('provenance', op='manifest', digest=digest, tag='image-D',
                  batch='bd', generation=1)
        self.step('provenance', op='attest', id='att-d', digest=digest, batch='bd',
                  signer='builder-a', source='repo-a', recipe='r1',
                  expected_recipe='r1', generation=1)
        self.step('provenance', op='sbom', digest=digest, components=['libd'], revision=1)

        self.step('channel', op='propose', id='d-dev', digest=digest,
                  environment='dev', at=10)
        self.step('channel', op='publish', id='d-dev', at=11)
        self.step('channel', op='propose', id='d-stage', digest=digest,
                  environment='stage', parent_environment='dev', at=12)
        self.step('channel', op='publish', id='d-stage', at=13)
        self.step('channel', op='window', environment='prod',
                  start=start, expires=close, generation=1)
        propose = self.step('channel', op='propose', id='d-prod', digest=digest,
                            environment='prod', parent_environment='stage', at=24)
        publish = self.step('channel', op='publish', id='d-prod', at=29)
        self.assertEqual(propose['decision'], 'pending')
        self.assertEqual(publish['decision'], 'published')  # naive self-report passes

        pseq = self.channel_event_seq('propose', 'd-prod')
        useq = self.channel_event_seq('publish', 'd-prod')
        self.assertLess(pseq, useq)
        return {'propose_seq': pseq, 'publish_seq': useq, 'generation': propose['generation']}

    def channel_event_seq(self, op, promotion_id):
        for row in rows(self.db,
                        "SELECT seq,payload FROM events WHERE subsystem='channel' ORDER BY seq"):
            payload = json.loads(row['payload'])
            if payload.get('op') == op and payload.get('id') == promotion_id:
                return row['seq']
        raise AssertionError(f'channel event {op}/{promotion_id} not found')

    def event_digest(self, seq):
        return digest_text(one(self.db, 'SELECT payload FROM events WHERE seq=?', (seq,))['payload'])

    def seed_fixture_witnesses(self, fixture=None):
        fixture = fixture or load_fixture()
        for witness in fixture['witnesses']:
            result = self.step(op='witness', **witness)
            self.assertEqual(result['decision'], 'witness_recorded', result)
        return fixture

    def seed_fixture_stamps(self, bind_publish_digest=None, fixture=None):
        fixture = fixture or load_fixture()
        for stamp in fixture['stamps']:
            payload = dict(stamp)
            if bind_publish_digest and stamp['event_key'] == 'publish-D':
                payload['original_digest'] = bind_publish_digest
            self.assertEqual(self.step(op='stamp', **payload)['decision'], 'stamp_recorded')

    def assert_replay_verified(self):
        self.db.close()
        result = replay(self.path)
        self.assertTrue(result['verified'], result.get('errors'))
        self.db = connect(self.path)
        return result

    # -- 1. independent reconstruction from the cross-clock fixture --------

    def test_fixture_rebuilds_interval_relations_and_undecidable_close(self):
        fixture = load_fixture()
        report = reconstruct_release(fixture)
        expected = fixture['expected']

        publish_event = report['events']['publish-D']
        per_source = {s['source']: s['interval'] for s in publish_event['stamps']}
        self.assertEqual(per_source['w-node-d'], expected['node_publish_interval'])
        self.assertEqual(per_source['w-signer-d'], expected['signer_publish_interval'])

        # Intersection, never min(claimed_utc)=29.
        self.assertEqual(report['propose']['interval'], expected['propose_interval'])
        self.assertEqual(report['publish']['interval'], expected['publish_interval'])
        self.assertEqual(report['publish']['interval'], [27, 31])
        # Conservative span/envelope [min lower, max upper] is also available
        # for reviewers who treat the correlated clocks as non-intersectable.
        self.assertEqual(report['publish']['interval_envelope'], [26, 32])

        # Both the local seq and the disjoint absolute intervals order
        # proposal before publish.
        self.assertEqual(report['seq_order'], 'propose_before_publish')
        self.assertEqual(report['interval_order'], 'propose_before_publish')
        self.assertTrue(report['order_proven'])

        # The close at minute 30 lies inside [27,31]: undecidable.
        publish = report['publish']
        self.assertEqual(publish['window_verdict'], INSUFFICIENT_EVIDENCE)
        self.assertEqual(publish['status'], 'time_unproven')
        self.assertIsNone(publish['production_window_met'])
        self.assertIn('interval_crosses_close', publish['reasons'])

        # Shared upstream makes the pair a single independence root.
        independence = publish['independence']
        self.assertEqual(independence['independence_groups'], 1)
        self.assertFalse(independence['fully_independent'])
        self.assertTrue(independence['shared_upstream'])
        self.assertIn('shared_upstream_correlation', publish['reasons'])

        # Stable clock version and reviewer entry point.
        self.assertTrue(report['clock_version'].startswith('clock-v-'))
        self.assertEqual(report['clock_version'], review_fixture(FIXTURE_PATH)['clock_version'])
        self.assertEqual(report['release']['digest'], DIGEST_D)
        self.assertEqual(report['release']['generation'], 4)

        # The trap itself is explicit in the fixture.
        self.assertEqual(expected['minimum_claimed_utc_trap'], 29)
        self.assertLess(expected['minimum_claimed_utc_trap'], 30)
        self.assertNotEqual(window_verdict([27, 31], 20, 30), PROVABLY_WITHIN)

    def test_three_valued_boundary_classification(self):
        # Entire interval strictly before the half-open close -> inside.
        self.assertEqual(window_verdict([28, 29], 20, 30), PROVABLY_WITHIN)
        self.assertEqual(window_verdict([29, 29], 20, 30), PROVABLY_WITHIN)
        # Lower endpoint at/after close -> provably outside.
        self.assertEqual(window_verdict([30, 30], 20, 30), PROVABLY_OUTSIDE)
        self.assertEqual(window_verdict([30, 33], 20, 30), PROVABLY_OUTSIDE)
        # Completely before opening -> outside.
        self.assertEqual(window_verdict([10, 19], 20, 30), PROVABLY_OUTSIDE)
        # Endpoint exactly on close still crosses the half-open boundary.
        self.assertEqual(window_verdict([29, 30], 20, 30), INSUFFICIENT_EVIDENCE)
        self.assertEqual(window_verdict([27, 31], 20, 30), INSUFFICIENT_EVIDENCE)
        # No interval is not licence to invent an instant.
        self.assertEqual(window_verdict(None, 20, 30), INSUFFICIENT_EVIDENCE)

    # -- 2. narrow order-only certificate ---------------------------------

    def test_order_only_certificate_proves_sequence_but_never_window(self):
        refs = self.channel_d_flow()
        result = self.step(op='order_certificate', id='cert-order-d',
                           digest=DIGEST_D, **refs)
        self.assertEqual(result['decision'], 'order_proven')
        self.assertEqual(result['scope'], 'order_only')
        self.assertTrue(result['order_proven'])
        self.assertEqual(result['seq_order'], 'propose_before_publish')
        self.assertIsNone(result['production_window_met'])
        self.assertEqual(result['window_claim'], 'not_evaluated')
        self.assertNotIn('interval', result)
        self.assertEqual(result['clock_version'], 'seq-only:events-v1')
        self.assertTrue(result['events_digest'].startswith('sha256:'))

        row = one(self.db, 'SELECT * FROM time_certificates WHERE id=?', ('cert-order-d',))
        self.assertEqual(row['scope'], 'order_only')
        self.assertEqual(row['status'], 'order_proven')
        self.assertIsNone(row['certified_utc'])
        self.assertIsNone(row['interval_low'])
        self.assertEqual(row['propose_event_digest'], self.event_digest(refs['propose_seq']))
        self.assertEqual(row['publish_event_digest'], self.event_digest(refs['publish_seq']))

        # Reversed sequence cannot be certified as proposal-before-publish.
        bad = self.step(op='order_certificate', id='cert-order-bad',
                        digest=DIGEST_D, generation=refs['generation'],
                        propose_seq=refs['publish_seq'],
                        publish_seq=refs['propose_seq'])
        self.assertEqual(bad['decision'], 'order_not_proven')
        self.assertIsNone(one(self.db, 'SELECT id FROM time_certificates WHERE id=?',
                              ('cert-order-bad',)))

        replay_result = self.assert_replay_verified()
        self.assertGreaterEqual(replay_result['decisions'], 1)

    def test_seq_alone_has_no_absolute_interval(self):
        # A bundle carrying only commit order cannot answer the window question.
        report = reconstruct_release({
            'propose_seq': 18, 'publish_seq': 21,
            'window': {'start': 20, 'expires': 30},
        })
        self.assertTrue(report['order_proven'])
        self.assertIsNone(report['publish']['interval'])
        self.assertEqual(report['publish']['window_verdict'], INSUFFICIENT_EVIDENCE)
        self.assertIsNone(report['publish']['production_window_met'])

    # -- 3. formal interval certificate for D is time_unproven ------------

    def test_formal_certificate_D_is_time_unproven_and_replays(self):
        refs = self.channel_d_flow()
        fixture = self.seed_fixture_witnesses()
        publish_digest = self.event_digest(refs['publish_seq'])
        self.seed_fixture_stamps(bind_publish_digest=publish_digest, fixture=fixture)

        result = self.step(
            op='release_certificate', id='cert-formal-d',
            digest=DIGEST_D,
            propose_event_key='propose-D', publish_event_key='publish-D',
            window_start=20, window_expires=30, **refs)

        self.assertEqual(result['decision'], 'time_unproven')
        self.assertEqual(result['status'], 'time_unproven')
        self.assertEqual(result['window_verdict'], INSUFFICIENT_EVIDENCE)
        self.assertIsNone(result['production_window_met'])
        self.assertEqual(result['interval'], [27, 31])
        self.assertEqual(result['seq_order'], 'propose_before_publish')
        self.assertEqual(result['interval_order'], 'propose_before_publish')
        self.assertEqual(result['clock_version'],
                         reconstruct_release(fixture)['clock_version'])
        self.assertEqual(result['publish_event_digest'], publish_digest)

        row = one(self.db, 'SELECT * FROM time_certificates WHERE id=?', ('cert-formal-d',))
        self.assertEqual(row['status'], 'time_unproven')
        self.assertEqual((row['interval_low'], row['interval_high']), (27, 31))
        self.assertEqual(row['verdict'], INSUFFICIENT_EVIDENCE)
        self.assertEqual(row['scope'], 'release_interval')

        verified = self.step(op='verify_certificate', id='cert-formal-d')
        self.assertTrue(verified['valid'], verified)

        replay_result = self.assert_replay_verified()
        self.assertTrue(replay_result['verified'])

        # Conclusions are identical when rebuilt from the replayed originals.
        reloaded = __import__('imagecourt.timeproof', fromlist=['_verify_certificate'])
        check = reloaded.run(self.db, {'op': 'verify_certificate', 'id': 'cert-formal-d'})
        self.assertTrue(check['valid'], check)
        self.assertEqual(check['stored_verdict'], INSUFFICIENT_EVIDENCE)
        self.assertEqual(check['correction_count'], 0)

    def test_review_from_database_matches_independent_fixture(self):
        fixture = self.seed_fixture_witnesses()
        self.seed_fixture_stamps(fixture=fixture)
        review = self.step(op='review_release',
                           propose_event_key='propose-D',
                           publish_event_key='publish-D',
                           window=fixture['window'])
        pure = reconstruct_release(fixture)
        self.assertEqual(review['propose']['interval'], pure['propose']['interval'])
        self.assertEqual(review['publish']['interval'], pure['publish']['interval'])
        self.assertEqual(review['publish']['window_verdict'],
                         pure['publish']['window_verdict'])
        self.assertEqual(review['independence']['independence_groups'], 1)
        self.assertEqual(review['clock_version'], pure['clock_version'])
        self.assert_replay_verified()

    def test_two_audit_deliverables_differ_in_strength_and_disclosure(self):
        refs = self.channel_d_flow()
        fixture = self.seed_fixture_witnesses()
        publish_digest = self.event_digest(refs['publish_seq'])
        self.seed_fixture_stamps(bind_publish_digest=publish_digest, fixture=fixture)

        # Deliverable 1: narrowed order certificate for the customer.
        order = self.step(op='order_certificate', id='cert-order-audit',
                          digest=DIGEST_D, **refs)
        self.assertEqual(order['decision'], 'order_proven')
        customer = self.step(op='disclosure_package', id='cert-order-audit',
                             audience='customer')
        self.assertEqual(customer['decision'], 'order_only_package')
        self.assertTrue(customer['order_proven'])
        self.assertIsNone(customer['production_window_met'])
        self.assertEqual(customer['window_claim'], 'not_evaluated')
        self.assertFalse(customer['originals_disclosed'])
        self.assertEqual(customer['witnesses'], [])
        customer_text = json.dumps(customer)
        self.assertNotIn('WS-NODE-D', customer_text)
        self.assertNotIn('signing_chain', customer_text)

        # Deliverable 2: formal interval certificate + confidential originals.
        formal = self.step(op='release_certificate', id='cert-formal-audit',
                           digest=DIGEST_D, **refs,
                           propose_event_key='propose-D', publish_event_key='publish-D',
                           window_start=20, window_expires=30)
        self.assertEqual(formal['decision'], 'time_unproven')

        confidential = self.step(op='disclosure_package', id='cert-formal-audit',
                                 audience='confidential_review')
        self.assertEqual(confidential['decision'], 'confidential_package')
        self.assertTrue(confidential['originals_disclosed'])
        self.assertEqual(confidential['interval'], [27, 31])
        self.assertEqual(confidential['verdict'], INSUFFICIENT_EVIDENCE)
        serials = {w['witness_seq'] for w in confidential['witnesses']}
        self.assertIn('WS-NODE-D-000731', serials)
        self.assertIn('WS-SIGNER-D-002044', serials)
        self.assertTrue(all(w['signing_chain'] for w in confidential['witnesses']))
        self.assertEqual(len(confidential['stamps']), 4)
        self.assertIsNotNone(confidential['report'])

        # Same release/window/originals: customer cannot claim on-time either.
        customer_formal = self.step(op='disclosure_package', id='cert-formal-audit',
                                    audience='customer')
        self.assertFalse(customer_formal['originals_disclosed'])
        self.assertEqual(customer_formal['interval'], [27, 31])
        self.assertIsNone(customer_formal['production_window_met'])
        self.assert_replay_verified()

    # -- 4. witness independence and non-reusable serials ------------------

    def test_witness_sequence_is_non_reusable(self):
        first = self.step(op='witness', id='w1', operator='ops-co', kind='node',
                          witness_seq='WS-0001', signing_chain=['k1', 'ca'],
                          calibration_start=0, calibration_end=60,
                          offset_min=-2, offset_max=2)
        self.assertEqual(first['decision'], 'witness_recorded')

        reused = self.step(op='witness', id='w2-forged-independent', operator='ops-co',
                           kind='node', witness_seq='WS-0001',
                           signing_chain=['k2', 'ca'],
                           calibration_start=0, calibration_end=60,
                           offset_min=-2, offset_max=2)
        self.assertEqual(reused['decision'], 'witness_seq_reused')
        self.assertIsNone(one(self.db, 'SELECT id FROM clock_sources WHERE id=?',
                              ('w2-forged-independent',)))
        self.assertEqual(one(self.db, 'SELECT COUNT(*) AS n FROM clock_sources '
                                     'WHERE witness_seq=?', ('WS-0001',))['n'], 1)

    def test_same_operator_counts_as_one_independence_root(self):
        w1 = {'id': 'w1', 'operator': 'ops-co', 'witness_seq': 'WS-1',
              'upstream_group': 'u'}
        w2 = {'id': 'w2', 'operator': 'ops-co', 'witness_seq': 'WS-2',
              'upstream_group': 'u'}
        report = independence_report([w1, w2])
        self.assertEqual(report['independence_groups'], 1)
        self.assertTrue(report['same_operator'])
        self.assertFalse(report['fully_independent'])

        w3 = {'id': 'w3', 'operator': 'other-notary', 'witness_seq': 'WS-3'}
        report3 = independence_report([w1, w2, w3])
        self.assertEqual(report3['independence_groups'], 2)
        self.assertTrue(report3['all_roots_distinct'] is False)

    def test_formal_certificate_enforces_independence_quorum(self):
        refs = self.channel_d_flow()
        for wid, serial in (('w1', 'WS-1'), ('w2', 'WS-2')):
            self.assertEqual(self.step(
                op='witness', id=wid, operator='same-operator', kind='node',
                witness_seq=serial, signing_chain=[f'key-{wid}'],
                calibration_start=0, calibration_end=60,
                offset_min=-1, offset_max=0)['decision'], 'witness_recorded')
            self.step(op='stamp', id=f'stamp-{wid}', event_key='publish-Q',
                      source=wid, local_at=29, claimed_utc=29)

        refused = self.step(op='release_certificate', id='cert-quorum',
                            digest=DIGEST_D, **refs,
                            publish_event_key='publish-Q',
                            window_start=20, window_expires=30,
                            min_independent_groups=2)
        self.assertEqual(refused['decision'], 'independence_not_established')
        self.assertEqual(refused['independence']['independence_groups'], 1)
        self.assertIsNone(one(self.db, 'SELECT id FROM time_certificates WHERE id=?',
                              ('cert-quorum',)))

        # A genuinely separate notary root reaches the quorum and resolves
        # the boundary inside with tight [-1, 0] bounds -> [28,29].
        self.assertEqual(self.step(
            op='witness', id='w3', operator='independent-notary', kind='notary',
            witness_seq='WS-3', signing_chain=['notary-key', 'notary-ca'],
            calibration_start=0, calibration_end=60,
            offset_min=-1, offset_max=0)['decision'], 'witness_recorded')
        self.step(op='stamp', id='stamp-w3', event_key='publish-Q',
                  source='w3', local_at=29, claimed_utc=29)
        granted = self.step(op='release_certificate', id='cert-quorum-ok',
                            digest=DIGEST_D, **refs,
                            publish_event_key='publish-Q',
                            window_start=20, window_expires=30,
                            min_independent_groups=2)
        self.assertNotEqual(granted['decision'], 'independence_not_established')
        self.assertEqual(granted['decision'], 'time_certified')
        self.assertEqual(granted['interval'], [28, 29])
        self.assert_replay_verified()

    # -- 5. clock rollback --------------------------------------------------

    def test_clock_rollback_is_detected_recorded_and_replayed(self):
        self.assertEqual(self.step(
            op='witness', id='w-clock', operator='ops-co', kind='node',
            witness_seq='WS-CLOCK-1', signing_chain=['k'],
            calibration_start=0, calibration_end=120,
            offset_min=-1, offset_max=1)['decision'], 'witness_recorded')

        normal = self.step(op='stamp', id='ts-1', event_key='e1',
                           source='w-clock', local_at=40, claimed_utc=40)
        self.assertEqual(normal, {'decision': 'stamp_recorded'})

        rolled = self.step(op='stamp', id='ts-2', event_key='e2',
                            source='w-clock', local_at=35, claimed_utc=35)
        self.assertTrue(rolled['rollback_detected'])
        self.assertEqual(rolled['anomaly_id'], 'anom-ts-2')

        stamp_row = one(self.db, 'SELECT rollback,rollback_reason FROM time_stamps WHERE id=?',
                        ('ts-2',))
        self.assertEqual(stamp_row['rollback'], 1)
        anomaly = one(self.db, 'SELECT * FROM clock_anomalies WHERE stamp=?', ('ts-2',))
        self.assertEqual(anomaly['kind'], 'clock_rollback')

        review = self.step(op='review_release', publish_event_key='e2')
        self.assertTrue(review['events']['e2']['stamps'][0]['rollback'])

        replay_result = self.assert_replay_verified()
        self.assertTrue(replay_result['verified'])
        anomaly_after = one(self.db, 'SELECT kind FROM clock_anomalies WHERE stamp=?', ('ts-2',))
        self.assertEqual(anomaly_after['kind'], 'clock_rollback')

    # -- 6. offline backfill is not rollback -------------------------------

    def test_offline_backfill_preserves_late_original_without_rollback(self):
        self.step(op='witness', id='w-off', operator='ops-co', kind='node',
                  witness_seq='WS-OFF-1', signing_chain=['k'],
                  calibration_start=0, calibration_end=120,
                  offset_min=-1, offset_max=1)
        self.step(op='stamp', id='ts-new', event_key='e-new',
                  source='w-off', local_at=40, claimed_utc=40)

        backfill = self.step(op='stamp', id='ts-old-offline', event_key='e-old',
                             source='w-off', local_at=12, claimed_utc=12,
                             backfill=True, received_at=55)
        self.assertEqual(backfill, {'decision': 'stamp_recorded'})
        old = one(self.db, 'SELECT backfill,rollback,received_at FROM time_stamps WHERE id=?',
                  ('ts-old-offline',))
        self.assertEqual((old['backfill'], old['rollback'], old['received_at']), (1, 0, 55))
        self.assertIsNone(one(self.db, 'SELECT id FROM clock_anomalies WHERE stamp=?',
                              ('ts-old-offline',)))

        # The same backwards reading without the offline marker IS rollback.
        late = self.step(op='stamp', id='ts-plain-old', event_key='e-plain-old',
                         source='w-off', local_at=10, claimed_utc=10)
        self.assertTrue(late['rollback_detected'])
        self.assert_replay_verified()

    # -- 7. late calibration and append-only corrections -------------------

    def test_late_calibration_revises_only_through_appended_correction(self):
        refs = self.channel_d_flow()
        fixture = self.seed_fixture_witnesses()
        publish_digest = self.event_digest(refs['publish_seq'])
        self.seed_fixture_stamps(bind_publish_digest=publish_digest, fixture=fixture)

        original = self.step(op='release_certificate', id='cert-late',
                             digest=DIGEST_D, **refs,
                             propose_event_key='propose-D', publish_event_key='publish-D',
                             window_start=20, window_expires=30)
        self.assertEqual(original['decision'], 'time_unproven')
        old_clock_version = original['clock_version']

        # Late lab calibration tightens both clocks to [-1, 0].
        for source in ('w-node-d', 'w-signer-d'):
            cal = self.step(op='calibrate', source=source,
                            offset_min=-1, offset_max=0,
                            reason='late laboratory calibration', recorded_at=40)
            self.assertEqual(cal['decision'], 'calibration_recorded')
            self.assertEqual(cal['version'], 2)

        # Original v1 calibration values are preserved, not overwritten.
        v1 = one(self.db, 'SELECT * FROM clock_calibrations WHERE source=? AND version=1',
                 ('w-node-d',))
        self.assertEqual((v1['offset_min'], v1['offset_max']), (-3, 3))
        v2 = one(self.db, 'SELECT * FROM clock_calibrations WHERE source=? AND version=2',
                 ('w-node-d',))
        self.assertEqual((v2['offset_min'], v2['offset_max']), (-1, 0))

        review = self.step(op='review_release',
                           propose_event_key='propose-D', publish_event_key='publish-D',
                           window_start=20, window_expires=30)
        publish = review['publish']
        self.assertEqual(publish['known_then_interval'], [27, 31])
        self.assertEqual(publish['current_interval'], [28, 29])
        self.assertEqual(publish['interval'], [28, 29])
        self.assertEqual(publish['window_verdict'], PROVABLY_WITHIN)

        # Issued certificate row is untouched before correction.
        before = one(self.db, 'SELECT status,clock_version,interval_low,interval_high '
                              'FROM time_certificates WHERE id=?', ('cert-late',))
        self.assertEqual(before['status'], 'time_unproven')
        self.assertEqual(before['clock_version'], old_clock_version)
        self.assertEqual((before['interval_low'], before['interval_high']), (27, 31))

        correction = self.step(op='correct_certificate', id='corr-late-1',
                               certificate_id='cert-late',
                               reason='append late calibration revision')
        self.assertEqual(correction['decision'], 'certificate_corrected')
        self.assertEqual(correction['revision'], 1)
        self.assertEqual(correction['verdict'], PROVABLY_WITHIN)
        self.assertEqual(correction['status'], 'time_certified')
        self.assertEqual(correction['interval'], [28, 29])
        self.assertNotEqual(correction['clock_version'], old_clock_version)

        # Original remains exactly as issued; correction is appended.
        after = one(self.db, 'SELECT * FROM time_certificates WHERE id=?', ('cert-late',))
        self.assertEqual(after['status'], 'time_unproven')
        self.assertEqual(after['clock_version'], old_clock_version)
        corrections = rows(self.db,
                            'SELECT * FROM time_certificate_corrections WHERE certificate_id=?',
                            ('cert-late',))
        self.assertEqual([c['revision'] for c in corrections], [1])

        # Re-issuing the same certificate id never overwrites it.
        reused = self.step(op='release_certificate', id='cert-late',
                           digest=DIGEST_D, **refs,
                           propose_event_key='propose-D', publish_event_key='publish-D',
                           window_start=20, window_expires=30)
        self.assertEqual(reused['decision'], 'reused')

        # Original certificate still verifies against its pinned clock version.
        verified = self.step(op='verify_certificate', id='cert-late')
        self.assertTrue(verified['valid'], verified)
        self.assertEqual(verified['stored_verdict'], INSUFFICIENT_EVIDENCE)
        self.assertEqual(verified['correction_count'], 1)

        replay_result = self.assert_replay_verified()
        self.assertTrue(replay_result['verified'])

    # -- 8. certificate scope cannot transfer to another release -----------

    def test_certificate_is_bound_to_release_events_and_clock(self):
        refs = self.channel_d_flow()
        self.seed_fixture_witnesses()
        self.seed_fixture_stamps(fixture=load_fixture())
        issued = self.step(op='release_certificate', id='cert-bound',
                           digest=DIGEST_D, **refs,
                           propose_event_key='propose-D', publish_event_key='publish-D',
                           window_start=20, window_expires=30)
        self.assertEqual(issued['decision'], 'time_unproven')

        ok = self.step(op='verify_certificate', id='cert-bound',
                       digest=DIGEST_D, generation=refs['generation'],
                       window_start=20, window_expires=30,
                       clock_version=issued['clock_version'])
        self.assertTrue(ok['valid'], ok)

        wrong_digest = self.step(op='verify_certificate', id='cert-bound',
                                 digest=OTHER_DIGEST)
        self.assertFalse(wrong_digest['valid'])
        self.assertIn('image_digest', wrong_digest['mismatches'])
        self.assertEqual(wrong_digest['decision'], 'certificate_scope_mismatch')

        wrong_generation = self.step(op='verify_certificate', id='cert-bound', generation=99)
        self.assertFalse(wrong_generation['valid'])
        self.assertIn('generation', wrong_generation['mismatches'])

        wrong_window = self.step(op='verify_certificate', id='cert-bound', window_expires=99)
        self.assertFalse(wrong_window['valid'])
        self.assertIn('window_expires', wrong_window['mismatches'])

        wrong_clock = self.step(op='verify_certificate', id='cert-bound',
                               clock_version='clock-v-deadbeefdeadbeef')
        self.assertFalse(wrong_clock['valid'])
        self.assertIn('clock_version', wrong_clock['mismatches'])

        # Same certificate id cannot be re-posted for another release.
        other_refs = {k: v for k, v in refs.items() if k != 'generation'}
        conflict = self.step(op='release_certificate', id='cert-bound',
                             digest=OTHER_DIGEST, generation=77, **other_refs,
                             propose_event_key='propose-D', publish_event_key='publish-D',
                             window_start=20, window_expires=30)
        self.assertEqual(conflict['decision'], 'certificate_id_conflict')

    def test_stamp_event_digest_must_match_referenced_event_original(self):
        refs = self.channel_d_flow()
        self.seed_fixture_witnesses()
        # Deliberately bind publish stamps to a different original text.
        self.seed_fixture_stamps(bind_publish_digest=digest_text('some other event text'))
        result = self.step(op='release_certificate', id='cert-bad-original',
                           digest=DIGEST_D, **refs,
                           propose_event_key='propose-D', publish_event_key='publish-D',
                           window_start=20, window_expires=30)
        self.assertEqual(result['decision'], 'event_original_mismatch')
        self.assertIsNone(one(self.db, 'SELECT id FROM time_certificates WHERE id=?',
                              ('cert-bad-original',)))

    # -- 9. provably inside / outside formal certificates ------------------

    def test_formal_certificates_for_inside_and_outside_intervals(self):
        refs = self.channel_d_flow()

        self.step(op='witness', id='w-tight', operator='notary-a', kind='notary',
                  witness_seq='WN-1', signing_chain=['notary-key'],
                  calibration_start=0, calibration_end=60,
                  offset_min=-1, offset_max=0)
        self.step(op='stamp', id='stamp-in', event_key='publish-IN',
                  source='w-tight', claimed_utc=29)
        inside = self.step(op='release_certificate', id='cert-in',
                           digest=DIGEST_D, **refs,
                           publish_event_key='publish-IN',
                           window_start=20, window_expires=30)
        self.assertEqual(inside['decision'], 'time_certified')
        self.assertTrue(inside['production_window_met'])
        self.assertEqual(inside['interval'], [28, 29])

        self.step(op='witness', id='w-late', operator='notary-b', kind='notary',
                  witness_seq='WN-2', signing_chain=['notary-key-b'],
                  calibration_start=0, calibration_end=60,
                  offset_min=1, offset_max=2)
        self.step(op='stamp', id='stamp-out', event_key='publish-OUT',
                  source='w-late', claimed_utc=29)
        outside = self.step(op='release_certificate', id='cert-out',
                            digest=DIGEST_D, **refs,
                            publish_event_key='publish-OUT',
                            window_start=20, window_expires=30)
        self.assertEqual(outside['decision'], 'time_certified_outside')
        self.assertFalse(outside['production_window_met'])
        self.assertEqual(outside['interval'], [30, 31])
        self.assertEqual(outside['window_verdict'], PROVABLY_OUTSIDE)
        self.assert_replay_verified()

    # -- 10. shared upstream common-mode error widens intervals ------------

    def test_relative_clock_errors_add_shared_upstream_interval(self):
        bundle = {
            'window': {'start': 20, 'expires': 30},
            'upstreams': [{'id': 'u', 'offset_min': -3, 'offset_max': 3}],
            'witnesses': [{'id': 'w', 'operator': 'ops', 'witness_seq': 'S1',
                            'absolute': False, 'upstream_group': 'u',
                            'offset_min': -2, 'offset_max': 2}],
            'stamps': [{'event_key': 'publish', 'source': 'w', 'claimed_utc': 29}],
        }
        report = reconstruct_release(bundle)
        # device [27,31] plus common upstream [-3,3] -> [24,34]
        self.assertEqual(report['publish']['interval'], [24, 34])
        self.assertEqual(report['publish']['window_verdict'], INSUFFICIENT_EVIDENCE)

        # Without an absolute calibration of the common upstream, no absolute
        # interval may be claimed at all.
        del bundle['upstreams']
        report2 = reconstruct_release(bundle)
        self.assertIsNone(report2['publish']['interval'])
        self.assertEqual(report2['publish']['window_verdict'], INSUFFICIENT_EVIDENCE)

    # -- 11. legacy provisional min-claimed behaviour remains a trap -------

    def test_legacy_provisional_min_claimed_coexists_but_is_not_window_proof(self):
        self.assertEqual(self.step(op='source', id='legacy-clock', operator='time-a',
                                   offset_min=-3, offset_max=3)['decision'],
                         'clock_recorded')
        self.step(op='stamp', id='legacy-stamp', event_key='publish-D',
                  source='legacy-clock', local_at=29, claimed_utc=29)
        provisional = self.step(op='certificate', id='legacy-cert', event_key='publish-D')
        self.assertEqual(provisional, {'decision': 'provisional_time', 'at': 29})
        row = one(self.db, 'SELECT * FROM time_certificates WHERE id=?', ('legacy-cert',))
        self.assertEqual(row['status'], 'provisional')
        self.assertEqual(row['scope'], 'provisional')

        # The same source's bounded interval says [26,32], crossing close 30.
        report = self.step(op='review_release', publish_event_key='publish-D',
                           window_start=20, window_expires=30)
        self.assertEqual(report['publish']['interval'], [26, 32])
        self.assertEqual(report['publish']['window_verdict'], INSUFFICIENT_EVIDENCE)
        self.assert_replay_verified()

    # -- 12. incomplete clock originals cannot be strict witnesses ---------

    def test_strict_witness_requires_every_original_element(self):
        result = self.step(op='witness', id='w-incomplete', operator='ops',
                           witness_seq='WS-X')
        self.assertEqual(result['decision'], 'incomplete_clock_original')
        self.assertIn('signing_chain', result['missing'])
        self.assertIn('calibration_start', result['missing'])
        self.assertIn('offset_min', result['missing'])
        self.assertIsNone(one(self.db, 'SELECT id FROM clock_sources WHERE id=?',
                              ('w-incomplete',)))


if __name__ == '__main__':
    unittest.main()
