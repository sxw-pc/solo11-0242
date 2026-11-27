import json
import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, one, replay

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'fixtures'


class BuildGreenRights(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'green.sqlite'
        self.db = connect(str(self.path))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def step(self, **x):
        return execute(self.db, 'energy', x)

    def seed_manifest(self, batch='batch-a', digest='sha256:aaa'):
        execute(self.db, 'provenance', {'op': 'manifest', 'digest': digest,
                                        'tag': 'img:1', 'batch': batch, 'generation': 1})

    def load_fixture(self, name):
        data = json.loads((FIXTURES / name).read_text(encoding='utf-8'))
        return [execute(self.db, 'energy', x) for x in data]

    def shared_meter(self):
        return self.load_fixture('green_shared_meter.json')

    def single_certificate(self):
        return self.load_fixture('green_single_certificate.json')

    def run_batch_a(self, run='run-a', batch='batch-a', digest='sha256:aaa',
                    site='site-a', region='region-east', customer='customer-a',
                    start=30, finish=90, allocations=(('reading-1', 30), ('reading-2', 20))):
        self.seed_manifest(batch, digest)
        self.assertEqual(self.step(op='build_start', id=run, batch=batch, digest=digest,
                                   site=site, region=region, customer=customer,
                                   at=start)['decision'], 'build_started')
        self.assertEqual(self.step(op='build_pause', id=run, at=50)['decision'], 'build_paused')
        self.assertEqual(self.step(op='build_retry', id=run, at=60)['decision'], 'build_resumed')
        self.assertEqual(self.step(op='build_standby', id=run, starts=60, ends=70,
                                   kwh=5)['decision'], 'standby_recorded')
        result = self.step(op='build_finish', id=run, at=finish,
                           allocations=[{'reading': r, 'kwh': k} for r, k in allocations])
        self.assertEqual(result['decision'], 'build_finished')
        return result

    # ------------------------------------------------------------------
    # Fixture sanity and replay
    # ------------------------------------------------------------------
    def test_fixtures_register_meter_chain_and_certificate_chain(self):
        meter = self.shared_meter()
        self.assertEqual([x['decision'] for x in meter],
                         ['meter_registered', 'reading_recorded', 'reading_recorded'])
        cert = self.single_certificate()
        self.assertEqual([x['decision'] for x in cert],
                         ['certificate_issued', 'certificate_transferred', 'certificate_transferred'])
        review = self.step(op='cert_review', serial='cert-1')
        self.assertEqual(review['owner'], 'platform')
        self.assertEqual(len(review['chain']), 3)
        self.assertEqual(review['remaining_kwh'], 30)
        self.assertTrue(replay(str(self.path))['verified'])

    def test_failure_fixture_decisions_and_replay(self):
        results = self.load_fixture('green_failure.json')
        self.assertEqual([x['decision'] for x in results],
                         ['unknown_meter', 'unknown_certificate', 'run_not_finished'])
        self.assertTrue(replay(str(self.path))['verified'])

    # ------------------------------------------------------------------
    # Customer A: grid-source-only claim (20 physical low-carbon units)
    # ------------------------------------------------------------------
    def test_grid_source_claim_attaches_only_physical_low_carbon(self):
        self.shared_meter()
        result = self.run_batch_a()
        self.assertEqual(result['measured_kwh'], 50)
        self.assertEqual(result['physical_low_carbon_kwh'], 20)
        review = self.step(op='build_review', id='run-a')
        self.assertTrue(review['allocation_matches_measurement'])
        self.assertEqual(len(review['segments']), 3)
        claim = self.step(op='claim_green', id='claim-a', run='run-a',
                          customer='customer-a', basis='grid_source',
                          physical_kwh=20, certificate_kwh=0, reading='reading-1')
        self.assertEqual(claim['decision'], 'draft_claim')
        published = self.step(op='claim_publish', id='claim-a')
        self.assertEqual(published['decision'], 'claim_published')
        # The 30-unit certificate stays untouched and remains sellable.
        self.single_certificate()
        _, remaining = None, self.step(op='cert_review', serial='cert-1')['remaining_kwh']
        self.assertEqual(remaining, 30)
        rights = self.step(op='rights_review')
        meter_view = next(m for m in rights['meters'] if m['decision'] == 'meter_reviewed'
                          and m['trusted_kwh'] == 100)
        self.assertEqual(meter_view['allocated_kwh'], 50)
        self.assertEqual(meter_view['headroom_kwh'], 50)
        self.assertTrue(replay(str(self.path))['verified'])

    def test_grid_basis_cannot_attach_market_certificates(self):
        self.shared_meter()
        self.run_batch_a()
        denied = self.step(op='claim_green', id='claim-x', run='run-a',
                           customer='customer-a', basis='grid_source',
                           physical_kwh=20, certificate_kwh=10)
        self.assertEqual(denied['decision'], 'grid_basis_forbids_certificates')

    def test_physical_claim_cannot_exceed_verifiable_low_carbon_share(self):
        self.shared_meter()
        self.run_batch_a()
        denied = self.step(op='claim_green', id='claim-x', run='run-a',
                           customer='customer-a', basis='grid_source',
                           physical_kwh=21, certificate_kwh=0)
        self.assertEqual(denied['decision'], 'claim_exceeds_physical_low_carbon')

    def test_source_string_is_not_low_carbon_evidence(self):
        self.step(op='meter_device', id='meter-a', site='site-a', region='region-east',
                  model='m', calibration_id='c1', calibration_at=0,
                  calibration_until=1000, at=0)
        denied = self.step(op='meter_reading', id='r1', device='meter-a', site='site-a',
                           window_start=0, window_end=10, kwh=10, low_carbon_kwh=5,
                           evidence=None, revision=1, at=10)
        self.assertEqual(denied['decision'], 'low_carbon_evidence_required')

    # ------------------------------------------------------------------
    # Customer A: market-basis claim (20 physical + 30 retired = 50 green)
    # ------------------------------------------------------------------
    def test_market_claim_retires_certificate_and_consumes_entitlement_permanently(self):
        self.shared_meter()
        self.single_certificate()
        self.run_batch_a()
        retired = self.step(op='cert_retire', id='retire-1', serial='cert-1',
                            run='run-a', owner='platform', kwh=30, at=95,
                            receipt='receipt-1')
        self.assertEqual(retired['decision'], 'certificate_retired')
        self.assertEqual(retired['remaining_kwh'], 0)
        claim = self.step(op='claim_green', id='claim-mkt', run='run-a',
                          customer='customer-a', basis='market',
                          physical_kwh=20, certificate_kwh=30, reading='reading-1')
        self.assertEqual(claim['decision'], 'draft_claim')
        self.assertEqual(self.step(op='claim_publish', id='claim-mkt')['decision'],
                         'claim_published')
        # A second build batch can never spend the same certificate again.
        self.seed_manifest('batch-b', 'sha256:bbb')
        self.assertEqual(self.step(op='build_start', id='run-b', batch='batch-b',
                                   digest='sha256:bbb', site='site-a', region='region-east',
                                   customer='customer-b', at=100)['decision'], 'build_started')
        self.assertEqual(self.step(op='build_finish', id='run-b', at=110,
                                   allocations=[{'reading': 'reading-2', 'kwh': 10}]
                                   )['decision'], 'build_finished')
        double = self.step(op='cert_retire', id='retire-2', serial='cert-1',
                           run='run-b', owner='platform', kwh=1, at=115,
                           receipt='receipt-2')
        self.assertEqual(double['decision'], 'retirement_exceeds_certificate')
        claim_b = self.step(op='claim_green', id='claim-b', run='run-b',
                            customer='customer-b', basis='market',
                            physical_kwh=0, certificate_kwh=1)
        self.assertEqual(claim_b['decision'], 'claim_exceeds_retired_attributes')
        self.assertTrue(replay(str(self.path))['verified'])

    def test_second_live_claim_on_same_run_is_rejected(self):
        self.shared_meter()
        self.single_certificate()
        self.run_batch_a()
        self.assertEqual(self.step(op='cert_retire', id='retire-1', serial='cert-1',
                                   run='run-a', owner='platform', kwh=30, at=95,
                                   receipt='receipt-1')['decision'], 'certificate_retired')
        self.assertEqual(self.step(op='claim_green', id='claim-d', run='run-a',
                                   customer='customer-a', basis='market',
                                   physical_kwh=20, certificate_kwh=30
                                   )['decision'], 'draft_claim')
        over = self.step(op='claim_green', id='claim-e', run='run-a',
                         customer='customer-a', basis='market',
                         physical_kwh=20, certificate_kwh=31)
        self.assertEqual(over['decision'], 'run_already_claimed')

    def test_claim_within_measurement_but_over_certificate_balance_denied(self):
        self.shared_meter()
        self.single_certificate()
        self.run_batch_a()
        self.assertEqual(self.step(op='cert_retire', id='retire-1', serial='cert-1',
                                   run='run-a', owner='platform', kwh=10, at=95,
                                   receipt='receipt-1')['decision'], 'certificate_retired')
        denied = self.step(op='claim_green', id='claim-short', run='run-a',
                           customer='customer-a', basis='market',
                           physical_kwh=20, certificate_kwh=11)
        self.assertEqual(denied['decision'], 'claim_exceeds_retired_attributes')

    def test_double_green_kwh_denied_even_when_certificates_cover_it(self):
        self.shared_meter()
        self.step(op='cert_issue', serial='cert-big', station='wind-park-2',
                  region='region-east', period_start=0, period_end=120,
                  initial_owner='platform', kwh=50, at=5)
        self.run_batch_a()
        self.assertEqual(self.step(op='cert_retire', id='retire-big', serial='cert-big',
                                   run='run-a', owner='platform', kwh=50, at=95,
                                   receipt='receipt-big')['decision'], 'certificate_retired')
        # 20 physical + 50 certificates = 70 green units from a 50 kwh build.
        denied = self.step(op='claim_green', id='claim-2g', run='run-a',
                           customer='customer-a', basis='market',
                           physical_kwh=20, certificate_kwh=50)
        self.assertEqual(denied['decision'], 'double_counted_green_kwh')

    def test_low_carbon_share_of_a_reading_is_counted_only_once(self):
        self.shared_meter()
        self.seed_manifest()
        self.assertEqual(self.step(op='build_start', id='run-c', batch='batch-a',
                                   digest='sha256:aaa', site='site-a', region='region-east',
                                   customer='customer-a', at=10)['decision'], 'build_started')
        # Two allocations from reading-1 (12 low-carbon of 60): splitting 40+10
        # cannot surface more than 12 verifiable low-carbon units.
        result = self.step(op='build_finish', id='run-c', at=50,
                           allocations=[{'reading': 'reading-1', 'kwh': 40},
                                        {'reading': 'reading-1', 'kwh': 10}])
        self.assertEqual(result['decision'], 'build_finished')
        self.assertEqual(result['physical_low_carbon_kwh'], 12)

    def test_reading_from_other_billing_period_cannot_be_borrowed(self):
        self.step(op='meter_device', id='meter-a', site='site-a', region='region-east',
                  model='m', calibration_id='c1', calibration_at=0,
                  calibration_until=1000, at=0)
        self.step(op='meter_reading', id='r-jan', device='meter-a', site='site-a',
                  window_start=0, window_end=30, kwh=30, low_carbon_kwh=10,
                  evidence='ev-jan', revision=1, at=30)
        self.step(op='meter_reading', id='r-feb', device='meter-a', site='site-a',
                  window_start=30, window_end=60, kwh=30, low_carbon_kwh=10,
                  evidence='ev-feb', predecessor='r-jan', revision=1, at=60)
        self.seed_manifest()
        self.assertEqual(self.step(op='build_start', id='run-feb', batch='batch-a',
                                   digest='sha256:aaa', site='site-a', region='region-east',
                                   customer='customer-a', at=35)['decision'], 'build_started')
        # January reading belongs to a closed period that never overlaps the run.
        denied = self.step(op='build_finish', id='run-feb', at=55,
                           allocations=[{'reading': 'r-jan', 'kwh': 10}])
        self.assertEqual(denied['decision'], 'reading_window_mismatch')
        ok = self.step(op='build_finish', id='run-feb', at=55,
                       allocations=[{'reading': 'r-feb', 'kwh': 10}])
        self.assertEqual(ok['decision'], 'build_finished')

    # ------------------------------------------------------------------
    # Shared physical meter: two batches, sum of allocations bounded by reading
    # ------------------------------------------------------------------
    def test_shared_meter_allocations_never_exceed_trusted_reading(self):
        self.shared_meter()
        self.run_batch_a(run='run-a', allocations=[('reading-1', 30), ('reading-2', 20)])
        self.seed_manifest('batch-b', 'sha256:bbb')
        self.assertEqual(self.step(op='build_start', id='run-b', batch='batch-b',
                                   digest='sha256:bbb', site='site-a', region='region-east',
                                   customer='customer-b', at=100)['decision'], 'build_started')
        ok = self.step(op='build_finish', id='run-b', at=110,
                       allocations=[{'reading': 'reading-2', 'kwh': 20}])
        self.assertEqual(ok['decision'], 'build_finished')
        review = self.step(op='meter_review', id='meter-a')
        self.assertTrue(review['continuous'])
        self.assertEqual(review['allocated_kwh'], 70)
        self.assertEqual(review['headroom_kwh'], 30)

    def test_repeated_claim_on_same_reading_is_blocked_by_allocation_ledger(self):
        self.shared_meter()
        self.run_batch_a()
        # A second batch reusing the same meter can only take what remains.
        self.seed_manifest('batch-b', 'sha256:bbb')
        self.assertEqual(self.step(op='build_start', id='run-b', batch='batch-b',
                                   digest='sha256:bbb', site='site-a', region='region-east',
                                   customer='customer-b', at=100)['decision'], 'build_started')
        greedy = self.step(op='build_finish', id='run-b', at=110,
                           allocations=[{'reading': 'reading-2', 'kwh': 21}])
        self.assertEqual(greedy['decision'], 'allocation_exceeds_reading')

    # ------------------------------------------------------------------
    # Cross-site and time-window mismatch
    # ------------------------------------------------------------------
    def test_cross_site_reading_cannot_back_another_site_build(self):
        self.shared_meter()
        self.step(op='meter_device', id='meter-b', site='site-b', region='region-east',
                  model='m', calibration_id='c2', calibration_at=0,
                  calibration_until=1000, at=0)
        self.step(op='meter_reading', id='reading-b', device='meter-b', site='site-b',
                  window_start=0, window_end=120, kwh=40, low_carbon_kwh=0,
                  evidence=None, revision=1, at=120)
        self.seed_manifest()
        self.assertEqual(self.step(op='build_start', id='run-a', batch='batch-a',
                                   digest='sha256:aaa', site='site-a', region='region-east',
                                   customer='customer-a', at=30)['decision'], 'build_started')
        denied = self.step(op='build_finish', id='run-a', at=90,
                           allocations=[{'reading': 'reading-b', 'kwh': 10}])
        self.assertEqual(denied['decision'], 'site_mismatch')

    def test_reading_outside_build_window_is_rejected(self):
        self.shared_meter()
        self.seed_manifest()
        self.assertEqual(self.step(op='build_start', id='run-late', batch='batch-a',
                                   digest='sha256:aaa', site='site-a', region='region-east',
                                   customer='customer-a', at=200)['decision'], 'build_started')
        denied = self.step(op='build_finish', id='run-late', at=240,
                           allocations=[{'reading': 'reading-1', 'kwh': 10}])
        self.assertEqual(denied['decision'], 'reading_window_mismatch')

    def test_meter_gap_is_visible_in_review(self):
        self.step(op='meter_device', id='meter-g', site='site-a', region='region-east',
                  model='m', calibration_id='c', calibration_at=0,
                  calibration_until=1000, at=0)
        self.step(op='meter_reading', id='g1', device='meter-g', site='site-a',
                  window_start=0, window_end=10, kwh=10, low_carbon_kwh=0,
                  evidence=None, revision=1, at=10)
        gap = self.step(op='meter_reading', id='g2', device='meter-g', site='site-a',
                        window_start=20, window_end=30, kwh=10, low_carbon_kwh=0,
                        evidence=None, revision=1, at=30)
        self.assertEqual(gap['decision'], 'reading_recorded')
        review = self.step(op='meter_review', id='meter-g')
        self.assertFalse(review['continuous'])
        self.assertEqual(review['gaps'], [[10, 20]])

    # ------------------------------------------------------------------
    # Calibration: uncalibrated meter and decertification
    # ------------------------------------------------------------------
    def test_uncalibrated_meter_reading_rejected(self):
        self.step(op='meter_device', id='meter-u', site='site-a', region='region-east',
                  model='m', calibration_id='c', calibration_at=0,
                  calibration_until=10, at=0)
        denied = self.step(op='meter_reading', id='u1', device='meter-u', site='site-a',
                           window_start=20, window_end=30, kwh=5, low_carbon_kwh=0,
                           evidence=None, revision=1, at=25)
        self.assertEqual(denied['decision'], 'meter_not_calibrated')

    def test_decertification_appends_impact_to_published_claim(self):
        self.shared_meter()
        self.run_batch_a()
        self.assertEqual(self.step(op='claim_green', id='claim-a', run='run-a',
                                   customer='customer-a', basis='grid_source',
                                   physical_kwh=20, certificate_kwh=0
                                   )['decision'], 'draft_claim')
        self.assertEqual(self.step(op='claim_publish', id='claim-a')['decision'],
                         'claim_published')
        result = self.step(op='meter_decertify', id='meter-a', at=300)
        self.assertEqual(result['decision'], 'meter_decertified')
        self.assertEqual(result['affected_claims'], ['claim-a'])
        review = self.step(op='claim_review', id='claim-a')
        reasons = [i['reason'] for i in review['impacts']]
        self.assertEqual(reasons, ['calibration_revoked'])
        # The published statement itself is not overwritten.
        self.assertEqual(review['current_version']['state'], 'published')
        self.assertEqual(review['current_version']['physical_kwh'], 20)

    # ------------------------------------------------------------------
    # Meter correction: append-only revision chain and remediation duty
    # ------------------------------------------------------------------
    def test_meter_correction_appends_revision_and_flags_over_allocation(self):
        self.shared_meter()
        self.run_batch_a()
        self.assertEqual(self.step(op='claim_green', id='claim-a', run='run-a',
                                   customer='customer-a', basis='grid_source',
                                   physical_kwh=20, certificate_kwh=0
                                   )['decision'], 'draft_claim')
        self.assertEqual(self.step(op='claim_publish', id='claim-a')['decision'],
                         'claim_published')
        corrected = self.step(op='meter_correct', id='reading-1', revision=2,
                              kwh=25, low_carbon_kwh=5, evidence='grid-attribution-letter-1-r2',
                              at=150)
        self.assertEqual(corrected['decision'], 'reading_corrected')
        self.assertTrue(corrected['allocation_exceeds_reading'])
        self.assertEqual(corrected['affected_claims'], ['claim-a'])
        stale = self.step(op='meter_correct', id='reading-1', revision=2,
                          kwh=25, low_carbon_kwh=5,
                          evidence='grid-attribution-letter-1-r2', at=160)
        self.assertEqual(stale['decision'], 'stale_reading_revision')
        review = self.step(op='meter_review', id='meter-a')
        self.assertEqual(review['trusted_kwh'], 65)
        self.assertEqual(review['allocated_kwh'], 50)
        claim_view = self.step(op='claim_review', id='claim-a')
        self.assertEqual([i['reason'] for i in claim_view['impacts']], ['meter_correction'])
        self.assertEqual(claim_view['current_version']['state'], 'published')
        self.assertTrue(replay(str(self.path))['verified'])

    # ------------------------------------------------------------------
    # Build rerun: digest unchanged, rights/claims still get appended impact
    # ------------------------------------------------------------------
    def test_build_rerun_preserves_digest_but_appends_claim_impact(self):
        self.shared_meter()
        self.run_batch_a()
        self.assertEqual(self.step(op='claim_green', id='claim-a', run='run-a',
                                   customer='customer-a', basis='grid_source',
                                   physical_kwh=20, certificate_kwh=0
                                   )['decision'], 'draft_claim')
        self.assertEqual(self.step(op='claim_publish', id='claim-a')['decision'],
                         'claim_published')
        rerun = self.step(op='build_rerun', id='run-a-r2', replaces='run-a',
                          site='site-a', region='region-east', at=200)
        self.assertEqual(rerun['decision'], 'rerun_started')
        self.assertEqual(rerun['affected_claims'], ['claim-a'])
        # Same digest, new run identity — the old claim is not silently rebound.
        new_run = one(self.db, 'SELECT * FROM energy_runs WHERE id=?', ('run-a-r2',))
        self.assertEqual(new_run['digest'], 'sha256:aaa')
        self.assertEqual(new_run['state'], 'open')
        review = self.step(op='claim_review', id='claim-a')
        self.assertEqual([i['reason'] for i in review['impacts']], ['build_rerun'])

    # ------------------------------------------------------------------
    # Transfer revocation after retirement: receipts stay, impact appended
    # ------------------------------------------------------------------
    def test_transfer_revocation_after_retirement_appends_remediation(self):
        self.shared_meter()
        self.single_certificate()
        self.run_batch_a()
        self.assertEqual(self.step(op='cert_retire', id='retire-1', serial='cert-1',
                                   run='run-a', owner='platform', kwh=30, at=95,
                                   receipt='receipt-1')['decision'], 'certificate_retired')
        self.assertEqual(self.step(op='claim_green', id='claim-mkt', run='run-a',
                                   customer='customer-a', basis='market',
                                   physical_kwh=20, certificate_kwh=30
                                   )['decision'], 'draft_claim')
        self.assertEqual(self.step(op='claim_publish', id='claim-mkt')['decision'],
                         'claim_published')
        revoked = self.step(op='cert_revoke_transfer', id='transfer-2', at=300)
        self.assertEqual(revoked['decision'], 'transfer_revoked')
        self.assertEqual(revoked['affected_claims'], ['claim-mkt'])
        # Retirement receipt remains on record; chain shows the rescission.
        review = self.step(op='cert_review', serial='cert-1')
        self.assertEqual(review['chain'][-1]['status'], 'revoked')
        retirements = [r for r in review['retirements'] if r['receipt'] == 'receipt-1']
        self.assertEqual(retirements[0]['status'], 'retired')
        claim_view = self.step(op='claim_review', id='claim-mkt')
        self.assertEqual([i['reason'] for i in claim_view['impacts']], ['transfer_revoked'])
        self.assertEqual(claim_view['current_version']['state'], 'published')
        self.assertTrue(replay(str(self.path))['verified'])

    # ------------------------------------------------------------------
    # Published claim immutability and versioning
    # ------------------------------------------------------------------
    def test_published_claim_is_immutable_and_versions_append(self):
        self.shared_meter()
        self.run_batch_a()
        self.assertEqual(self.step(op='claim_green', id='claim-a', run='run-a',
                                   customer='customer-a', basis='grid_source',
                                   physical_kwh=20, certificate_kwh=0
                                   )['decision'], 'draft_claim')
        self.assertEqual(self.step(op='claim_publish', id='claim-a')['decision'],
                         'claim_published')
        again = self.step(op='claim_publish', id='claim-a')
        self.assertEqual(again['decision'], 'claim_already_published')
        new_version = self.step(op='claim_new_version', id='claim-a',
                                basis='grid_source', physical_kwh=10, certificate_kwh=0)
        self.assertEqual(new_version['decision'], 'claim_version_drafted')
        self.assertEqual(new_version['version'], 2)
        review = self.step(op='claim_review', id='claim-a')
        self.assertEqual(len(review['history']), 2)
        self.assertEqual(int(review['history'][0]['superseded_by']), 2)
        self.assertEqual(review['current_version']['version'], 2)
        self.assertEqual(review['current_version']['state'], 'draft')

    def test_duplicate_claim_identifier_conflicts(self):
        self.shared_meter()
        self.run_batch_a()
        payload = dict(op='claim_green', id='claim-a', run='run-a',
                       customer='customer-a', basis='grid_source',
                       physical_kwh=5, certificate_kwh=0)
        self.assertEqual(self.step(**payload)['decision'], 'draft_claim')
        self.assertEqual(self.step(**payload)['decision'], 'claim_identity_conflict')

    def test_claim_customer_must_match_run_beneficiary(self):
        self.shared_meter()
        self.run_batch_a()
        denied = self.step(op='claim_green', id='claim-x', run='run-a',
                           customer='customer-b', basis='grid_source',
                           physical_kwh=5, certificate_kwh=0)
        self.assertEqual(denied['decision'], 'claim_customer_mismatch')

    # ------------------------------------------------------------------
    # Digest identity: the build must follow the confirmed manifest batch
    # ------------------------------------------------------------------
    def test_build_rejects_self_reported_batch_name(self):
        self.seed_manifest(batch='batch-a', digest='sha256:aaa')
        denied = self.step(op='build_start', id='run-x', batch='batch-b',
                           digest='sha256:aaa', site='site-a', region='region-east',
                           customer='customer-a', at=1)
        self.assertEqual(denied['decision'], 'unknown_batch')

    def test_certificate_region_and_period_must_match_build(self):
        self.shared_meter()
        self.run_batch_a()
        self.step(op='cert_issue', serial='cert-west', station='solar-2',
                  region='region-west', period_start=0, period_end=120,
                  initial_owner='platform', kwh=10, at=5)
        region_denied = self.step(op='cert_retire', id='r-west', serial='cert-west',
                                  run='run-a', owner='platform', kwh=5, at=95,
                                  receipt='receipt-w')
        self.assertEqual(region_denied['decision'], 'certificate_region_mismatch')
        self.step(op='cert_issue', serial='cert-old', station='wind-9',
                  region='region-east', period_start=0, period_end=10,
                  initial_owner='platform', kwh=10, at=5)
        period_denied = self.step(op='cert_retire', id='r-old', serial='cert-old',
                                  run='run-a', owner='platform', kwh=5, at=95,
                                  receipt='receipt-o')
        self.assertEqual(period_denied['decision'], 'certificate_period_mismatch')


if __name__ == '__main__':
    unittest.main()
