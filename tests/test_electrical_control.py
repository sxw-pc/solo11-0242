import json
import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, replay

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'fixtures'


class ElectricalIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'power.sqlite'
        self.db = connect(str(self.path))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def step(self, sub, **x):
        return execute(self.db, sub, x)

    def load_fixture(self, name):
        data = json.loads((FIXTURES / name).read_text(encoding='utf-8'))
        return [execute(self.db, item.pop('sub'), item) for item in data]

    # ------------------------------------------------------------------
    # The original defect: two breaker acks plus a live reserve feed must
    # never produce a safe permit.
    # ------------------------------------------------------------------
    def test_breaker_acks_cannot_override_live_reserve_feed(self):
        self.step('electrical', op='rack', id='rack-1', generation=3)
        self.step('admission', op='workload', id='build-1', environment='prod',
                  digest='sha256:a', generation=1)
        for feed, breaker in [('primary', 'b1'), ('reserve', 'b2')]:
            self.step('electrical', op='feed', rack='rack-1', feed=feed, breaker=breaker)
            self.step('electrical', op='breaker_ack', id=f'cmd-{breaker}',
                      breaker=breaker, action='open', ack=f'ack-{breaker}')
        self.step('electrical', op='workload', rack='rack-1', workload='build-1')
        self.step('meter', op='calibrate', probe='probe-a', at=40, valid_until=500)
        self.step('meter', op='sample', id='sample-1', breaker='b2',
                  source='probe:probe-a', volts=230, at=41)
        result = self.step('electrical', op='permit', id='permit-1',
                           rack='rack-1', generation=3, at=42)
        self.assertNotEqual(result['decision'], 'safe')
        self.assertEqual(result['decision'], 'outside_repair_window')
        self.assertEqual(self.step('meter', op='inspect', breaker='b2')['volts'], 230)
        self.assertTrue(replay(str(self.path))['verified'])

    def test_stale_rack_generation_ack_rejected(self):
        self.step('electrical', op='rack', id='rack-1', generation=4)
        self.step('electrical', op='feed', rack='rack-1', feed='primary', breaker='b1')
        self.step('electrical', op='feed', rack='rack-1', feed='reserve', breaker='b2')
        self.step('electrical', op='window', rack='rack-1', start=10, expires=99, generation=1)
        result = self.step('electrical', op='permit', id='p-old',
                           rack='rack-1', generation=3, at=20)
        self.assertEqual(result['decision'], 'stale_rack_generation')

    # ------------------------------------------------------------------
    # Acceptance 1: voltage verification against the wrong rack.
    # ------------------------------------------------------------------
    def test_wrong_rack_metering_does_not_clear_target_breaker(self):
        self.step('electrical', op='rack', id='r-a', generation=1)
        self.step('electrical', op='rack', id='r-b', generation=1)
        self.step('electrical', op='feed', rack='r-a', feed='primary', breaker='k1')
        self.step('electrical', op='feed', rack='r-b', feed='primary', breaker='k2')
        self.step('electrical', op='window', rack='r-a', start=10, expires=99, generation=1)
        self.step('electrical', op='part', serial='s1', rack='r-a', position='pdu')
        self.step('electrical', op='backfeed_path', id='bf1', rack='r-a', breaker='k1', label='tie')
        self.step('meter', op='calibrate', probe='p', at=5, valid_until=200)
        self.step('electrical', op='dispatch', id='c1', rack='r-a', breaker='k1', action='open', at=12)
        self.step('electrical', op='position', id='pos1', breaker='k1', position='open',
                  source='local-indicator', at=13)
        # 230 V is measured on the *other* rack's breaker.
        self.step('meter', op='sample', id='s-other', breaker='k2',
                  source='probe:p', volts=230, at=14)
        diagnosis = self.step('meter', op='diagnose', breaker='k2', at=15)
        self.assertEqual(diagnosis['decision'], 'not_open')
        # No trusted zero-voltage sample on k1 itself -> permit refused.
        refused = self.step('electrical', op='permit', id='p1', rack='r-a',
                            generation=1, at=16)
        self.assertEqual(refused['decision'], 'no_trusted_voltage_sample')

    # ------------------------------------------------------------------
    # Acceptance 2: primary and reserve backfeed both block contact.
    # ------------------------------------------------------------------
    def test_primary_and_reserve_backfeed_block_permit(self):
        self.step('electrical', op='rack', id='rack-1', generation=2)
        self.step('electrical', op='feed', rack='rack-1', feed='primary', breaker='b1')
        self.step('electrical', op='feed', rack='rack-1', feed='reserve', breaker='b2')
        self.step('electrical', op='backfeed_path', id='bf1', rack='rack-1', breaker='b1', label='ups')
        self.step('electrical', op='backfeed_path', id='bf2', rack='rack-1', breaker='b2', label='tie')
        self.step('electrical', op='part', serial='s1', rack='rack-1', position='pdu')
        self.step('electrical', op='window', rack='rack-1', start=10, expires=99, generation=1)
        self.step('meter', op='calibrate', probe='p', at=5, valid_until=200)
        for breaker, sample_id, volts in [('b1', 's1', 230), ('b2', 's2', 230)]:
            self.step('electrical', op='dispatch', id=f'c-{breaker}', rack='rack-1',
                      breaker=breaker, action='open', at=11)
            self.step('electrical', op='position', id=f'pos-{breaker}', breaker=breaker,
                      position='open', source='local-indicator', at=12)
            self.step('meter', op='sample', id=sample_id, breaker=breaker,
                      source='probe:p', volts=volts, at=13)
            self.assertEqual(self.step('meter', op='diagnose', breaker=breaker, at=14)['decision'],
                             'live_backfeed')
        self.assertEqual(self.step('electrical', op='permit', id='p-live',
                                   rack='rack-1', generation=2, at=15)['decision'],
                         'live_backfeed')

    # ------------------------------------------------------------------
    # Acceptance 3: expired probe calibration cannot establish zero voltage.
    # ------------------------------------------------------------------
    def test_uncalibrated_probe_reading_cannot_clear_permit(self):
        self.step('electrical', op='rack', id='rack-1', generation=1)
        self.step('electrical', op='feed', rack='rack-1', feed='primary', breaker='b1')
        self.step('electrical', op='backfeed_path', id='bf1', rack='rack-1', breaker='b1', label='tie')
        self.step('electrical', op='part', serial='s1', rack='rack-1', position='pdu')
        self.step('electrical', op='window', rack='rack-1', start=10, expires=99, generation=1)
        self.step('meter', op='calibrate', probe='old', at=1, valid_until=20)
        self.step('electrical', op='dispatch', id='c1', rack='rack-1', breaker='b1',
                  action='open', at=11)
        self.step('electrical', op='position', id='pos1', breaker='b1', position='open',
                  source='local-indicator', at=12)
        sample = self.step('meter', op='sample', id='s-old', breaker='b1',
                           source='probe:old', volts=0, at=25)
        self.assertEqual(sample['decision'], 'sampled_uncalibrated')
        inspect = self.step('meter', op='inspect', breaker='b1')
        self.assertFalse(inspect['trusted'])
        self.assertEqual(self.step('electrical', op='permit', id='p1',
                                   rack='rack-1', generation=1, at=26)['decision'],
                         'no_trusted_voltage_sample')

    # ------------------------------------------------------------------
    # Acceptance 4: duplicate command acks / repeat open commands.
    # ------------------------------------------------------------------
    def test_duplicate_open_command_refused_before_external_state_known(self):
        self.step('electrical', op='rack', id='rack-1', generation=1)
        self.step('electrical', op='feed', rack='rack-1', feed='reserve', breaker='b2')
        first = self.step('electrical', op='dispatch', id='c1', rack='rack-1',
                          breaker='b2', action='open', state='sent', at=10)
        self.assertEqual(first['decision'], 'dispatched')
        second = self.step('electrical', op='dispatch', id='c2', rack='rack-1',
                           breaker='b2', action='open', at=11)
        self.assertEqual(second['decision'], 'duplicate_open_command')
        # Once the local indicator proves open, a further command is assessable
        # rather than blindly repeated.
        self.step('electrical', op='position', id='pos1', breaker='b2',
                  position='open', source='local-indicator', at=12)
        third = self.step('electrical', op='dispatch', id='c3', rack='rack-1',
                          breaker='b2', action='open', at=13)
        self.assertEqual(third['decision'], 'dispatched')

    def test_lost_ack_leaves_external_switch_unknown(self):
        self.step('electrical', op='rack', id='rack-4', generation=1)
        self.step('electrical', op='feed', rack='rack-4', feed='primary', breaker='b6')
        self.step('electrical', op='backfeed_path', id='bf4', rack='rack-4', breaker='b6', label='tie')
        self.step('electrical', op='part', serial='s4', rack='rack-4', position='pdu')
        self.step('electrical', op='window', rack='rack-4', start=10, expires=99, generation=1)
        self.step('meter', op='calibrate', probe='p', at=5, valid_until=200)
        self.step('electrical', op='dispatch', id='lost-cmd', rack='rack-4',
                  breaker='b6', action='open', state='lost', at=11)
        # Legacy ack channel says open but no position/metering evidence exists.
        self.step('electrical', op='breaker_ack', id='legacy', breaker='b6',
                  action='open', ack='ack-b6')
        result = self.step('electrical', op='permit', id='p4',
                           rack='rack-4', generation=1, at=14)
        self.assertEqual(result['decision'], 'ack_lost_external_state_unknown')

    # ------------------------------------------------------------------
    # Acceptance 5: migration with partial outputs must not count as done.
    # ------------------------------------------------------------------
    def test_migration_requires_verified_complete_output_chain(self):
        self._ready_workload('build-urgent', 'rack-1', 'rack-2')
        self.step('admission', op='build_output', id='o1', workload='build-urgent',
                  rack='rack-1', digest='sha256:u', state='partial', at=20)
        self.assertEqual(self.step('admission', op='migrate', id='m1',
                                   lease_id='lease-1', source_rack='rack-1',
                                   target_rack='rack-2', at=21)['decision'],
                         'partial_output_on_source')
        self.step('admission', op='build_output', id='o2', workload='build-urgent',
                  rack='rack-1', digest='sha256:u', state='complete', at=22)
        self.assertEqual(self.step('admission', op='migrate', id='m1',
                                   lease_id='lease-1', source_rack='rack-1',
                                   target_rack='rack-2', at=23)['decision'],
                         'migration_started')
        self.step('admission', op='transfer', id='m1', at=24)
        # Partial output on standby does not prove the build continues.
        self.step('admission', op='build_output', id='o3', workload='build-urgent',
                  rack='rack-2', digest='sha256:u', state='partial', at=25)
        self.assertEqual(self.step('admission', op='verify_migration', id='m1',
                                   decision_id='sd1', lease_id='lease-1', at=26)['decision'],
                         'no_complete_output_on_target')
        # A complete output with the wrong digest is not the same task.
        self.step('admission', op='build_output', id='o4', workload='build-urgent',
                  rack='rack-2', digest='sha256:different', state='complete', at=27)
        self.assertEqual(self.step('admission', op='build_output', id='o5',
                                   workload='build-urgent', rack='rack-2',
                                   digest='sha256:different', state='complete', at=28)['decision'],
                         'output_digest_mismatch')
        self.step('admission', op='build_output', id='o6', workload='build-urgent',
                  rack='rack-2', digest='sha256:u', state='complete', at=29)
        verified = self.step('admission', op='verify_migration', id='m1',
                             decision_id='sd2', lease_id='lease-1', at=30)
        self.assertEqual(verified['decision'], 'migration_verified')
        # Lease stays active: customer deadline is preserved on the standby rack.
        lease = self.db.execute("SELECT status FROM leases WHERE id='lease-1'").fetchone()
        self.assertEqual(lease['status'], 'active')

    def test_isolated_flag_alone_does_not_stop_running_build(self):
        self._ready_workload('build-urgent', 'rack-1', 'rack-2')
        # admission isolate marks bookkeeping only; permit still sees active lease.
        self.step('admission', op='isolate', id='lease-1')
        self.step('electrical', op='backfeed_path', id='bf1', rack='rack-1', breaker='b1', label='tie')
        self.step('electrical', op='part', serial='s1', rack='rack-1', position='pdu')
        self.step('electrical', op='window', rack='rack-1', start=10, expires=99, generation=1)
        result = self.step('electrical', op='permit', id='p1', rack='rack-1',
                           generation=1, at=40)
        self.assertEqual(result['decision'], 'workloads_running')

    # ------------------------------------------------------------------
    # Acceptance 6: entry already on site, then permit withdrawn.
    # ------------------------------------------------------------------
    def test_post_issuance_live_reading_withdraws_permit_and_evacuates(self):
        permit_id = self._fully_isolated_rack('rack-1')
        self.step('electrical', op='entry', id='e1', permit=permit_id,
                  rack='rack-1', technician='tech-1', at=60)
        self.step('meter', op='sample', id='live-again', breaker='b2',
                  source='probe:probe-a', volts=230, at=61)
        status = self.step('electrical', op='status', id=permit_id)
        self.assertEqual(status['decision'], 'withdrawn')
        self.assertEqual(status['revoke_reason'], 'live_backfeed')
        entry = self.db.execute("SELECT state FROM field_entries WHERE id='e1'").fetchone()
        self.assertEqual(entry['state'], 'evacuated')
        # Original permit and entry rows are retained, only status columns move.
        self.assertEqual(self.db.execute(
            "SELECT COUNT(*) FROM electrical_permits WHERE id=?", (permit_id,)).fetchone()[0], 1)
        # Re-entry under a withdrawn permit is refused.
        self.assertEqual(self.step('electrical', op='entry', id='e2', permit=permit_id,
                                   rack='rack-1', technician='tech-2', at=62)['decision'],
                         'permit_not_active')

    # ------------------------------------------------------------------
    # Acceptance 7: erroneous customer resume notice must be corrected,
    # originals retained.
    # ------------------------------------------------------------------
    def test_wrong_resume_notice_is_corrected_not_overwritten(self):
        self._ready_workload('build-urgent', 'rack-1', 'rack-2')
        self.step('admission', op='notice', id='n1', lease_id='lease-1',
                  kind='service_resume', at=30, detail='wrong resume')
        corrected = self.step('admission', op='correct_notice', id='n1', new_id='n2',
                              kind='service_pause', at=31, detail='still paused')
        self.assertEqual(corrected['decision'], 'notice_corrected')
        original = self.db.execute("SELECT state FROM customer_notices WHERE id='n1'").fetchone()
        self.assertEqual(original['state'], 'corrected')
        rows = self.db.execute("SELECT id FROM customer_notices ORDER BY id").fetchall()
        self.assertEqual([r['id'] for r in rows], ['n1', 'n2'])
        # Re-correcting is rejected so the original trail is stable.
        self.assertEqual(self.step('admission', op='correct_notice', id='n1',
                                   new_id='n3', kind='service_pause', at=32,
                                   detail='x')['decision'], 'notice_already_corrected')

    def test_contract_pause_records_deadline_loss_and_requires_acceptance_to_restart(self):
        self._ready_workload('build-urgent', 'rack-1', 'rack-2')
        pause = self.step('admission', op='contract_pause', id='lease-1',
                          decision_id='sd-p', responsibility='maintenance-window',
                          deadline_loss=90, at=40)
        self.assertEqual(pause['decision'], 'paused')
        self.assertEqual(pause['deadline_loss'], 90)
        # Restart before repair acceptance is refused.
        self.assertEqual(self.step('admission', op='restart', id='lease-1',
                                   rack='rack-1', at=41)['decision'], 'repair_not_accepted')

    # ------------------------------------------------------------------
    # End-to-end fixture replays: the same conflict scene under both legal
    # dispositions, plus the unknown-external-switch diagnosis scene.
    # ------------------------------------------------------------------
    def test_migration_disposition_fixture(self):
        results = self.load_fixture('electrical_conflict_migration.json')
        decisions = [r['decision'] for r in results]
        # 230 V present -> every early permit attempt refused.
        self.assertIn('live_backfeed', decisions)
        self.assertIn('backfeed_path_open', decisions)
        self.assertIn('migration_verified', decisions)
        self.assertIn('safe', decisions)
        self.assertIn('withdrawn', decisions)
        self.assertIn('accepted', decisions)
        self.assertTrue(replay(str(self.path))['verified'])

    def test_contract_pause_disposition_fixture(self):
        results = self.load_fixture('electrical_conflict_pause.json')
        decisions = [r['decision'] for r in results]
        self.assertIn('live_backfeed', decisions)
        self.assertIn('paused', decisions)
        self.assertIn('notice_corrected', decisions)
        self.assertIn('safe', decisions)
        self.assertIn('restarted', decisions)
        service = self.db.execute("SELECT deadline_loss,responsibility FROM service_decisions").fetchone()
        self.assertEqual(service['deadline_loss'], 90)
        self.assertEqual(service['responsibility'], 'maintenance-window')
        self.assertTrue(replay(str(self.path))['verified'])

    def test_diagnosis_fixture_classifies_each_conflict(self):
        results = self.load_fixture('electrical_diagnosis.json')
        decisions = [r['decision'] for r in results]
        self.assertIn('duplicate_open_command', decisions)
        self.assertIn('sampled_uncalibrated', decisions)
        self.assertIn('probe_uncalibrated', decisions)
        self.assertIn('not_open', decisions)
        self.assertIn('safe', decisions)
        self.assertTrue(replay(str(self.path))['verified'])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _ready_workload(self, workload, source_rack, target_rack):
        self.step('electrical', op='rack', id=source_rack, generation=1)
        self.step('electrical', op='rack', id=target_rack, generation=1, standby_for=source_rack)
        self.step('electrical', op='feed', rack=source_rack, feed='primary', breaker='b1')
        self.step('electrical', op='feed', rack=source_rack, feed='reserve', breaker='b2')
        self.step('provenance', op='scope', signer='builder-a', source='repo-a')
        self.step('provenance', op='manifest', digest='sha256:u', tag='u:1',
                  batch='b1', generation=1)
        self.step('provenance', op='attest', id='a1', digest='sha256:u', batch='b1',
                  signer='builder-a', source='repo-a', recipe='r1',
                  expected_recipe='r1', generation=1)
        self.step('provenance', op='sbom', digest='sha256:u', components=['lib-a'], revision=1)
        self.step('channel', op='propose', id='p-dev', digest='sha256:u',
                  environment='dev', at=5)
        self.step('channel', op='publish', id='p-dev', at=6)
        self.step('channel', op='propose', id='p-stage', digest='sha256:u',
                  environment='stage', parent_environment='dev', at=7)
        self.step('channel', op='publish', id='p-stage', at=8)
        self.step('admission', op='workload', id=workload, environment='stage',
                  digest='sha256:u', generation=1)
        self.step('admission', op='admit', id='lease-1', workload=workload,
                  generation=1, channel_generation=1, at=9, expires=400)
        self.step('electrical', op='workload', rack=source_rack, workload=workload)

    def _fully_isolated_rack(self, rack):
        self.step('electrical', op='rack', id=rack, generation=1)
        self.step('electrical', op='feed', rack=rack, feed='primary', breaker='b1')
        self.step('electrical', op='feed', rack=rack, feed='reserve', breaker='b2')
        self.step('electrical', op='backfeed_path', id='bf1', rack=rack, breaker='b1', label='ups')
        self.step('electrical', op='backfeed_path', id='bf2', rack=rack, breaker='b2', label='tie')
        self.step('electrical', op='part', serial='s1', rack=rack, position='pdu')
        self.step('electrical', op='window', rack=rack, start=10, expires=120, generation=1)
        self.step('meter', op='calibrate', probe='probe-a', at=5, valid_until=500)
        for breaker in ('b1', 'b2'):
            self.step('electrical', op='dispatch', id=f'c-{breaker}', rack=rack,
                      breaker=breaker, action='open', at=20)
            self.step('electrical', op='position', id=f'pos-{breaker}', breaker=breaker,
                      position='open', source='local-indicator', at=21)
            self.step('meter', op='sample', id=f's-{breaker}', breaker=breaker,
                      source='probe:probe-a', volts=0, at=22)
            self.step('electrical', op='backfeed_clear', id=f'bf{1 if breaker == "b1" else 2}', at=23)
            self.step('electrical', op='lockout', id=f'lo-{breaker}', rack=rack,
                      breaker=breaker, technician='tech-1', state='applied', at=24)
        result = self.step('electrical', op='permit', id='permit-x', rack=rack,
                           generation=1, at=25)
        self.assertEqual(result['decision'], 'safe')
        return 'permit-x'


if __name__ == '__main__':
    unittest.main()
