import unittest

from imagecourt.store import connect
from imagecourt.tenant_config import record
from imagecourt.foreign_runtime import permits_egress
from imagecourt import runtime_portability as rp


DIGEST = 'sha256:digest-1'


class RuntimePortabilityTest(unittest.TestCase):
    def setUp(self):
        self.db = connect(':memory:')
        record(self.db, 'C1', 'tenant-A', DIGEST, 2048, 2, 'approved',
               2, 'secret-A')

    def tearDown(self):
        self.db.close()

    # -- helpers -----------------------------------------------------------

    def bundle(self, bundle_id='B1'):
        result = rp.build_bundle(self.db, bundle_id, 'C1')
        self.assertEqual('bundle_drafted', result['decision'])
        return result['document']

    def source_leases(self, n=2):
        for i in range(n):
            self.db.execute('INSERT INTO leases VALUES(?,?,?,?,?,?)',
                            ('lease-%d' % i, 'web-1', DIGEST, 1, 1000,
                             'active'))

    def hosted_ready(self, target='target-X', layer='layer-1',
                     node_online=True, layer_online=True):
        rp.register_target(self.db, target, memory_unit='GiB',
                           supported_groups=['approved'],
                           secret_slot_mode='tenant', node_online=node_online)
        rp.register_layer(self.db, layer, online=layer_online)
        self.bundle()
        ack = rp.acknowledge_import(self.db, 'B1', target, import_id='I1')
        rp.provision_workload(self.db, 'W1', 'B1', target)
        rp.bind_egress(self.db, 'B1', target, 'hosted', layer_id=layer)
        rp.inject_secret(self.db, 'G1', 'B1', target)
        return ack

    # -- 1. unapproved egress ----------------------------------------------

    def test_bare_import_over_permits_but_restricted_runner_denies(self):
        ack = self.hosted_ready()
        # The foreign importer still says "imported" and over-permits.
        self.assertTrue(ack['bare_import_allows_unapproved'])
        self.assertTrue(permits_egress(self.db, 'I1', 'unapproved'))
        # The real target decision after binding enforces the contract.
        self.assertEqual('allow',
                         rp.evaluate_egress(self.db, 'B1', 'approved')['decision'])
        self.assertEqual('deny',
                         rp.evaluate_egress(self.db, 'B1', 'unapproved')['decision'])
        trials = rp.run_trials(self.db, 'B1')
        self.assertEqual('trials_passed', trials['decision'])
        self.assertEqual('target_accepted',
                         rp.accept_target(self.db, 'B1')['decision'])

    def test_export_pins_customer_digest_units_replicas_and_egress_semantics(self):
        doc = self.bundle()
        self.assertEqual('tenant-A', doc['customer'])
        self.assertEqual(DIGEST, doc['digest'])
        self.assertEqual(2048 * 1024 ** 2, doc['memory']['bytes'])
        self.assertEqual('MiB', doc['memory']['unit'])
        self.assertEqual(2, doc['replicas'])
        self.assertEqual(2, doc['paid_concurrency'])
        self.assertEqual(['approved'], doc['egress']['allow'])
        self.assertEqual('deny', doc['egress']['default'])
        self.assertFalse(doc['secrets'][0]['material_included'])

    # -- 2. memory unit misread --------------------------------------------

    def test_target_memory_unit_misread_is_evidenced_and_corrected(self):
        self.hosted_ready()
        # The bare import stores 2048 and the target would read it as GiB:
        # 2048 GiB instead of the contracted 2 GiB (2048 MiB).
        wl = rp._workload(self.db, 'B1')
        self.assertEqual(2048 * 1024 ** 2, wl['memory_bytes'])
        trials = rp.run_trials(self.db, 'B1')
        evidence = next(t for t in trials['trials']
                        if t['capability'] == 'memory_evidence')
        self.assertEqual('fail', evidence['verdict'])
        self.assertEqual(str(2048 * 1024 ** 3), evidence['observed'])
        gating = next(t for t in trials['trials']
                      if t['capability'] == 'memory')
        self.assertEqual('pass', gating['verdict'])
        self.assertEqual('trials_passed', trials['decision'])

    def test_indivisible_memory_unit_blocks_provisioning(self):
        record(self.db, 'C2', 'tenant-A', 'sha256:d2', 1500, 1, 'approved',
               1, 'secret-A2')
        rp.register_target(self.db, 'target-Y', memory_unit='GiB',
                           secret_slot_mode='tenant')
        rp.build_bundle(self.db, 'B2', 'C2')
        rp.acknowledge_import(self.db, 'B2', 'target-Y', import_id='I2')
        self.assertEqual('memory_unit_indivisible',
                         rp.provision_workload(self.db, 'W2', 'B2',
                                               'target-Y')['decision'])

    # -- 3. cross-tenant secret slot ---------------------------------------

    def test_cross_tenant_shared_slot_rejected_and_independent_grant_revocable(self):
        rp.register_target(self.db, 'target-Z', memory_unit='GiB',
                           secret_slot_mode='shared')
        rp.register_layer(self.db, 'layer-1')
        self.bundle()
        rp.acknowledge_import(self.db, 'B1', 'target-Z', import_id='I1')
        rp.provision_workload(self.db, 'W1', 'B1', 'target-Z')
        rp.bind_egress(self.db, 'B1', 'target-Z', 'hosted',
                       layer_id='layer-1')
        self.assertEqual('cross_tenant_secret_slot',
                         rp.inject_secret(self.db, 'G1', 'B1',
                                          'target-Z')['decision'])
        # A tenant-isolated slot gets a fresh, independently revocable grant.
        rp.register_target(self.db, 'target-Z', memory_unit='GiB',
                           secret_slot_mode='tenant')
        self.assertEqual('secret_authorized',
                         rp.inject_secret(self.db, 'G1', 'B1',
                                          'target-Z')['decision'])
        grant = self.db.execute(
            "SELECT * FROM secret_grants WHERE id='G1'").fetchone()
        self.assertEqual('tenant', grant['slot_mode'])
        self.assertEqual('authorized', grant['status'])
        self.assertEqual('secret_revoked',
                         rp.revoke_secret(self.db, 'G1')['decision'])
        self.assertEqual('acceptance_blocked',
                         rp.accept_target(self.db, 'B1')['decision'])

    # -- 4. target node offline --------------------------------------------

    def test_target_node_offline_fails_closed(self):
        self.hosted_ready(node_online=False)
        # Provisioning cannot create on an offline node.
        self.db.execute("DELETE FROM target_workloads")
        self.assertEqual('target_node_offline',
                         rp.provision_workload(self.db, 'W1', 'B1',
                                               'target-X')['decision'])
        # Re-create online, then the node disappears before serving.
        rp.set_node_online(self.db, 'target-X', True)
        rp.provision_workload(self.db, 'W1', 'B1', 'target-X')
        rp.bind_egress(self.db, 'B1', 'target-X', 'hosted',
                       layer_id='layer-1')
        rp.set_node_online(self.db, 'target-X', False)
        self.assertEqual('node_offline',
                         rp.target_request(self.db, 'B1',
                                           'approved')['decision'])
        blocked = rp.accept_target(self.db, 'B1')
        self.assertEqual('acceptance_blocked', blocked['decision'])
        self.assertIn('target_node_offline', blocked['reasons'])

    # -- 5. hosted layer unreachable ---------------------------------------

    def test_hosted_layer_outage_fails_closed_and_blocks_acceptance(self):
        self.hosted_ready(layer_online=False)
        self.assertEqual('enforcement_unreachable',
                         rp.evaluate_egress(self.db, 'B1',
                                           'approved')['decision'])
        trials = rp.run_trials(self.db, 'B1')
        self.assertEqual('trials_failed', trials['decision'])
        blocked = rp.accept_target(self.db, 'B1')
        self.assertEqual('acceptance_blocked', blocked['decision'])
        self.assertIn('hosted_layer_unreachable', blocked['reasons'])
        # Recovery restores the original reachable set without expansion.
        rp.set_layer_online(self.db, 'layer-1', True)
        self.assertEqual('allow',
                         rp.evaluate_egress(self.db, 'B1',
                                           'approved')['decision'])
        self.assertEqual('deny',
                         rp.evaluate_egress(self.db, 'B1',
                                           'unapproved')['decision'])
        rp.run_trials(self.db, 'B1')
        self.assertEqual('target_accepted',
                         rp.accept_target(self.db, 'B1')['decision'])

    # -- 6. customer rejects narrowing sign-off ----------------------------

    def test_narrow_mode_requires_signed_delta_and_honours_rejection(self):
        rp.register_target(self.db, 'target-L', memory_unit='GiB',
                           supported_groups=['approved'],
                           secret_slot_mode='tenant')
        self.bundle()
        rp.acknowledge_import(self.db, 'B1', 'target-L', import_id='I1')
        rp.provision_workload(self.db, 'W1', 'B1', 'target-L')
        rp.propose_delta(self.db, 'D1', 'B1', removed_groups=[],
                         manual_groups=['approved'])
        rp.inject_secret(self.db, 'G1', 'B1', 'target-L')
        # Without signature the narrower local rules cannot take effect.
        self.assertEqual('delta_not_signed',
                         rp.bind_egress(self.db, 'B1', 'target-L', 'narrow',
                                        delta_id='D1')['decision'])
        # A customer rejection keeps the migration from silently shrinking.
        self.assertEqual('delta_rejected',
                         rp.reject_delta(self.db, 'D1')['decision'])
        self.assertEqual('delta_not_signed',
                         rp.bind_egress(self.db, 'B1', 'target-L', 'narrow',
                                        delta_id='D1')['decision'])

    def test_signed_narrowing_moves_destinations_to_manual_admission(self):
        rp.register_target(self.db, 'target-L', memory_unit='GiB',
                           supported_groups=['approved'],
                           secret_slot_mode='tenant')
        self.bundle()
        rp.acknowledge_import(self.db, 'B1', 'target-L', import_id='I1')
        rp.provision_workload(self.db, 'W1', 'B1', 'target-L')
        rp.propose_delta(self.db, 'D1', 'B1', removed_groups=[],
                         manual_groups=['approved'])
        self.assertEqual('delta_signed', rp.sign_delta(self.db, 'D1')['decision'])
        rp.inject_secret(self.db, 'G1', 'B1', 'target-L')
        bound = rp.bind_egress(self.db, 'B1', 'target-L', 'narrow',
                               delta_id='D1')
        self.assertEqual('egress_bound', bound['decision'])
        self.assertEqual([], bound['allow'])  # automatic business shrunk
        self.assertEqual('manual_admission',
                         rp.evaluate_egress(self.db, 'B1',
                                           'approved')['decision'])
        self.assertEqual('deny',
                         rp.evaluate_egress(self.db, 'B1',
                                           'unapproved')['decision'])
        self.assertEqual('trials_passed',
                         rp.run_trials(self.db, 'B1')['decision'])
        self.assertEqual('target_accepted',
                         rp.accept_target(self.db, 'B1')['decision'])

    def test_unsupported_group_only_resolved_by_signed_narrowing(self):
        # Target cannot enforce the original group: compatibility import
        # must not silently widen anything.
        rp.register_target(self.db, 'target-L', memory_unit='GiB',
                           supported_groups=[], secret_slot_mode='tenant')
        self.bundle()
        rp.acknowledge_import(self.db, 'B1', 'target-L', import_id='I1')
        rp.provision_workload(self.db, 'W1', 'B1', 'target-L')
        rp.propose_delta(self.db, 'D1', 'B1', removed_groups=[],
                         manual_groups=['approved'])
        rp.sign_delta(self.db, 'D1')
        # Signed automatic reach that the target cannot enforce locally
        # is refused rather than silently widened by the import.
        rp.propose_delta(self.db, 'D2', 'B1', removed_groups=[],
                         manual_groups=[])
        rp.sign_delta(self.db, 'D2')
        self.assertEqual('target_unsupported_group',
                         rp.bind_egress(self.db, 'B1', 'target-L', 'narrow',
                                        delta_id='D2')['decision'])
        rp.propose_delta(self.db, 'D3', 'B1', removed_groups=['approved'],
                         manual_groups=[])
        rp.sign_delta(self.db, 'D3')
        self.assertEqual('egress_bound',
                         rp.bind_egress(self.db, 'B1', 'target-L', 'narrow',
                                        delta_id='D3')['decision'])

    def test_delta_cannot_reach_beyond_source_contract(self):
        self.bundle()
        self.assertEqual('delta_outside_source_scope',
                         rp.propose_delta(self.db, 'D1', 'B1',
                                          removed_groups=['unapproved'],
                                          manual_groups=[])['decision'])

    # -- 7. double occupancy across both sides ------------------------------

    def test_cutover_never_exceeds_paid_concurrency(self):
        self.hosted_ready()
        rp.run_trials(self.db, 'B1')
        rp.accept_target(self.db, 'B1')
        self.source_leases(2)
        self.assertEqual('cutover_started',
                         rp.begin_cutover(self.db, 'B1')['decision'])
        # Activating a target replica without retiring a source lease
        # would run three against a paid limit of two.
        blocked = rp.cutover_step(self.db, 'B1', retire=0, activate=1)
        self.assertEqual('concurrency_exceeded', blocked['decision'])
        self.assertFalse(blocked['receipt']['within_limit'])
        first = rp.cutover_step(self.db, 'B1', retire=1, activate=1)
        self.assertTrue(first['receipt']['within_limit'])
        self.assertEqual(2, first['receipt']['total'])
        second = rp.cutover_step(self.db, 'B1', retire=1, activate=1)
        self.assertEqual((0, 2), (second['receipt']['source_active'],
                                  second['receipt']['target_active']))
        done = rp.complete_cutover(self.db, 'B1')
        self.assertEqual('cutover_completed', done['decision'])

    def test_source_service_runs_until_target_accepted(self):
        self.hosted_ready()
        self.source_leases(2)
        # Cutover cannot even start while acceptance is blocked.
        rp.set_layer_online(self.db, 'layer-1', False)
        self.assertEqual('target_not_accepted',
                         rp.begin_cutover(self.db, 'B1')['decision'])
        active = self.db.execute(
            "SELECT COUNT(*) AS n FROM leases WHERE status='active'").fetchone()
        self.assertEqual(2, active['n'])

    # -- 8. late source lease renewal ---------------------------------------

    def test_late_lease_renewal_rejected_during_and_after_cutover(self):
        self.hosted_ready()
        rp.run_trials(self.db, 'B1')
        rp.accept_target(self.db, 'B1')
        self.source_leases(1)
        # Before cutover a normal renewal is fine.
        self.assertEqual('lease_renewed',
                         rp.renew_source_lease(self.db, 'B1', 'lease-0',
                                               2000)['decision'])
        rp.begin_cutover(self.db, 'B1')
        late = rp.renew_source_lease(self.db, 'B1', 'lease-0', 3000)
        self.assertEqual('late_renewal_rejected', late['decision'])
        # The late renewal never extended the lease; the receipt marks why.
        self.assertEqual('late_renewal_rejected', late['receipt']['note'])
        self.assertEqual(2000, self.db.execute(
            "SELECT expires FROM leases WHERE id='lease-0'").fetchone()['expires'])

    # -- 9. failure rollback with real traffic attribution ------------------

    def test_rollback_restores_source_and_keeps_traffic_evidence(self):
        self.hosted_ready()
        rp.run_trials(self.db, 'B1')
        rp.accept_target(self.db, 'B1')
        self.source_leases(2)
        rp.begin_cutover(self.db, 'B1')
        rp.cutover_step(self.db, 'B1', retire=1, activate=1)
        # Real customer results land on both sides during the window.
        rp.source_request(self.db, 'B1', 'approved', at=10)
        rp.source_request(self.db, 'B1', 'unapproved', at=11)
        rp.target_request(self.db, 'B1', 'approved', at=12)
        rp.target_request(self.db, 'B1', 'unapproved', at=13)
        result = rp.rollback(self.db, 'RB1', 'B1', 'target_node_failure',
                             at=20)
        self.assertEqual('rolled_back', result['decision'])
        self.assertEqual(1, result['source_served'])
        self.assertEqual(1, result['target_served'])
        self.assertEqual(4, len(result['customer_results']))
        self.assertEqual('source', result['restored_side'])
        # The retired source lease is a real active lease again.
        active = self.db.execute(
            "SELECT COUNT(*) AS n FROM leases WHERE status='active'").fetchone()
        self.assertEqual(2, active['n'])
        # Target-side capability is really destroyed and grants revoked.
        wl = rp._workload(self.db, 'B1')
        self.assertEqual('destroyed', wl['state'])
        self.assertEqual(0, wl['running_replicas'])
        self.assertEqual('workload_destroyed',
                         rp.evaluate_egress(self.db, 'B1',
                                           'approved')['decision'])
        grants = self.db.execute(
            "SELECT DISTINCT status FROM secret_grants").fetchall()
        self.assertEqual(['revoked'], [g['status'] for g in grants])
        stored = self.db.execute(
            "SELECT * FROM rollback_records WHERE id='RB1'").fetchone()
        self.assertEqual('target_node_failure', stored['reason'])

    def test_rollback_cannot_be_recorded_twice(self):
        self.hosted_ready()
        rp.run_trials(self.db, 'B1')
        rp.accept_target(self.db, 'B1')
        rp.rollback(self.db, 'RB1', 'B1', 'first')
        self.assertEqual('rollback_already_recorded',
                         rp.rollback(self.db, 'RB2', 'B1', 'second')['decision'])


if __name__ == '__main__':
    unittest.main()
