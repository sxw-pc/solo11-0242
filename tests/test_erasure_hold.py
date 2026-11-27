"""Acceptance: real erasure of customer bytes, minimal judicial hold,
two lawful custody paths, distinct completion facts and replayable proof.

Run from the repository root:

    python -B -m unittest discover -s tests -q
"""
import json
import tempfile
import unittest
from pathlib import Path

from imagecourt import retention
from imagecourt.store import connect, execute, one, replay, rows

ROOT = Path(__file__).resolve().parents[1]
DIGEST_D = 'sha256:' + 'd0' * 32
TENANT_A = 'customer-a'
TENANT_B = 'customer-b'
COPY1 = 'copy-d-site1'
COPY2 = 'copy-d-site2'
TRACE_TEXT = ("D0-TRACE <<COURT-TRACE-D0-accident-diagnostic>> "
              "minimal incident trajectory 0123456789 ")
LAWFUL_B = ('TENANT-B-LAWFUL same digest other customer copy '
            'LAWFUL-B-55667788')
SECRETS = ['SECRET-SAMPLE-ALPHA-7f3a9c21', 'SECRET-SAMPLE-BETA-9b2c4e77']
WIPE_BYTE = 1


class ErasureHoldCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'state.sqlite')
        self.escrow_dir = str(Path(self.tmp.name) / 'escrow')
        self.db = connect(self.path)
        self.fixture = json.loads(
            (ROOT / 'fixtures' / 'erasure_hold_multisite.json').read_text(encoding='utf-8'))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def load_world(self):
        decisions = []
        for entry in self.fixture:
            x = {k: v for k, v in entry.items() if k != 'subsystem'}
            decisions.append(execute(self.db, entry['subsystem'], x)['decision'])
        return decisions

    def original_payload(self):
        return one(self.db, 'SELECT payload FROM artifact_copies WHERE id=?', (COPY1,))['payload']

    def trace_range(self):
        seg = one(self.db,
                  "SELECT start_off,end_off FROM artifact_segments "
                  "WHERE id=? AND seg_key='seg-trace'", (f'{COPY1}:seg-trace',))
        return seg['start_off'], seg['end_off']

    def order(self, oid='ord-1', mode='isolated_custody', **extra):
        cmd = {'op': 'court_order', 'id': oid, 'tenant': TENANT_A, 'digest': DIGEST_D,
               'signer': 'judge.a@court.example', 'at': 20,
               'matter': 'D0 incident, docket 2026-CV-0091',
               'segments': ['seg-trace'], 'mode': mode, 'case_ref': '2026-CV-0091'}
        cmd.update(extra)
        return execute(self.db, 'retention', cmd)

    def erase(self, rid='erase-1', **extra):
        cmd = {'op': 'erase', 'id': rid, 'tenant': TENANT_A, 'digest': DIGEST_D, 'at': 21}
        cmd.update(extra)
        return execute(self.db, 'retention', cmd)

    def fulfill(self, rid='erase-1', fid='fulfill-1', at=22, **extra):
        cmd = {'op': 'fulfill', 'id': fid, 'request_id': rid, 'at': at}
        cmd.update(extra)
        return execute(self.db, 'retention', cmd)

    def replay_live(self):
        """Replay into an open in-memory DB so the replayed state can be audited."""
        source = connect(self.path)
        events = rows(source, 'SELECT subsystem,payload FROM events ORDER BY seq')
        target = connect(':memory:')
        for item in events:
            execute(target, item['subsystem'], json.loads(item['payload']))
        source.close()
        return target

    def assert_replay_verified_and_clean(self, extra_needles=()):
        needles = [*SECRETS, *extra_needles]
        # The live source log/tables must already be clean.
        self.assertEqual(retention.scan_needles(self.db, needles), {})
        result = replay(self.path)
        self.assertTrue(result['verified'], json.dumps(result, ensure_ascii=False)[:2000])
        serialized = json.dumps(result, ensure_ascii=False)
        for needle in needles:
            self.assertNotIn(needle, serialized, 'secret leaked into replay result')
        target = self.replay_live()
        try:
            hits = retention.scan_needles(target, needles)
            self.assertEqual(hits, {}, f'payload resurrected during replay: {hits}')
        finally:
            target.close()
        return result

    def assert_production_all_wiped(self, payload):
        original = payload.encode('utf-8')
        view = retention.production_view(self.db, TENANT_A, DIGEST_D)
        # two site copies + two caches + one running-workload physical image
        self.assertEqual(sorted(v['kind'] for v in view),
                         ['cache', 'cache', 'runtime', 'site_copy', 'site_copy'])
        for loc in view:
            raw = (loc['payload'] or '').encode('utf-8')
            self.assertEqual(len(raw), len(original), loc['id'])
            self.assertTrue(raw and all(b == WIPE_BYTE for b in raw),
                            f'{loc["kind"]}:{loc["id"]} not physically overwritten')
            self.assertNotIn('COURT-TRACE-D0', loc['payload'] or '')


class CourtOrderValidation(ErasureHoldCase):
    def test_order_locks_signer_time_matter_and_minimal_byte_range(self):
        self.load_world()
        start, end = self.trace_range()
        self.assertEqual(end - start, len(TRACE_TEXT))

        ok = self.order()
        self.assertEqual(ok['decision'], 'hold_recorded')
        self.assertEqual(ok['ranges'], [[start, end]])
        self.assertEqual(ok['minimal_bytes'], len(TRACE_TEXT))

        stored = one(self.db, 'SELECT * FROM preservation_orders WHERE id=?', ('ord-1',))
        self.assertEqual(stored['signer'], 'judge.a@court.example')
        self.assertEqual(stored['issued_at'], 20)
        self.assertIn('2026-CV-0091', stored['matter'])
        self.assertEqual(json.loads(stored['ranges_json']), [[start, end]])
        self.assertEqual(stored['status'], 'active')

    def test_incomplete_orders_are_rejected(self):
        self.load_world()
        cases = [
            ({'signer': None}, 'missing_signer'),
            ({'at': None}, 'missing_time'),
            ({'matter': None}, 'missing_matter'),
            ({'segments': [], 'ranges': []}, 'empty_hold_range'),
            ({'segments': ['does-not-exist']}, 'empty_hold_range'),
            ({'ranges': [[0, 10_000_000]]}, 'range_out_of_bounds'),
        ]
        for i, (mutation, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                cmd = {'op': 'court_order', 'id': f'bad-{i}', 'tenant': TENANT_A,
                       'digest': DIGEST_D, 'signer': 'j', 'at': 1, 'matter': 'm',
                       'segments': ['seg-trace']}
                cmd.update(mutation)
                cmd = {k: v for k, v in cmd.items() if v is not None}
                result = execute(self.db, 'retention', cmd)
                self.assertEqual(result['decision'], 'invalid_order')
                self.assertIn(reason, result['reasons'])
                self.assertIsNone(
                    one(self.db, 'SELECT id FROM preservation_orders WHERE id=?',
                        (f'bad-{i}',)))


class IsolatedCustodyTests(ErasureHoldCase):
    def test_minimal_trace_retained_in_isolated_custody_everything_else_burned(self):
        self.load_world()
        payload = self.original_payload()
        start, end = self.trace_range()
        self.assertEqual(payload[start:end], TRACE_TEXT)
        # The old lease is unexpired and still marked active/running.
        self.assertEqual(one(self.db, "SELECT status FROM leases WHERE id='lease-d-old'")['status'],
                         'active')
        self.assertEqual(one(self.db, "SELECT status FROM workloads WHERE id='workload-d-old'")
                         ['status'], 'running')

        self.assertEqual(self.order()['decision'], 'hold_recorded')
        self.erase()
        result = self.fulfill()

        self.assertEqual(result['decision'], 'erasure_completed', result)
        self.assertEqual(result['certificate_status'], 'complete')
        self.assertEqual(sorted(result['physical_completed']),
                         ['cache-d-site1', 'cache-d-site2', COPY1, COPY2,
                          'runtime-d-old-lease'])
        self.assertEqual(sorted(result['backups_destroyed']),
                         ['backup-d-region1', 'backup-d-region2'])

        # --- verbatim physical erasure at every site/cache/runtime ------
        self.assert_production_all_wiped(payload)
        # The unexpired lease was not used to hide anything: bytes are gone.
        rt = one(self.db, 'SELECT state,payload FROM runtime_artifacts WHERE id=?',
                 ('runtime-d-old-lease',))
        self.assertEqual(rt['state'], 'purged')
        self.assertTrue(all(b == WIPE_BYTE for b in rt['payload'].encode()))

        # --- backups are physically discharged --------------------------
        for bid in ('backup-d-region1', 'backup-d-region2'):
            row = one(self.db, 'SELECT state,payload FROM artifact_backups WHERE id=?', (bid,))
            self.assertEqual(row['state'], 'destroyed')
            self.assertIsNone(row['payload'])

        # --- other customer's lawful same-digest copy is untouched ------
        b = one(self.db, 'SELECT payload FROM artifact_copies WHERE id=?', ('copy-b-site1',))
        self.assertEqual(b['payload'], LAWFUL_B)

        # --- exactly the minimal slice survives, sealed in custody ------
        items = rows(self.db, "SELECT * FROM custody_items WHERE order_id='ord-1'")
        self.assertEqual(len(items), 1)
        self.assertEqual((items[0]['start_off'], items[0]['end_off']), (start, end))
        self.assertEqual(items[0]['status'], 'sealed')
        self.assertNotEqual(items[0]['sealed_blob'], TRACE_TEXT)  # ciphertext at rest
        key = one(self.db, 'SELECT * FROM custody_keys WHERE order_id=?', ('ord-1',))
        self.assertEqual(key['status'], 'active')
        self.assertTrue(key['custodian'] and key['key_ref'] and key['fingerprint'])
        order_row = one(self.db, 'SELECT custodian,key_ref,purpose FROM preservation_orders '
                                 "WHERE id='ord-1'")
        self.assertIn('isolated', order_row['custodian'])
        self.assertTrue(order_row['purpose'])

        access = execute(self.db, 'retention',
                         {'op': 'access_custody', 'id': 'access-1', 'order_id': 'ord-1',
                          'item_id': items[0]['id'], 'at': 23,
                          'accessor': 'clerk.b@court.example',
                          'purpose': 'respond to docket 2026-CV-0091 retrieval'})
        self.assertEqual(access['decision'], 'custody_access_logged')
        opened = retention.read_custody(self.db, 'access-1')
        self.assertEqual(opened, TRACE_TEXT)
        self.assertEqual(opened, payload[start:end])
        self.assertFalse(any(s in opened for s in SECRETS))
        log = one(self.db, 'SELECT accessor,purpose,result FROM custody_access WHERE id=?',
                  ('access-1',))
        self.assertEqual(log['result'], 'granted')
        self.assertIn('2026-CV-0091', log['purpose'])

        # --- customer certificate explicitly discloses retention --------
        cert = one(self.db, 'SELECT * FROM erasure_certificates WHERE request_id=?', ('erase-1',))
        self.assertEqual(cert['status'], 'complete')
        self.assertEqual(cert['mode'], 'isolated_custody')
        retained = json.loads(cert['retained_json'])
        self.assertEqual(retained['ranges'], [[start, end]])
        self.assertEqual(retained['minimal_bytes'], end - start)
        self.assertEqual(retained['order'], 'ord-1')
        self.assertTrue(retained['custodian'] and retained['key_ref'])
        receipt = one(self.db, 'SELECT status FROM customer_receipts WHERE request_id=?',
                      ('erase-1',))
        self.assertEqual(receipt['status'], 'issued')

        # Physical purge, backup discharge, judicial extraction and customer
        # receipt are four separately recorded facts.
        kinds = {r['kind'] for r in rows(
            self.db, "SELECT DISTINCT kind FROM erasure_facts WHERE request_id='erase-1'")}
        self.assertEqual(kinds, {'physical', 'backup', 'judicial', 'receipt'})
        physical = rows(self.db,
                        "SELECT target_id,status FROM erasure_facts "
                        "WHERE request_id='erase-1' AND kind='physical' ORDER BY target_id")
        self.assertEqual([r['target_id'] for r in physical],
                         ['cache-d-site1', 'cache-d-site2', COPY1, COPY2,
                          'runtime-d-old-lease'])
        self.assertTrue(all(r['status'] == 'completed' for r in physical))

        # --- no customer bytes in SQL-visible logs/tables --------------
        self.assertEqual(retention.scan_needles(self.db, SECRETS), {})
        self.assertEqual(retention.scan_needles(self.db, [payload]), {})

        # --- replay must verify and must not resurrect anything ----------
        result = self.assert_replay_verified_and_clean(extra_needles=[payload])
        self.assertGreaterEqual(result['redactions'], 5)
        self.assertTrue(result['history_verified'])


class ExternalEscrowTests(ErasureHoldCase):
    def test_trace_goes_to_independent_escrow_platform_gets_zero_retention(self):
        self.load_world()
        payload = self.original_payload()
        start, end = self.trace_range()
        self.order(oid='ord-ext', mode='external_escrow')
        self.erase(rid='erase-ext')
        result = self.fulfill(rid='erase-ext', fid='ful-ext',
                              escrow='escrow-court', escrow_dir=self.escrow_dir)
        self.assertEqual(result['decision'], 'erasure_completed', result)
        self.assertEqual(result['mode'], 'zero_retention_external_escrow')

        # The external托管 received the verbatim minimal slice.
        files = list(Path(self.escrow_dir).glob('*.json'))
        self.assertEqual(len(files), 1)
        delivered = json.loads(files[0].read_text(encoding='utf-8'))
        self.assertEqual(delivered['content'], payload[start:end])
        self.assertEqual(delivered['content'], TRACE_TEXT)

        # Platform keeps no sealed custody item and wipes every physical byte.
        self.assertEqual(rows(self.db, "SELECT id FROM custody_items WHERE status='sealed'"), [])
        self.assert_production_all_wiped(payload)
        for bid in ('backup-d-region1', 'backup-d-region2'):
            self.assertIsNone(
                one(self.db, 'SELECT payload FROM artifact_backups WHERE id=?', (bid,))['payload'])

        cert = one(self.db, 'SELECT * FROM erasure_certificates WHERE request_id=?',
                   ('erase-ext',))
        self.assertEqual(cert['status'], 'complete')
        self.assertEqual(cert['mode'], 'zero_retention_external_escrow')
        retained = json.loads(cert['retained_json'])
        self.assertIn('escrow', retained['destination'])
        self.assertEqual(retained['ranges'], [[start, end]])
        # Only a non-reversible commitment stays on the platform ledger.
        extraction = one(self.db, 'SELECT status,receipt,commitment FROM judicial_extractions')
        self.assertEqual(extraction['status'], 'delivered')
        self.assertTrue(extraction['receipt'] and extraction['commitment'])

        self.assertEqual(retention.scan_needles(self.db, SECRETS + [TRACE_TEXT, payload]), {})
        self.assert_replay_verified_and_clean(extra_needles=[TRACE_TEXT, payload])

    def test_escrow_unreachable_blocks_certificate_then_delivery_recovers(self):
        self.load_world()
        payload = self.original_payload()
        self.order(oid='ord-u', mode='external_escrow')
        self.erase(rid='erase-u')
        failed = self.fulfill(rid='erase-u', fid='ful-u', escrow='escrow-court',
                              escrow_unreachable=True)
        self.assertEqual(failed['decision'], 'erasure_incomplete')
        self.assertEqual(failed['judicial'], 'escrow_unreachable')
        self.assertTrue(any(b['gate'] == 'judicial' for b in failed['blockers']))
        self.assertIsNone(
            one(self.db, "SELECT id FROM erasure_certificates WHERE status='complete'"))
        extraction = one(self.db, 'SELECT status,reason FROM judicial_extractions')
        self.assertEqual((extraction['status'], extraction['reason']),
                         ('failed', 'escrow_unreachable'))
        # Safety fallback preserves the minimal slice as pending sealed custody
        # while still allowing all production bytes to be purged.
        pending = rows(self.db, "SELECT id FROM custody_items WHERE status='pending_escrow'")
        self.assertEqual(len(pending), 1)
        self.assert_production_all_wiped(payload)
        # Even in the failed state the log is redacted and replay verifies.
        self.assert_replay_verified_and_clean()

        recovered = execute(self.db, 'retention',
                            {'op': 'deliver_escrow', 'id': 'deliver-u',
                             'request_id': 'erase-u', 'order_id': 'ord-u', 'at': 24,
                             'escrow': 'escrow-court', 'escrow_dir': self.escrow_dir})
        self.assertEqual(recovered['decision'], 'extracted_to_escrow', recovered)
        self.assertEqual(recovered['certificate_status'], 'complete')
        files = list(Path(self.escrow_dir).glob('*.json'))
        self.assertEqual(len(files), 1)
        self.assertEqual(json.loads(files[0].read_text(encoding='utf-8'))['content'],
                         TRACE_TEXT)
        self.assertIsNone(
            one(self.db, "SELECT sealed_blob FROM custody_items WHERE status='transferred'")
            ['sealed_blob'])
        self.assert_replay_verified_and_clean(extra_needles=[TRACE_TEXT])


class PartialFailureTests(ErasureHoldCase):
    def test_partial_purge_failure_blocks_then_retry_completes(self):
        self.load_world()
        payload = self.original_payload()
        self.order()
        self.erase()
        partial = self.fulfill(faults={COPY2: 'site2 disk io error'})
        self.assertEqual(partial['decision'], 'erasure_incomplete')
        self.assertEqual([f['id'] for f in partial['physical_failed']], [COPY2])
        self.assertTrue(any(b['target'] == COPY2 for b in partial['blockers']))
        self.assertIsNone(
            one(self.db, "SELECT id FROM erasure_certificates WHERE status='complete'"))

        # The failed actual copy keeps its raw bytes; the others are burned.
        self.assertEqual(
            one(self.db, 'SELECT payload FROM artifact_copies WHERE id=?', (COPY2,))['payload'],
            payload)
        self.assertTrue(all(b == 1 for b in
                            one(self.db, 'SELECT payload FROM artifact_copies WHERE id=?',
                                (COPY1,))['payload'].encode()))
        failed_fact = one(self.db,
                          "SELECT status FROM erasure_facts WHERE target_id=? AND kind='physical'",
                          (COPY2,))
        self.assertEqual(failed_fact['status'], 'failed')
        # Failed state itself must replay faithfully.
        result = replay(self.path)
        self.assertTrue(result['verified'], result)

        retry = self.fulfill(fid='fulfill-retry', at=30)
        self.assertEqual(retry['decision'], 'erasure_completed', retry)
        self.assertEqual(retry['certificate_status'], 'complete')
        self.assertTrue(all(b == 1 for b in
                            one(self.db, 'SELECT payload FROM artifact_copies WHERE id=?',
                                (COPY2,))['payload'].encode()))
        self.assertIsNotNone(
            one(self.db, "SELECT id FROM erasure_certificates WHERE status='complete'"))
        self.assert_replay_verified_and_clean(extra_needles=[payload])


class RevocationTests(ErasureHoldCase):
    def test_revocation_only_disposes_actually_retained_slice(self):
        self.load_world()
        payload = self.original_payload()
        start, end = self.trace_range()
        self.order()
        self.erase()
        self.fulfill()
        access = execute(self.db, 'retention',
                         {'op': 'access_custody', 'id': 'access-before', 'order_id': 'ord-1',
                          'at': 23, 'accessor': 'clerk', 'purpose': 'court access'})
        self.assertEqual(retention.read_custody(self.db, 'access-before'), TRACE_TEXT)

        revoked = execute(self.db, 'retention',
                          {'op': 'revoke_hold', 'id': 'revoke-1', 'order_id': 'ord-1', 'at': 40})
        self.assertEqual(revoked['decision'], 'hold_revoked')
        self.assertEqual(revoked['destroyed_custody_items'], ['custody:ord-1:0'])
        self.assertEqual(one(self.db, "SELECT status FROM preservation_orders WHERE id='ord-1'")
                         ['status'], 'revoked')
        item = one(self.db, "SELECT status,sealed_blob FROM custody_items WHERE id='custody:ord-1:0'")
        self.assertEqual(item['status'], 'destroyed')
        self.assertIsNone(item['sealed_blob'])
        self.assertEqual(one(self.db, "SELECT status FROM custody_keys WHERE order_id='ord-1'")
                         ['status'], 'destroyed')

        denied = execute(self.db, 'retention',
                         {'op': 'access_custody', 'id': 'access-after', 'order_id': 'ord-1',
                          'at': 41, 'accessor': 'clerk', 'purpose': 'curiosity'})
        self.assertEqual(denied['decision'], 'custody_denied')
        self.assertIsNone(retention.read_custody(self.db, 'access-after'))

        # Neither the trace nor the erased samples survive anywhere, including
        # old events; nothing can be rebuilt by replay.
        self.assertEqual(retention.scan_needles(self.db, [TRACE_TEXT, payload, *SECRETS]), {})
        result = self.assert_replay_verified_and_clean(extra_needles=[TRACE_TEXT, payload])
        target = self.replay_live()
        try:
            rows_left = rows(target, "SELECT sealed_blob,status FROM custody_items")
            self.assertTrue(all(r['sealed_blob'] is None for r in rows_left))
        finally:
            target.close()
        self.assertTrue(result['verified'])

        again = execute(self.db, 'retention',
                        {'op': 'revoke_hold', 'id': 'revoke-2', 'order_id': 'ord-1', 'at': 42})
        self.assertEqual(again['decision'], 'reused')

    def test_revocation_cannot_exceed_locked_range(self):
        self.load_world()
        self.order()
        self.erase()
        self.fulfill()
        out = execute(self.db, 'retention',
                      {'op': 'revoke_hold', 'id': 'revoke-bad', 'order_id': 'ord-1', 'at': 40,
                       'ranges': [{'start': 0, 'end': 72}]})
        self.assertEqual(out['decision'], 'range_exceeds_hold')
        self.assertEqual(one(self.db, "SELECT status FROM preservation_orders WHERE id='ord-1'")
                         ['status'], 'active')


class DuplicateRequestTests(ErasureHoldCase):
    def test_duplicate_customer_requests_and_repeated_fulfillment_are_idempotent(self):
        self.load_world()
        first = self.erase('erase-dup')
        self.assertEqual(first['decision'], 'erase_requested')
        duplicate = self.erase('erase-dup')
        self.assertEqual(duplicate['decision'], 'reused')
        self.assertTrue(duplicate['duplicate'])

        k1 = self.erase('erase-key-1', idempotency_key='customer-click-77')
        k2 = self.erase('erase-key-2', idempotency_key='customer-click-77')
        self.assertEqual(k1['decision'], 'erase_requested')
        self.assertEqual(k2['decision'], 'reused')
        self.assertEqual(k2['original_request'], 'erase-key-1')

        count = one(self.db, 'SELECT COUNT(*) AS n FROM erase_requests')['n']
        self.assertEqual(count, 2)  # erase-dup + erase-key-1 only

        self.order(oid='ord-dup')
        done1 = self.fulfill(rid='erase-dup', fid='ful-1')
        done2 = self.fulfill(rid='erase-dup', fid='ful-2', at=23)
        self.assertEqual(done1['certificate_status'], 'complete')
        self.assertEqual(done2['decision'], 'erasure_completed')
        self.assertEqual(
            one(self.db, 'SELECT COUNT(*) AS n FROM erasure_certificates WHERE request_id=?',
                ('erase-dup',))['n'], 1)
        # Deterministic fact ids mean repeated fulfillment adds no duplicates.
        fact_count = one(self.db,
                         "SELECT COUNT(*) AS n FROM erasure_facts WHERE request_id='erase-dup' "
                         "AND kind='physical'")['n']
        self.assertEqual(fact_count, 5)
        self.assert_replay_verified_and_clean()

    def test_erase_can_fulfill_in_one_call_when_requested(self):
        self.load_world()
        self.order(oid='ord-one')
        out = self.erase('erase-one', fulfill=True)
        self.assertEqual(out['decision'], 'erasure_completed', out)
        self.assertEqual(out['certificate_status'], 'complete')
        self.assertIsNotNone(
            one(self.db, "SELECT id FROM erasure_certificates WHERE request_id='erase-one' "
                         "AND status='complete'"))
        self.assert_replay_verified_and_clean()


class ScopeTests(ErasureHoldCase):
    def test_copy_id_scope_leaves_other_site_and_tenant_untouched(self):
        self.load_world()
        payload = self.original_payload()
        self.erase('erase-one-site', copy_ids=[COPY1])
        purge = execute(self.db, 'retention',
                        {'op': 'purge', 'id': 'purge-1', 'request_id': 'erase-one-site', 'at': 22})
        self.assertEqual(purge['decision'], 'physical_purged')
        self.assertIn(COPY1, purge['completed'])
        self.assertNotIn(COPY2, purge['completed'])

        self.assertTrue(all(b == 1 for b in
                            one(self.db, 'SELECT payload FROM artifact_copies WHERE id=?',
                                (COPY1,))['payload'].encode()))
        self.assertEqual(
            one(self.db, 'SELECT payload FROM artifact_copies WHERE id=?', (COPY2,))['payload'],
            payload)
        self.assertEqual(
            one(self.db, 'SELECT payload FROM artifact_caches WHERE id=?',
                ('cache-d-site2',))['payload'], payload)
        self.assertEqual(
            one(self.db, 'SELECT payload FROM artifact_copies WHERE id=?',
                ('copy-b-site1',))['payload'], LAWFUL_B)
        # Out-of-scope bytes intentionally survive, so only assert that replay
        # preserves the exact scope boundary (not global absence).
        result = replay(self.path)
        self.assertTrue(result['verified'], result)
        live = self.replay_live()
        try:
            self.assertTrue(all(b == 1 for b in
                                one(live, 'SELECT payload FROM artifact_copies WHERE id=?',
                                    (COPY1,))['payload'].encode()))
            self.assertEqual(
                one(live, 'SELECT payload FROM artifact_copies WHERE id=?',
                    (COPY2,))['payload'], payload)
            self.assertEqual(
                one(live, 'SELECT payload FROM artifact_copies WHERE id=?',
                    ('copy-b-site1',))['payload'], LAWFUL_B)
        finally:
            live.close()

    def test_category_scope_is_verbatim_and_surgical(self):
        db = self.db
        execute(db, 'provenance',
                {'op': 'manifest', 'digest': 'sha256:cat', 'tag': 'cat', 'batch': 'b',
                 'generation': 1})
        sample1 = 'sample-one SECRET-CAT-AAAA '
        trace = 'diagnostic KEEP-TRACE-7777 '
        sample2 = 'sample-two SECRET-CAT-BBBB'
        execute(db, 'retention', {
            'op': 'copy', 'id': 'copy-cat', 'digest': 'sha256:cat', 'tenant': 't',
            'site': 's',
            'segments': [
                {'id': 'g1', 'category': 'test_samples', 'text': sample1},
                {'id': 'tr', 'category': 'incident_trace', 'text': trace},
                {'id': 'g2', 'category': 'test_samples', 'text': sample2}]})
        original = sample1 + trace + sample2
        execute(db, 'retention',
                {'op': 'erase', 'id': 'erase-cat', 'tenant': 't', 'digest': 'sha256:cat',
                 'at': 1, 'categories': ['test_samples']})
        out = execute(db, 'retention',
                      {'op': 'purge', 'id': 'purge-cat', 'request_id': 'erase-cat', 'at': 2})
        self.assertEqual(out['decision'], 'physical_purged')
        after = one(db, 'SELECT payload FROM artifact_copies WHERE id=?', ('copy-cat',))['payload']
        ob, ab = original.encode(), after.encode()
        self.assertEqual(len(ab), len(ob))
        t0, t1 = len(sample1.encode()), len((sample1 + trace).encode())
        # sample categories overwritten byte-for-byte ...
        self.assertTrue(all(b == 1 for b in ab[:t0]))
        self.assertTrue(all(b == 1 for b in ab[t1:]))
        # ... while the un-targeted trace survives verbatim at its offsets.
        self.assertEqual(ab[t0:t1].decode(), trace)
        self.assertNotIn('SECRET-CAT-AAAA', after)
        self.assertNotIn('SECRET-CAT-BBBB', after)
        self.assertIn('KEEP-TRACE-7777', after)
        result = replay(self.path)
        self.assertTrue(result['verified'], result)


class LegacyCommandReplayTests(ErasureHoldCase):
    def test_seeded_commands_still_replay_and_fulfillment_purges_resurrection(self):
        db = self.db
        execute(db, 'provenance',
                 {'op': 'manifest', 'digest': 'sha256:demo', 'tag': 'demo:1',
                  'batch': 'batch', 'generation': 1})
        raw = 'synthetic-client-byte SECRET-LEGACY-0001'
        self.assertEqual(execute(db, 'retention', {
            'op': 'copy', 'id': 'copy-a', 'digest': 'sha256:demo', 'tenant': 'tenant-a',
            'site': 'site-a', 'payload': raw})['decision'], 'copy_recorded')
        self.assertEqual(execute(db, 'retention', {
            'op': 'hold', 'id': 'hold-a', 'tenant': 'tenant-a', 'digest': 'sha256:demo',
            'scope': 'case-a'})['decision'], 'hold_recorded')
        self.assertEqual(execute(db, 'retention', {
            'op': 'erase', 'id': 'erase-a', 'tenant': 'tenant-a', 'digest': 'sha256:demo',
            'at': 5})['copies'], 1)
        # At the request-only stage the old event honestly regenerates payload.
        early = replay(self.path)
        self.assertTrue(early['verified'], early)
        live = self.replay_live()
        self.assertEqual(one(live, 'SELECT payload FROM artifact_copies WHERE id=?',
                             ('copy-a',))['payload'], raw)
        live.close()

        done = self.fulfill(rid='erase-a', fid='ful-a', at=6)
        self.assertEqual(done['decision'], 'erasure_completed', done)
        self.assertEqual(retention.scan_needles(db, [raw, 'SECRET-LEGACY-0001']), {})
        final = replay(self.path)
        self.assertTrue(final['verified'], final)
        again = self.replay_live()
        try:
            row = one(again, 'SELECT payload FROM artifact_copies WHERE id=?', ('copy-a',))
            self.assertTrue(row['payload'] and all(b == 1 for b in row['payload'].encode()))
            self.assertEqual(
                retention.scan_needles(again, [raw, 'SECRET-LEGACY-0001']), {})
        finally:
            again.close()


if __name__ == '__main__':
    unittest.main()
