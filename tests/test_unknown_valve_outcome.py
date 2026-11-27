import json
import tempfile
import unittest
from pathlib import Path

from imagecourt.cooling import Plant
from imagecourt.store import connect, execute, one, replay, rows
ROOT = Path(__file__).resolve().parents[1]
FIXTURES = {
    'before_act': ROOT / 'fixtures' / 'valve_unknown_before_act.json',
    'after_act': ROOT / 'fixtures' / 'valve_unknown_after_act.json',
}


class UnknownValveOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'unknown_valve.sqlite'
        self.db = connect(str(self.path))
        # 批次 B 的镜像清单（provenance 事实），两个物理世界共用同一提交未知原件。
        execute(self.db, 'provenance', {'op': 'manifest', 'digest': 'sha256:b-hot',
                                        'tag': 'batch-b:hot', 'batch': 'batch-b',
                                        'generation': 1})

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def _load(self, world):
        events = json.loads(FIXTURES[world].read_text(encoding='utf-8'))
        results = [execute(self.db, 'cooling', x) for x in events]
        return events, results

    def _drive_plant(self, plant):
        """用物理装置重放同一时间线：一次真实驱动、一次重启、三次独立见证读数。"""
        outcome = plant.controller.attempt('V', 'recirculate', 4)
        plant.controller.restart(6)
        readings = {at: plant.observe(at) for at in (7, 8, 9)}
        return outcome, readings

    def _hydrology_matches_plant(self, reading):
        # 数据库登记的独立见证读数必须与物理装置探头一致，不允许由裁决侧编造。
        rows_ = rows(self.db, "SELECT * FROM hydrology_observations WHERE at=? ORDER BY point",
                     (reading['at'],))
        self.assertEqual({r['point']: (r['level'], r['flow'], r['temperature']) for r in rows_},
                         {'pool': (reading['pool_level'], 0,
                                   35 if reading['pool_level'] is not None else None),
                          'outfall': (None, reading['outfall_flow'],
                                      reading['outfall_temperature'])})

    def _adjudication(self, adjudication_id):
        return one(self.db, 'SELECT * FROM discharge_adjudications WHERE id=?',
                   (adjudication_id,))

    # ------------------------------------------------------------------
    # 物理世界一：控制器动作前断线，阀从未换位，热水实际流出厂界。
    # ------------------------------------------------------------------
    def test_world_before_act_discharged_is_never_rewritten(self):
        events, results = self._load('before_act')
        plant = Plant('before_act')
        outcome, readings = self._drive_plant(plant)

        # 动作前断线：没有换位、没有持久接收痕迹，外部动作只发生一次。
        self.assertEqual(outcome, {'ack': False, 'moved': False, 'persisted': False})
        self.assertEqual(plant.attempts(), 1)
        self.assertEqual(readings[7]['valve'], 'drain')
        self.assertEqual(readings[8]['valve'], 'drain')
        self.assertEqual(readings[9]['valve'], 'drain')
        for at in (7, 8, 9):
            self._hydrology_matches_plant(readings[at])

        # t=7：两物理世界证据相同，裁决必须承认无法判定，而不是照抄 sent。
        self.assertEqual(self._adjudication('adj-7')['verdict'], 'outcome_unknown')
        self.assertEqual(self._adjudication('adj-7')['valve_state'], 'unobserved')
        # t=8：独立阀位见证与意图相悖；t=9：厂界探头确认热水已流出厂界。
        self.assertEqual(self._adjudication('adj-8')['verdict'], 'discharged_confirmed')
        self.assertEqual(self._adjudication('adj-9')['verdict'], 'discharged_confirmed')
        self.assertEqual(self._adjudication('adj-9')['discharged'], 4)
        self.assertEqual(self._adjudication('adj-9')['retained'], 36)

        # 恢复走 hold：全新机械隔离意图，客户交付延期，水留在现场。
        recovery = one(self.db, "SELECT * FROM recovery_actions WHERE id='rec-1'")
        self.assertEqual(recovery['path'], 'hold')
        self.assertEqual(recovery['custodian'], 'on_site')
        self.assertEqual(recovery['delivery_at'], 30)
        self.assertIsNone(recovery['transfer_manifest'])
        # 外部动作 = 一次阀门驱动 + 一次机械隔离；全程没有重发 V。
        self.assertEqual(rows(self.db, "SELECT COUNT(*) AS c FROM external_actions")[0]['c'], 2)
        self.assertEqual(plant.attempts(), 1)

        meter = one(self.db, "SELECT * FROM permit_meters WHERE id='meter-1'")
        self.assertEqual(meter['discharged'], 4)
        self.assertEqual(meter['verdict'], 'within_permit')

        # 迟到的控制器声称不能把已流出厂界的水倒改成未排。
        late = next(r for r in results if r['decision'] == 'late_ack_supplementary')
        self.assertEqual(late['discharged'], 4)
        self.assertEqual(late['verdict'], 'discharged_confirmed')
        cert = one(self.db, "SELECT * FROM build_compliance WHERE id='cert-1'")
        self.assertEqual(cert['verdict'], 'certified_with_delivery_delay')

        # 重放只重现数据库裁决：物理装置的外部动作次数不增加。
        before = plant.attempts()
        report = replay(str(self.path))
        self.assertTrue(report['verified'], report)
        self.assertEqual(plant.attempts(), before)

    # ------------------------------------------------------------------
    # 物理世界二：阀已换位，回执在返回前丢失，热水全部留在池内。
    # ------------------------------------------------------------------
    def test_world_after_act_retained_water_not_counted_as_discharged(self):
        events, results = self._load('after_act')
        plant = Plant('after_act')
        outcome, readings = self._drive_plant(plant)

        # 动作后断线：阀已换位、持久痕迹在，但回执丢失；外部动作同样只发生一次。
        self.assertEqual(outcome, {'ack': False, 'moved': True, 'persisted': True})
        self.assertEqual(plant.attempts(), 1)
        self.assertEqual(readings[7]['valve'], 'recirculate')
        self.assertEqual(readings[8]['valve'], 'recirculate')
        self.assertEqual(readings[9]['valve'], 'recirculate')
        for at in (7, 8, 9):
            self._hydrology_matches_plant(readings[at])

        self.assertEqual(self._adjudication('adj-7')['verdict'], 'outcome_unknown')
        self.assertEqual(self._adjudication('adj-8')['verdict'], 'retained_probable')
        self.assertEqual(self._adjudication('adj-9')['verdict'], 'retained_probable')
        self.assertEqual(self._adjudication('adj-9')['discharged'], 0)
        self.assertEqual(self._adjudication('adj-9')['retained'], 42)

        # 移动闭环：供应商接管这批热水并留下实物转运原件，客户较早拿到镜像。
        recovery = one(self.db, "SELECT * FROM recovery_actions WHERE id='rec-1'")
        self.assertEqual(recovery['path'], 'mobile_closed_loop')
        self.assertEqual(recovery['custodian'], 'mcu-1')
        self.assertEqual(recovery['transfer_manifest'], 'paper-manifest-7')
        self.assertEqual(recovery['delivery_at'], 20)
        # 该路径不操作阀门：外部动作记录仍只有最初那一次。
        self.assertEqual(rows(self.db, "SELECT COUNT(*) AS c FROM external_actions")[0]['c'], 1)
        self.assertEqual(plant.attempts(), 1)

        meter = one(self.db, "SELECT * FROM permit_meters WHERE id='meter-1'")
        self.assertEqual(meter['discharged'], 0)
        self.assertEqual(meter['verdict'], 'within_permit')

        late = next(r for r in results if r['decision'] == 'late_ack_supplementary')
        self.assertEqual(late['discharged'], 0)
        cert = one(self.db, "SELECT * FROM build_compliance WHERE id='cert-1'")
        self.assertEqual(cert['verdict'], 'certified_external_custody')

        before = plant.attempts()
        report = replay(str(self.path))
        self.assertTrue(report['verified'], report)
        self.assertEqual(plant.attempts(), before)

    # ------------------------------------------------------------------
    # 控制器重启失去历史后，任何对结果未知意图的重发都必须被拒绝；
    # 给 intent 加 done 布尔或自动重试都无法判断先前动作，故网关只认真实证据。
    # ------------------------------------------------------------------
    def test_unknown_outcome_cannot_be_redispatched_after_restart(self):
        self._load('before_act')
        # 一个全新的、未派过单的阀门意图：代次 1 已随重启失效，仍被代次校验拦下。
        execute(self.db, 'cooling', {'op': 'valve', 'id': 'fresh-intent-1',
                                     'loop': 'loop-b', 'position': 'recirculate', 'at': 8})
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'dispatch', 'id': 'ea-retry-old-gen', 'intent': 'fresh-intent-1',
            'loop': 'loop-b', 'kind': 'valve', 'position': 'recirculate',
            'generation': 1, 'at': 8, 'witness': 'w-valve'})['decision'],
            'stale_controller_generation')
        # 重用 V 且使用新代次：V 已派过单，网关直接拒绝，绝不允许第二次驱动阀门。
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'dispatch', 'id': 'ea-retry-new-gen', 'intent': 'V', 'loop': 'loop-b',
            'kind': 'valve', 'position': 'recirculate', 'generation': 2, 'at': 8,
            'witness': 'w-valve'})['decision'], 'intent_already_dispatched')
        # 同要素的隔离派单是幂等重入（恢复路径内部会重入网关），不产生第二次动作。
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'dispatch', 'id': 'iso-b-action', 'intent': 'iso-b', 'loop': 'loop-b',
            'kind': 'mechanical_isolation', 'position': 'isolated',
            'generation': 2, 'at': 10, 'witness': 'w-mech'})['decision'],
            'external_action_dispatched')
        # 同一隔离意图改要素再派则被拒绝。
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'dispatch', 'id': 'ea-dup', 'intent': 'iso-b', 'loop': 'loop-b',
            'kind': 'mechanical_isolation', 'position': 'bypassed',
            'generation': 2, 'at': 11, 'witness': 'w-mech'})['decision'],
            'intent_already_dispatched')
        # 未派过单但已被裁决为结果未知的阀门意图，同样禁止盲目驱动实物。
        # 在独立回路里构造，避免复用 V 的厂界观测流。
        execute(self.db, 'cooling', {'op': 'loop', 'id': 'loop-c', 'site': 'site-a',
                                     'flow_limit': 100, 'temp_limit': 40})
        execute(self.db, 'cooling', {'op': 'permit', 'loop': 'loop-c', 'volume_limit': 50,
                                     'start': 0, 'expires': 100, 'temp_limit': 40})
        execute(self.db, 'cooling', {'op': 'controller_start', 'loop': 'loop-c',
                                     'at': 2, 'history_retained': False})
        execute(self.db, 'cooling', {'op': 'valve', 'id': 'V-other',
                                     'loop': 'loop-c', 'position': 'drain', 'at': 7})
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'adjudicate', 'id': 'adj-other', 'loop': 'loop-c',
            'intent': 'V-other', 'at': 8})['verdict'], 'outcome_unknown')
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'dispatch', 'id': 'ea-other', 'intent': 'V-other', 'loop': 'loop-c',
            'kind': 'valve', 'position': 'drain', 'generation': 1, 'at': 9,
            'witness': 'w-valve'})['decision'], 'unknown_outcome_redispatch_blocked')
        # 未被接受的见证不能为物理动作或实测背书。
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'hydrology', 'id': 'h-bad', 'loop': 'loop-b', 'at': 9,
            'point': 'outfall', 'level': None, 'flow': 9, 'temperature': 50,
            'witness': 'w-shadow'})['decision'], 'witness_not_accepted')

    def test_four_kinds_of_facts_cannot_impersonate_each_other(self):
        self._load('after_act')
        # 1) 数据库 sent 不产生阀位实测；没有读数时阀位状态是 unobserved。
        self.assertEqual(self._adjudication('adj-7')['valve_state'], 'unobserved')
        # 2) 控制器回执是独立事实：重启代次没有历史，receipt 表也不反推阀位。
        self.assertEqual(rows(self.db,
                              "SELECT COUNT(*) AS c FROM controller_receipts WHERE intent='V'")[0]['c'], 1)
        self.assertIsNone(one(self.db, "SELECT * FROM valve_readings WHERE at<8"))
        # 3) 厂界排放只由排口实测推算：所有排口读数为零流时排放量必须为零。
        self.assertEqual(sum(r['flow'] for r in rows(
            self.db, "SELECT * FROM hydrology_observations WHERE point='outfall'")), 0)
        self.assertEqual(self._adjudication('adj-9')['discharged'], 0)
        # 4) 业务裁决单独成表，不回写任何物理事实表。
        self.assertEqual(one(self.db, "SELECT status FROM valve_intents WHERE id='V'")['status'],
                         'sent')

    def test_physical_evidence_holds_against_contradictory_late_claim(self):
        # 物理证据已确认热水流出厂界后，控制器迟到的“已回流”声称不能倒改裁决与计量。
        self._load('before_act')
        confirmed = self._adjudication('adj-9')
        self.assertEqual(confirmed['verdict'], 'discharged_confirmed')
        self.assertEqual(confirmed['discharged'], 4)
        # 再登记一条与物理证据相矛盾的控制器执行声称，并重新走迟到确认。
        execute(self.db, 'cooling', {
            'op': 'receipt', 'id': 'rc-contradictory', 'intent': 'V', 'loop': 'loop-b',
            'generation': 1, 'at': 14, 'kind': 'execution_claim',
            'status': 'claims_recirculated'})
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'late_ack', 'id': 'ack-contradictory', 'receipt': 'rc-contradictory',
            'incident': 'inc-1', 'loop': 'loop-b', 'at': 14})['decision'],
            'late_ack_supplementary')
        # 裁决表追加了新行，但排放量与结论保持不变，排口事实未被回写。
        latest = self._adjudication('ack-contradictory')
        self.assertEqual(latest['verdict'], 'discharged_confirmed')
        self.assertEqual(latest['discharged'], 4)
        self.assertEqual(one(self.db,
                             "SELECT discharged FROM permit_meters WHERE id='meter-1'")
                         ['discharged'], 4)

    def test_database_only_batch_gets_no_water_compliance(self):
        # 只在数据库里跑完事件、没有任何恢复路径时，批次不得取得用水合规证明。
        events = json.loads(FIXTURES['after_act'].read_text(encoding='utf-8'))
        for x in events:
            if x['op'] in ('recover', 'certify_build'):
                continue
            execute(self.db, 'cooling', x)
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'certify_build', 'id': 'cert-denied', 'batch': 'batch-b',
            'loop': 'loop-b', 'at': 13})['decision'], 'water_compliance_denied')

    def test_late_receipt_alone_cannot_establish_discharge_or_retention(self):        # 只登记控制器声称、没有任何独立见证时，裁决仍是未知，且不能据此计量。
        events = json.loads(FIXTURES['before_act'].read_text(encoding='utf-8'))
        for x in events:
            if x['op'] in ('valve_reading', 'hydrology', 'adjudicate',
                           'recover', 'meter', 'late_ack', 'certify_build'):
                continue
            execute(self.db, 'cooling', x)
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'adjudicate', 'id': 'adj-blind', 'loop': 'loop-b',
            'intent': 'V', 'at': 12})['verdict'], 'outcome_unknown')
        self.assertEqual(execute(self.db, 'cooling', {
            'op': 'late_ack', 'id': 'ack-blind', 'receipt': 'rc-late',
            'incident': 'inc-1', 'loop': 'loop-b', 'at': 12})['verdict'], 'outcome_unknown')

    def test_both_fixtures_replay_without_touching_the_valve(self):
        for world in FIXTURES:
            with tempfile.TemporaryDirectory() as directory:
                path = str(Path(directory) / f'{world}.sqlite')
                db = connect(path)
                execute(db, 'provenance', {'op': 'manifest', 'digest': 'sha256:b-hot',
                                           'tag': 'batch-b:hot', 'batch': 'batch-b',
                                           'generation': 1})
                plant = Plant(world)
                plant.controller.attempt('V', 'recirculate', 4)
                plant.controller.restart(6)
                for x in json.loads(FIXTURES[world].read_text(encoding='utf-8')):
                    execute(db, 'cooling', x)
                self.assertEqual(plant.attempts(), 1)
                report = replay(path)
                self.assertTrue(report['verified'], report)
                # 重放全程不再驱动实物：外部动作次数保持 1（hold 世界另有一次机械隔离，
                # 但那也是重放前的数据库裁决，物理装置本身始终只被驱动过一次）。
                self.assertEqual(plant.attempts(), 1)
                db.close()


if __name__ == '__main__':
    unittest.main()
