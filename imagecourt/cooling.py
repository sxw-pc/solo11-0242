from .store import one, rows


# ---------------------------------------------------------------------------
# 确定性的物理世界模拟器：阀控制器 + 管道滞后 + 池水位 + 厂界探头。
# 它不接触数据库，也不提供任何“重发历史命令”的能力；重启后命令历史清空，
# 外部只能通过实测传感器（阀位/水位/流量/温度）推断水的去向。
# 两个物理世界共用同一份“sent”业务原件，只在断线时机上不同：
#   before_act：动作前断线，阀从未换位；
#   after_act ：动作完成后、回执返回前断线，阀已换位。
# ---------------------------------------------------------------------------
class ValveController:
    def __init__(self, world):
        if world not in ('before_act', 'after_act'):
            raise ValueError(world)
        self.world = world
        self.valve = 'drain'
        self.generation = 1
        # 易失内存：重启即清空，因此重启后无法据此判断旧命令是否执行过。
        self.received = []
        self.attempts = 0          # 真正驱动过实物的动作次数（测试断言的外部事实）
        self.restarted_at = None

    def attempt(self, intent, target, at):
        """一次真实的外部驱动尝试。返回控制器能否给出回执。"""
        self.attempts += 1
        self.received.append({'intent': intent, 'target': target, 'at': at})
        if self.world == 'before_act':
            # 动作前断线：阀保持原位，持久层没有任何接收痕迹。
            return {'ack': False, 'moved': False, 'persisted': False}
        # after_act：阀完成换位，但回执丢失；代次内的持久痕迹重启后仍在。
        self.valve = target
        return {'ack': False, 'moved': True, 'persisted': True}

    def restart(self, at):
        self.generation += 1
        self.received = []
        self.restarted_at = at
        return self.generation

    def sensor(self, at, pool_level, outfall_flow, outfall_temp):
        return {'at': at, 'valve': self.valve, 'generation': self.generation,
                'pool_level': pool_level, 'outfall_flow': outfall_flow,
                'outfall_temperature': outfall_temp}


# 两个物理世界各自的剧本：同一业务时间线上的独立见证读数。
# t=7 两世界读数完全相同（与“已换位/未换位”都相容）；
# t=8 的独立阀位见证开始分化；t=9 厂界探头与池水位给出最终去向。
PHYSICAL_TRACES = {
    'before_act': {
        7: {'pool_level': 40, 'outfall_flow': 0, 'outfall_temperature': 28},
        8: {'pool_level': 38, 'outfall_flow': 2, 'outfall_temperature': 35},
        9: {'pool_level': 36, 'outfall_flow': 2, 'outfall_temperature': 35}},
    'after_act': {
        7: {'pool_level': 40, 'outfall_flow': 0, 'outfall_temperature': 28},
        8: {'pool_level': 40, 'outfall_flow': 0, 'outfall_temperature': 28},
        9: {'pool_level': 42, 'outfall_flow': 0, 'outfall_temperature': 28}},
}


class Plant:
    """按剧本回放物理读数的厂界装置；attempts 是不可被数据库事件冒充的外部事实。"""

    def __init__(self, world):
        self.world = world
        self.controller = ValveController(world)

    def observe(self, at):
        point = PHYSICAL_TRACES[self.world][at]
        return self.controller.sensor(at, point['pool_level'],
                                      point['outfall_flow'], point['outfall_temperature'])

    def attempts(self):
        return self.controller.attempts


# ---------------------------------------------------------------------------
# 纯查询辅助：四类事实分别从不同的表取，任何裁决函数都不得跨类冒充。
# ---------------------------------------------------------------------------
def _latest_adjudication(db, loop, intent):
    return one(db, """SELECT * FROM discharge_adjudications
                      WHERE loop=? AND intent=? ORDER BY at DESC""", (loop, intent))


def _open_incident(db, loop):
    return one(db, "SELECT * FROM discharge_incidents WHERE loop=? AND status='open'", (loop,))


def _adjudicate(db, x):
    intent = one(db, 'SELECT * FROM valve_intents WHERE id=?', (x['intent'],))
    if not intent:
        return {'decision': 'unknown_intent'}
    reading = one(db, """SELECT * FROM valve_readings WHERE loop=? AND at<=?
                         ORDER BY at DESC""", (x['loop'], x['at']))
    hydro = rows(db, """SELECT * FROM hydrology_observations WHERE loop=? AND at<=?
                        ORDER BY at""", (x['loop'], x['at']))
    outfall = [h for h in hydro if h['point'] == 'outfall' and h['at'] > intent['at']]
    pool = [h for h in hydro if h['point'] == 'pool' and h['at'] > intent['at']]
    # 1) 阀位事实：只认独立见证的实测，不认 intent 的 sent，也不认控制器声称。
    if not reading:
        valve_state = 'unobserved'
    elif reading['position'] == intent['position']:
        valve_state = 'matches_intent'
    else:
        valve_state = 'diverges_from_intent'
    # 2) 厂界排放事实：只认排口实测的流量/温度；管道滞后期间没有读数即为未判定。
    seen_outfall = [h for h in outfall if h['flow'] > 0]
    hot_outfall = [h for h in seen_outfall if h['temperature'] > 28]
    discharged = sum(h['flow'] for h in hot_outfall)
    # 3) 池内留存事实：独立见证的池水位；无读数时不得凭意图推定。
    retained = pool[-1]['level'] if pool else None
    undeterminable = []
    if not reading:
        undeterminable.append('valve_position')
    if not outfall:
        undeterminable.append('pipe_lag_destination')
    if retained is None:
        undeterminable.append('pool_retained_volume')
    # 三态裁决，全部基于独立实测，intent 的 sent 与控制器声称均不参与：
    #   discharged_confirmed：排口实测到热水（厂界事实优先，不可回改）；
    #   retained_probable   ：阀位实测与意图一致且排口无热水；
    #   outcome_unknown     ：证据与“已换位/未换位”都相容，明确保留未知部分。
    if hot_outfall:
        verdict = 'discharged_confirmed'
    elif valve_state == 'matches_intent' and not seen_outfall:
        verdict = 'retained_probable'
    else:
        verdict = 'outcome_unknown'
    # 单调性：已确认流出厂界的水量只能维持或上调，绝不回写为更小值。
    prior = _latest_adjudication(db, x['loop'], x['intent'])
    if prior and prior['discharged'] > discharged:
        discharged = prior['discharged']
        if verdict != 'discharged_confirmed':
            verdict = 'discharged_confirmed'
    basis = {'valve_reading': reading['id'] if reading else None,
             'outfall_observations': [h['id'] for h in outfall],
             'pool_observations': [h['id'] for h in pool],
             'receipts_ignored_for_destination': True}
    db.execute('INSERT INTO discharge_adjudications VALUES(?,?,?,?,?,?,?,?,?,?)',
               (x['id'], x['loop'], x['intent'], x['at'], valve_state, verdict,
                discharged, retained, ','.join(undeterminable) or None,
                str(basis)))
    return {'decision': 'adjudicated', 'verdict': verdict,
            'valve_state': valve_state, 'discharged': discharged,
            'retained': retained, 'undeterminable': undeterminable}


def _gate_external_action(db, x):
    """物理动作网关：每次动作必须带不重用的业务意图、目标阀位、许可窗口、
    控制器代次和独立见证；对结果未知的旧意图一律拒绝重发，杜绝二次排水。"""
    # 每个业务意图只能派单一次；重发必须携带新的不重用意图。
    # 同一派单要素的重复提交（恢复路径的幂等重入）只返回既有记录，不产生第二次动作。
    existing = one(db, 'SELECT * FROM external_actions WHERE intent=?', (x['intent'],))
    if existing:
        if (existing['kind'], existing['position'], existing['generation'],
                existing['witness']) == (x['kind'], x['position'],
                                         x['generation'], x['witness']):
            return {'decision': 'external_action_dispatched', 'id': existing['id'],
                    'idempotent': True}
        return {'decision': 'intent_already_dispatched'}
    # 阀门类动作必须绑定一个已登记的阀门意图；机械隔离等独立动作不需要。
    intent = one(db, 'SELECT * FROM valve_intents WHERE id=?', (x['intent'],))
    if x['kind'] == 'valve' and not intent:
        return {'decision': 'unknown_intent'}
    permit = one(db, 'SELECT * FROM discharge_permits WHERE loop=? AND status=?',
                 (x['loop'], 'active'))
    if not permit or not permit['start'] <= x['at'] < permit['expires']:
        return {'decision': 'outside_permit_window'}
    gen = one(db, """SELECT * FROM controller_generations WHERE loop=?
                     ORDER BY generation DESC""", (x['loop'],))
    if not gen or gen['generation'] != x['generation']:
        return {'decision': 'stale_controller_generation'}
    witness = one(db, 'SELECT * FROM witnesses WHERE id=? AND accepted=1', (x['witness'],))
    if not witness:
        return {'decision': 'witness_not_accepted'}
    # 事故未决期间，禁止对结果未知的同一排水意图再驱动阀门
    # （可能把本应留在池内的水再次排掉）；不同意图的新动作不在此列。
    incident = _open_incident(db, x['loop'])
    if intent and incident and incident['intent'] == x['intent']:
        return {'decision': 'unknown_outcome_redispatch_blocked'}
    prior = _latest_adjudication(db, x['loop'], x['intent'])
    if intent and prior and prior['verdict'] == 'outcome_unknown':
        return {'decision': 'unknown_outcome_redispatch_blocked'}
    db.execute('INSERT INTO external_actions VALUES(?,?,?,?,?,?,?,?,?,?)',
               (x['id'], x['intent'], x['loop'], x['kind'], x['position'],
                x['generation'], f"{permit['start']}-{permit['expires']}", x['at'],
                x['witness'], 'dispatched'))
    return {'decision': 'external_action_dispatched'}


def run(db, x):
    op = x['op']
    if op == 'loop':
        if x['flow_limit'] <= 0:
            return {'decision': 'invalid_loop'}
        db.execute('INSERT INTO cooling_loops VALUES(?,?,?,?,?)',
                   (x['id'], x['site'], x['flow_limit'], x['temp_limit'], 'active'))
        return {'decision': 'loop_recorded'}
    if op == 'sample':
        loop = one(db, 'SELECT * FROM cooling_loops WHERE id=?', (x['loop'],))
        if not loop:
            return {'decision': 'loop_missing'}
        db.execute('INSERT INTO water_samples VALUES(?,?,?,?,?,?)',
                   (x['id'], x['loop'], x['point'], x['at'], x['flow'], x['temperature']))
        return {'decision': 'water_sampled'}
    if op == 'build':
        manifest = one(db, 'SELECT * FROM manifests WHERE digest=?', (x['digest'],))
        if not manifest or manifest['batch'] != x['batch']:
            return {'decision': 'unknown_batch'}
        db.execute('INSERT INTO cooling_builds VALUES(?,?,?,?,?)',
                   (x['id'], x['batch'], x['loop'], x['starts'], x['ends']))
        return {'decision': 'build_linked'}
    if op == 'valve':
        loop = one(db, 'SELECT * FROM cooling_loops WHERE id=?', (x['loop'],))
        if not loop:
            return {'decision': 'loop_missing'}
        db.execute('INSERT INTO valve_intents VALUES(?,?,?,?,?)',
                   (x['id'], x['loop'], x['position'], x['at'], 'sent'))
        return {'decision': 'valve_command_sent'}
    if op == 'report':
        loop = one(db, 'SELECT * FROM cooling_loops WHERE id=?', (x['loop'],))
        if not loop:
            return {'decision': 'loop_missing'}
        measured = rows(db, 'SELECT flow FROM water_samples WHERE loop=?', (x['loop'],))
        volume = sum(item['flow'] for item in measured)
        db.execute('INSERT INTO water_reports VALUES(?,?,?,?,?)',
                   (x['id'], x['loop'], x['period'], volume, 'draft'))
        return {'decision': 'report_drafted', 'volume': volume}
    if op == 'permit':
        if x['start'] >= x['expires'] or x['volume_limit'] <= 0:
            return {'decision': 'invalid_permit'}
        db.execute('INSERT INTO discharge_permits VALUES(?,?,?,?,?,?)',
                   (x['loop'], x['volume_limit'], x['start'], x['expires'],
                    x['temp_limit'], 'active'))
        return {'decision': 'permit_recorded'}
    if op == 'witness':
        db.execute('INSERT INTO witnesses VALUES(?,?,?,?)',
                   (x['id'], x['party'], x['kind'], 1 if x['accepted'] else 0))
        return {'decision': 'witness_accepted' if x['accepted'] else 'witness_rejected'}
    if op == 'controller_start':
        last = one(db, """SELECT MAX(generation) AS g FROM controller_generations
                          WHERE loop=?""", (x['loop'],))
        generation = (last['g'] or 0) + 1
        if x.get('generation') is not None and x['generation'] != generation:
            return {'decision': 'controller_generation_conflict'}
        db.execute('INSERT INTO controller_generations VALUES(?,?,?,?)',
                   (x['loop'], generation, x['at'], 1 if x['history_retained'] else 0))
        return {'decision': 'controller_generation_recorded', 'generation': generation}
    if op == 'dispatch':
        return _gate_external_action(db, x)
    if op == 'receipt':
        # 控制器接收/执行声称是独立事实；迟到时只能补证据，不改变水去向裁决。
        if not one(db, 'SELECT id FROM valve_intents WHERE id=?', (x['intent'],)):
            return {'decision': 'unknown_intent'}
        db.execute('INSERT INTO controller_receipts VALUES(?,?,?,?,?,?,?)',
                   (x['id'], x['intent'], x['loop'], x['generation'], x['at'],
                    x['kind'], x['status']))
        return {'decision': 'receipt_recorded'}
    if op == 'valve_reading':
        if not one(db, 'SELECT id FROM witnesses WHERE id=? AND accepted=1', (x['witness'],)):
            return {'decision': 'witness_not_accepted'}
        db.execute('INSERT INTO valve_readings VALUES(?,?,?,?,?,?)',
                   (x['id'], x['loop'], x['at'], x['position'], x['witness'],
                    x['generation']))
        return {'decision': 'valve_reading_recorded'}
    if op == 'hydrology':
        if not one(db, 'SELECT id FROM witnesses WHERE id=? AND accepted=1', (x['witness'],)):
            return {'decision': 'witness_not_accepted'}
        db.execute('INSERT INTO hydrology_observations VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], x['loop'], x['at'], x['point'], x['level'],
                    x['flow'], x['temperature'], x['witness']))
        return {'decision': 'hydrology_recorded'}
    if op == 'incident':
        if _open_incident(db, x['loop']):
            return {'decision': 'incident_already_open'}
        db.execute('INSERT INTO discharge_incidents VALUES(?,?,?,?,?)',
                   (x['id'], x['loop'], x['intent'], x['at'], 'open'))
        return {'decision': 'incident_declared'}
    if op == 'adjudicate':
        return _adjudicate(db, x)
    if op == 'recover':
        incident = one(db, 'SELECT * FROM discharge_incidents WHERE id=?', (x['incident'],))
        if not incident or incident['status'] != 'open':
            return {'decision': 'no_open_incident'}
        latest = _latest_adjudication(db, x['loop'], incident['intent'])
        if not latest:
            return {'decision': 'adjudication_required'}
        if x['path'] == 'hold':
            # 独立机械隔离是一个全新的物理动作意图，绝不重用 V，也不操作排水阀。
            gate = _gate_external_action(db, {
                'id': x['id'] + '-action', 'intent': x['intent_id'], 'loop': x['loop'],
                'kind': 'mechanical_isolation', 'position': 'isolated',
                'generation': x['generation'], 'at': x['at'],
                'witness': x['isolation_witness']})
            if gate['decision'] != 'external_action_dispatched':
                return gate
            custodian = 'on_site'
            transfer = None
        elif x['path'] == 'mobile_closed_loop':
            unit = one(db, "SELECT * FROM witnesses WHERE id=? AND kind='mobile_unit' AND accepted=1",
                       (x['custodian'],))
            if not unit:
                return {'decision': 'mobile_unit_not_accepted'}
            custodian = x['custodian']
            transfer = x['transfer_manifest']
            x['isolation_witness'] = None
        else:
            return {'decision': 'invalid_recovery_path'}
        db.execute("UPDATE discharge_incidents SET status='recovered' WHERE id=?", (x['incident'],))
        db.execute('INSERT INTO recovery_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                   (x['id'], x['loop'], incident['intent'], x['incident'], x['at'],
                    x['path'], x['batch'], custodian, x['delivery_at'], transfer,
                    x['isolation_witness'], 'executed'))
        return {'decision': 'recovery_executed', 'path': x['path'], 'custodian': custodian}
    if op == 'meter':
        permit = one(db, "SELECT * FROM discharge_permits WHERE loop=? AND status='active'",
                     (x['loop'],))
        if not permit:
            return {'decision': 'permit_missing'}
        incident = one(db, 'SELECT * FROM discharge_incidents WHERE id=?', (x['incident'],))
        if not incident:
            return {'decision': 'incident_missing'}
        # 许可计量只采信厂界排口实测与裁决中的单调排放量；回执不参与计量。
        latest = _latest_adjudication(db, x['loop'], incident['intent'])
        discharged = latest['discharged'] if latest else 0
        verdict = 'within_permit' if discharged <= permit['volume_limit'] else 'permit_exceeded'
        db.execute('INSERT INTO permit_meters VALUES(?,?,?,?,?,?,?)',
                   (x['id'], x['loop'], x['incident'], x['at'], discharged,
                    permit['volume_limit'], verdict))
        return {'decision': 'meter_recorded', 'discharged': discharged,
                'volume_limit': permit['volume_limit'], 'verdict': verdict}
    if op == 'certify_build':
        build = one(db, 'SELECT * FROM cooling_builds WHERE batch=? AND loop=?',
                    (x['batch'], x['loop']))
        if not build:
            return {'decision': 'build_not_linked'}
        if one(db, 'SELECT id FROM build_compliance WHERE batch=?', (x['batch'],)):
            return {'decision': 'compliance_already_certified'}
        open_incident = _open_incident(db, x['loop'])
        recovery = one(db, """SELECT * FROM recovery_actions WHERE loop=? AND batch=?
                              ORDER BY at DESC""", (x['loop'], x['batch']))
        if open_incident or not recovery:
            # 外部动作失败时，只在数据库里完成的批次不得取得用水合规证明。
            return {'decision': 'water_compliance_denied'}
        latest = _latest_adjudication(db, x['loop'], recovery['intent'])
        if latest and latest['undeterminable']:
            return {'decision': 'water_balance_unclosed'}
        meter = one(db, """SELECT * FROM permit_meters WHERE loop=?
                           ORDER BY at DESC""", (x['loop'],))
        if meter and meter['verdict'] == 'permit_exceeded':
            return {'decision': 'permit_meter_blocks_certification'}
        if recovery['path'] == 'hold':
            verdict = 'certified_with_delivery_delay'
            basis = 'water_retained_on_site_mechanical_isolation'
        else:
            verdict = 'certified_external_custody'
            basis = f"transfer_manifest:{recovery['transfer_manifest']}"
        db.execute('INSERT INTO build_compliance VALUES(?,?,?,?,?,?)',
                   (x['id'], x['batch'], x['loop'], x['at'], verdict, basis))
        return {'decision': 'build_compliance_certified', 'verdict': verdict}
    if op == 'late_ack':
        receipt = one(db, 'SELECT * FROM controller_receipts WHERE id=?', (x['receipt'],))
        if not receipt:
            return {'decision': 'receipt_missing'}
        incident = one(db, 'SELECT * FROM discharge_incidents WHERE id=?', (x['incident'],))
        if not incident:
            return {'decision': 'incident_missing'}
        before = _latest_adjudication(db, x['loop'], incident['intent'])
        if not before:
            # 没有基于物理证据的裁决时，控制器声称不能凭空建立排放或留存事实。
            return {'decision': 'adjudication_required'}
        # 迟到确认只能补充证据：重新裁决后排放量与结论不得被倒改。
        after = _adjudicate(db, {'id': x['id'], 'loop': x['loop'],
                                 'intent': incident['intent'], 'at': x['at']})
        if after['discharged'] != before['discharged'] or after['verdict'] != before['verdict']:
            return {'decision': 'late_ack_would_rewrite_history'}
        return {'decision': 'late_ack_supplementary', 'verdict': after['verdict'],
                'discharged': after['discharged']}
    raise ValueError(op)
