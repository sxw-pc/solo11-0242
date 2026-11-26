import json
import tempfile
import unittest
from pathlib import Path

from imagecourt import store
from imagecourt.store import connect, execute, replay
from imagecourt.royalty_capture import provisional_dues
from imagecourt.royalty_settlement import balances, statement

ROOT = Path(__file__).resolve().parents[1]
CASH_KINDS = ('payment', 'advance', 'recovery', 'recourse_recovery',
              'escrow_deposit', 'escrow_release', 'supplementary_payment')


class RoyaltySettlementTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state.sqlite'
        self.db = connect(str(self.path))

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def step(self, sub='settlement', **x):
        return execute(self.db, sub, x)

    def fixture(self, sub, name):
        data = json.loads((ROOT / 'fixtures' / name).read_text(encoding='utf-8'))
        return [execute(self.db, sub, x) for x in data]

    def build(self, digest, components, revision=1, batch='b1', tag='img:1'):
        execute(self.db, 'provenance', {'op': 'manifest', 'digest': digest, 'tag': tag,
                                        'batch': batch, 'generation': 1})
        execute(self.db, 'provenance', {'op': 'sbom', 'digest': digest,
                                        'components': components, 'revision': revision})

    def contract(self, cid='C1', customer='cust-1', escrow=None, uw=None):
        return self.step(op='contract', id=cid, customer=customer,
                         escrow_account=escrow or 'escrow-' + cid.lower(),
                         underwriter=uw or 'uw-' + cid.lower())

    def credential(self, cid, binary, ben, rate, chain='root', territory='*',
                   signed=5, registered=6, effective=6, holder=None, version=None):
        return self.step(op='credential', id=cid, binary=binary, holder=holder or cid,
                         beneficiary=ben, license_version=version or cid + '-lic', rate=rate,
                         chain=chain, territory=territory, signed_at=signed,
                         registered_at=registered, effective_from=effective)

    def cash_conserved(self):
        marks = ','.join('?' * len(CASH_KINDS))
        total = store.one(self.db, 'SELECT COALESCE(SUM(amount),0) AS t FROM ledger WHERE kind IN (%s)' % marks,
                          CASH_KINDS)['t']
        self.assertEqual(total, 0)

    def replay_settlement_events(self):
        before = balances(self.db)
        for e in store.rows(self.db, "SELECT payload FROM events WHERE subsystem='settlement' ORDER BY seq"):
            execute(self.db, 'settlement', json.loads(e['payload']))
        self.assertEqual(balances(self.db), before)

    def test_same_binary_renamed_or_nested_counts_once_per_contract(self):
        self.contract()
        self.contract('C2', 'cust-2')
        self.step(op='alias', name='libv', binary='bin:V')
        self.step(op='alias', name='libv-nested', binary='bin:V')   # 依赖嵌套出现的同一二进制
        self.step(op='alias', name='libv-legacy', binary='bin:V')   # 改名后的同一二进制
        self.credential('cred-A', 'bin:V', 'ben-A', 100)
        self.build('sha256:img1', ['libv', 'libv-nested'])
        r = self.step(op='deliver', id='d1', contract='C1', digest='sha256:img1',
                      territory='EU', at=10, confirmation='signed-1')
        self.assertEqual(r['decision'], 'delivered')
        self.assertEqual(r['obligations'], ['C1|bin:V'])
        # 清单修订把组件改名；已交付版本的义务不得被改写
        execute(self.db, 'provenance', {'op': 'sbom', 'digest': 'sha256:img1',
                                        'components': ['libv-legacy'], 'revision': 2})
        self.build('sha256:img2', ['libv-legacy'], batch='b2', tag='img:2')
        r = self.step(op='deliver', id='d2', contract='C1', digest='sha256:img2',
                      territory='EU', at=20, confirmation='signed-2')
        self.assertEqual(r['decision'], 'delivered')
        self.assertEqual(r['obligations'], [])
        # 同一合同下同一二进制只计一次；另一合同取得改名后的副本才另计一次
        self.assertEqual(statement(self.db, 'cust-1')['total_billed'], 100)
        r = self.step(op='deliver', id='d3', contract='C2', digest='sha256:img2',
                      territory='EU', at=25, confirmation='signed-c2')
        self.assertEqual(r['obligations'], ['C2|bin:V'])
        self.assertEqual(statement(self.db, 'cust-2')['total_billed'], 100)
        # 已交付快照保留先前清单；同一副本的重复交付不是第二次发行
        d1 = store.one(self.db, 'SELECT components FROM deliveries WHERE id=?', ('d1',))
        self.assertEqual(json.loads(d1['components']), ['bin:V'])
        s1 = statement(self.db, 'cust-1')['obligations'][0]
        self.assertEqual(s1['digest'], 'sha256:img1')
        self.assertEqual(s1['pinned_license'], 'cred-A-lic')
        r = self.step(op='deliver', id='d4', contract='C1', digest='sha256:img1',
                      territory='EU', at=30, confirmation='signed-4')
        self.assertEqual(r['decision'], 'redelivery')
        r = self.step(op='deliver', id='d1', contract='C1', digest='sha256:img1',
                      territory='EU', at=10, confirmation='signed-1')
        self.assertEqual(r['decision'], 'reused')
        self.assertEqual(statement(self.db, 'cust-1')['total_billed'], 100)
        self.assertTrue(replay(str(self.path))['verified'])

    def test_lease_retry_and_renewal_are_not_second_distributions(self):
        self.fixture('provenance', 'provenance_normal.json')
        self.fixture('channel', 'channel_normal.json')
        self.fixture('admission', 'admission_normal.json')
        self.contract()
        self.step(op='alias', name='lib-a', binary='bin:A')
        self.step(op='alias', name='lib-b', binary='bin:B')
        self.credential('cred-a', 'bin:A', 'ben-a', 40)
        self.credential('cred-b', 'bin:B', 'ben-b', 60)
        r = self.step(op='deliver', id='d1', contract='C1', digest='sha256:aaa',
                      territory='EU', at=15, confirmation='signed-1')
        self.assertEqual(r['decision'], 'delivered')
        before = balances(self.db)
        self.assertEqual(provisional_dues(self.db, 'sha256:aaa', 7), 14)
        # 续租、到期、以新租约重试、提前终止：临时单随之膨胀，结算纹丝不动
        self.assertEqual(self.step('admission', op='renew', id='lease-1', at=20, expires=60)['decision'], 'renewed')
        self.assertEqual(self.step('admission', op='expire', id='lease-1', at=61)['decision'], 'expired')
        self.assertEqual(self.step('admission', op='admit', id='lease-2', workload='web-1',
                                   generation=1, channel_generation=1, at=62, expires=90)['decision'], 'admitted')
        self.assertEqual(self.step('admission', op='isolate', id='lease-2')['decision'], 'isolated')
        self.assertEqual(provisional_dues(self.db, 'sha256:aaa', 7), 28)
        self.assertEqual(balances(self.db), before)
        self.assertEqual(statement(self.db, 'cust-1')['total_billed'], 100)
        self.assertTrue(replay(str(self.path))['verified'])

    def test_late_license_corrects_via_recoverable_supplementary_settlement(self):
        self.contract('C9', 'cust-9')
        self.step(op='alias', name='libx', binary='bin:X')
        self.build('sha256:img3', ['libx'])
        r = self.step(op='deliver', id='d1', contract='C9', digest='sha256:img3',
                      territory='US', at=10, confirmation='signed-1')
        self.assertEqual(r['decision'], 'delivered')
        self.assertEqual(self.step(op='settle', id='pay-1', obligation='C9|bin:X', at=11)['decision'], 'unlicensed')
        self.assertEqual(statement(self.db, 'cust-9')['total_billed'], 0)
        # 其他地域的凭据不适用于交付地域
        self.credential('cred-X-eu', 'bin:X', 'ben-X', 999, territory='EU', signed=8, registered=20, effective=8)
        self.assertEqual(self.step(op='reconcile', id='rec-0', obligation='C9|bin:X', at=21)['decision'], 'no_change')
        # 许可迟到：不改写钉定记录，只以可追索的追加清偿补上
        self.credential('cred-X1', 'bin:X', 'ben-X', 40, signed=4, registered=22, effective=5)
        r = self.step(op='reconcile', id='rec-1', obligation='C9|bin:X', at=23)
        self.assertEqual(r['decision'], 'corrected')
        self.assertEqual(balances(self.db)['total']['holder:ben-X'], 40)
        self.assertEqual(statement(self.db, 'cust-9')['total_billed'], 40)
        # 更晚登记、却对交付时刻生效的版本，只追加差额
        self.credential('cred-X2', 'bin:X', 'ben-X', 55, signed=6, registered=30, effective=6)
        r = self.step(op='reconcile', id='rec-2', obligation='C9|bin:X', at=31)
        self.assertEqual(r['decision'], 'corrected')
        self.assertEqual(balances(self.db)['total']['holder:ben-X'], 55)
        self.assertEqual(statement(self.db, 'cust-9')['total_billed'], 55)
        # 重放更正不会让客户或权利人任何一边的余额增加
        self.assertEqual(self.step(op='reconcile', id='rec-2', obligation='C9|bin:X', at=31)['decision'], 'reused')
        self.assertEqual(self.step(op='reconcile', id='rec-3', obligation='C9|bin:X', at=32)['decision'], 'no_change')
        self.assertEqual(balances(self.db)['total']['holder:ben-X'], 55)
        self.assertEqual(statement(self.db, 'cust-9')['total_billed'], 55)
        ob = store.one(self.db, 'SELECT * FROM obligations WHERE id=?', ('C9|bin:X',))
        self.assertIsNone(ob['credential'])
        self.assertEqual(ob['status'], 'settled')
        self.cash_conserved()
        self.assertTrue(replay(str(self.path))['verified'])

    def component_v_setup(self):
        # 发行时清单称组件 V 属于甲的商业库；同一二进制确已交付三个客户
        self.step(op='alias', name='libv', binary='bin:V')
        self.step(op='alias', name='libu', binary='bin:U')
        self.credential('cred-A', 'bin:V', 'ben-A', 100, holder='A', version='V-commercial-1')
        self.credential('cred-U', 'bin:U', 'ben-U', 50, holder='U', version='U-lic-1')
        self.build('sha256:img1', ['libv', 'libu'])
        for i in (1, 2, 3):
            self.contract('C%d' % i, 'cust-%d' % i)
            r = self.step(op='deliver', id='d%d' % i, contract='C%d' % i, digest='sha256:img1',
                          territory='EU', at=10, confirmation='signed-%d' % i)
            self.assertEqual(r['decision'], 'delivered')
        # 无争议部分先结清
        for i in (1, 2, 3):
            r = self.step(op='settle', id='pay-u%d' % i, obligation='C%d|bin:U' % i, at=11)
            self.assertEqual(r['decision'], 'settled')
        # 乙随后登记其上游权利，并拿出签署日早于首次公开登记的历史转授权书
        self.credential('cred-B-root', 'bin:V', 'ben-Broot', 90, holder='B-root',
                        version='V-upstream', signed=15, registered=15, effective=15)
        r = self.credential('cred-B', 'bin:V', 'ben-B', 100, holder='B', version='V-old-branch',
                            chain='cred-B-root', signed=7, registered=15, effective=7)
        self.assertEqual(r['decision'], 'registered_anomalous')
        for i in (1, 2, 3):
            r = self.step(op='dispute', id='disp-%d' % i, obligation='C%d|bin:V' % i,
                          claimant='B', credential='cred-B', at=16)
            self.assertEqual(r['decision'], 'disputed')

    def test_dispute_modes_reconcile_to_exactly_one_payment_per_obligation(self):
        self.component_v_setup()
        # 争议期间仅凭催告不能付款；监管账户与承保方都必须是合同指定方
        self.assertEqual(self.step(op='settle', id='pay-v1', obligation='C1|bin:V', at=17)['decision'], 'disputed')
        self.assertEqual(self.step(op='escrow', id='esc-1-bad', obligation='C1|bin:V',
                                   account='someone-else', at=17)['decision'], 'wrong_escrow_account')
        self.assertEqual(self.step(op='escrow', id='esc-1', obligation='C1|bin:V',
                                   account='escrow-c1', at=17)['decision'], 'escrowed')
        self.assertEqual(self.step(op='underwrite', id='uw-2-bad', obligation='C2|bin:V',
                                   underwriter='uw-c1', at=17)['decision'], 'wrong_underwriter')
        self.assertEqual(self.step(op='underwrite', id='uw-2', obligation='C2|bin:V',
                                   underwriter='uw-c2', at=17)['decision'], 'underwritten')
        # 预付给目前证据较完整的一方：甲的链条完整，乙的转授权书签署日异常
        r = self.step(op='advance', id='adv-2', obligation='C2|bin:V', at=18)
        self.assertEqual((r['decision'], r['recipient']), ('advanced', 'ben-A'))
        # 争议期内继续履行已承诺的客户发行；新副本按当前登记确定适用许可
        self.contract('C4', 'cust-4')
        r = self.step(op='deliver', id='d4', contract='C4', digest='sha256:img1',
                      territory='EU', at=19, confirmation='signed-4')
        self.assertEqual(r['decision'], 'delivered')
        ob4 = store.one(self.db, 'SELECT * FROM obligations WHERE id=?', ('C4|bin:V',))
        self.assertEqual(ob4['credential'], 'cred-B-root')
        # C3：乙撤诉，监管款释放给钉定的权利人
        self.assertEqual(self.step(op='escrow', id='esc-3', obligation='C3|bin:V',
                                   account='escrow-c3', at=17)['decision'], 'escrowed')
        r = self.step(op='withdraw_claim', id='wd-3', obligation='C3|bin:V', at=20)
        self.assertEqual((r['decision'], r['paid_to']), ('withdrawn', 'ben-A'))
        # 裁决迟到：乙在 C1、C2 上胜诉，实际付款与最终权利归属核对
        r = self.step(op='adjudicate', id='adj-1', obligation='C1|bin:V', winner='cred-B', at=25)
        self.assertEqual((r['decision'], r['paid_to']), ('resolved', 'ben-B'))
        r = self.step(op='adjudicate', id='adj-2', obligation='C2|bin:V', winner='cred-B', at=25)
        self.assertEqual((r['decision'], r['paid_to']), ('resolved', 'ben-B'))
        b = balances(self.db)['total']
        self.assertEqual(b['holder:ben-B'], 200)      # C1 监管释放 + C2 追索后补付
        self.assertEqual(b['holder:ben-A'], 100)      # C2 预付被追回，C3 撤诉后得款
        self.assertEqual(b['holder:ben-U'], 150)      # 无争议组件三份合同
        self.assertNotIn('holder:ben-Broot', b)       # 仅登记不等于有权收款
        self.assertEqual(b['escrow:escrow-c1'], 0)
        self.assertEqual(b['escrow:escrow-c3'], 0)
        self.assertEqual(b['underwriter:uw-c2'], 0)   # 追索完成后赔付承诺解除
        self.assertEqual(b['finance'], -450)
        for i in (1, 2, 3):
            s = statement(self.db, 'cust-%d' % i)
            self.assertEqual(s['total_billed'], 150)  # 客户不因争议收到重复账单
        self.assertEqual(statement(self.db, 'cust-4')['total_billed'], 140)
        self.cash_conserved()
        # 同一事件重放：监管释放、承保追偿、撤诉都不会让任何一边余额增加
        self.assertEqual(self.step(op='adjudicate', id='adj-1', obligation='C1|bin:V',
                                   winner='cred-B', at=25)['decision'], 'reused')
        self.assertEqual(self.step(op='withdraw_claim', id='wd-3', obligation='C3|bin:V',
                                   at=20)['decision'], 'reused')
        self.assertEqual(self.step(op='escrow', id='esc-1', obligation='C1|bin:V',
                                   account='escrow-c1', at=17)['decision'], 'reused')
        self.assertEqual(self.step(op='advance', id='adv-2', obligation='C2|bin:V',
                                   at=18)['decision'], 'reused')
        self.replay_settlement_events()
        result = replay(str(self.path))
        self.assertTrue(result['verified'], result)

    def test_revoked_sublicense_recovers_mispayment(self):
        self.contract('C5', 'cust-5')
        self.contract('C6', 'cust-6')
        self.step(op='alias', name='liby', binary='bin:Y')
        self.build('sha256:img4', ['liby'])
        self.credential('cred-Y1', 'bin:Y', 'ben-Y1', 70, signed=5, registered=6, effective=6)
        self.credential('cred-Y2', 'bin:Y', 'ben-Y2', 70, chain='cred-Y1',
                        signed=7, registered=7, effective=7)
        self.step(op='deliver', id='d5', contract='C5', digest='sha256:img4',
                  territory='EU', at=10, confirmation='s5')
        self.step(op='deliver', id='d6', contract='C6', digest='sha256:img4',
                  territory='EU', at=10, confirmation='s6')
        ob = store.one(self.db, 'SELECT * FROM obligations WHERE id=?', ('C5|bin:Y',))
        self.assertEqual(ob['credential'], 'cred-Y2')
        self.assertEqual(self.step(op='settle', id='pay-5', obligation='C5|bin:Y', at=11)['decision'], 'settled')
        # 转授权失效：已付的款只能通过可追索的追加清偿更正
        self.assertEqual(self.step(op='revoke_credential', id='cred-Y2')['decision'], 'revoked')
        self.assertEqual(self.step(op='settle', id='pay-6', obligation='C6|bin:Y', at=12)['decision'], 'credential_revoked')
        self.assertEqual(self.step(op='reconcile', id='rec-5', obligation='C5|bin:Y', at=13)['decision'], 'corrected')
        self.assertEqual(self.step(op='reconcile', id='rec-6', obligation='C6|bin:Y', at=13)['decision'], 'corrected')
        b = balances(self.db)['total']
        self.assertEqual(b['holder:ben-Y2'], 0)     # 错付全额追回
        self.assertEqual(b['holder:ben-Y1'], 140)   # 存续的权利人每合同只收一次
        self.assertEqual(statement(self.db, 'cust-5')['total_billed'], 70)
        self.assertEqual(statement(self.db, 'cust-6')['total_billed'], 70)
        # 追索重放不会追回第二次
        self.assertEqual(self.step(op='reconcile', id='rec-5', obligation='C5|bin:Y', at=13)['decision'], 'reused')
        self.assertEqual(self.step(op='reconcile', id='rec-5b', obligation='C5|bin:Y', at=14)['decision'], 'no_change')
        b = balances(self.db)['total']
        self.assertEqual(b['holder:ben-Y2'], 0)
        self.assertEqual(b['holder:ben-Y1'], 140)
        self.cash_conserved()
        self.assertTrue(replay(str(self.path))['verified'])

    def test_duplicate_fulfillment_ops_cannot_double_pay(self):
        self.component_v_setup()
        # 同一争议下的第二笔监管存入（新单据号）不得重复占用现金
        self.assertEqual(self.step(op='escrow', id='esc-1', obligation='C1|bin:V',
                                   account='escrow-c1', at=17)['decision'], 'escrowed')
        self.assertEqual(self.step(op='escrow', id='esc-1b', obligation='C1|bin:V',
                                   account='escrow-c1', at=18)['decision'], 'mode_conflict')
        self.assertEqual(balances(self.db)['total']['escrow:escrow-c1'], 100)
        # 同一争议下的第二笔预付（新单据号）不得重复付款
        self.assertEqual(self.step(op='underwrite', id='uw-2', obligation='C2|bin:V',
                                   underwriter='uw-c2', at=17)['decision'], 'underwritten')
        self.assertEqual(self.step(op='advance', id='adv-2', obligation='C2|bin:V', at=18)['decision'], 'advanced')
        r = self.step(op='advance', id='adv-2b', obligation='C2|bin:V', at=19)
        self.assertEqual((r['decision'], r['recipient']), ('reused', 'ben-A'))
        self.assertEqual(balances(self.db)['total']['holder:ben-A'], 100)
        # 预付对象胜诉时只解除赔付承诺，不再发生资金移动
        r = self.step(op='adjudicate', id='adj-2', obligation='C2|bin:V', winner='cred-A', at=25)
        self.assertEqual((r['decision'], r['paid_to']), ('resolved', 'ben-A'))
        b = balances(self.db)['total']
        self.assertEqual(b['holder:ben-A'], 100)
        self.assertEqual(b['underwriter:uw-c2'], 0)
        # 裁决已终局的义务不再接受账外更正
        self.assertEqual(self.step(op='reconcile', id='rec-2', obligation='C2|bin:V', at=26)['decision'], 'adjudicated')
        self.cash_conserved()
        self.assertTrue(replay(str(self.path))['verified'])

    def test_demand_letter_alone_is_not_payment_authorization(self):
        self.contract()
        self.step(op='alias', name='libv', binary='bin:V')
        self.credential('cred-A', 'bin:V', 'ben-A', 100)
        self.build('sha256:img1', ['libv'])
        self.step(op='deliver', id='d1', contract='C1', digest='sha256:img1',
                  territory='EU', at=10, confirmation='s1')
        # 未登记的催告函不能立案，更不能授权付款
        self.assertEqual(self.step(op='dispute', id='disp-x', obligation='C1|bin:V',
                                   claimant='B', credential='letter-from-B', at=11)['decision'], 'unknown_credential')
        # 代码指纹对不上的凭据不能主张该二进制
        self.credential('cred-Z', 'bin:Z', 'ben-Z', 100)
        self.assertEqual(self.step(op='dispute', id='disp-z', obligation='C1|bin:V',
                                   claimant='Z', credential='cred-Z', at=11)['decision'], 'fingerprint_mismatch')
        # 转授权链断裂的凭据不能登记
        self.assertEqual(self.step(op='credential', id='cred-orphan', binary='bin:V', holder='B',
                                   beneficiary='ben-B', license_version='v', rate=100,
                                   chain='missing-parent', territory='*', signed_at=1,
                                   registered_at=2, effective_from=2)['decision'], 'chain_broken')
        # 没有争议就没有监管、承保或预付
        self.assertEqual(self.step(op='escrow', id='e-x', obligation='C1|bin:V',
                                   account='escrow-c1', at=11)['decision'], 'not_disputed')
        self.assertEqual(self.step(op='advance', id='a-x', obligation='C1|bin:V', at=11)['decision'], 'not_disputed')
        # 唯一可付路径是钉定凭据上的税务受益人
        r = self.step(op='settle', id='pay-1', obligation='C1|bin:V', at=12)
        self.assertEqual(r['decision'], 'settled')
        b = balances(self.db)['total']
        self.assertEqual(b['holder:ben-A'], 100)
        self.assertNotIn('holder:ben-B', b)
        self.cash_conserved()
        self.assertTrue(replay(str(self.path))['verified'])


if __name__ == '__main__':
    unittest.main()
