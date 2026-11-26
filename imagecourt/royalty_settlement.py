"""发行版税结算：以可复算的发行义务连接构建证据、许可链与实际副本交付。

结算对象是每一（合同，组件二进制）恰一次的发行义务，钉在实际交付的镜像摘要、
交付时刻可适用的许可版本、客户取得副本的时刻与地域上。清单修订、租约续期或重试、
组件改名与依赖嵌套都不能改写或复制已钉定的义务；权利人身份、转授权链与税务受益人
只由独立登记的凭据建立，单张催告函不能充当付款授权。许可迟到、转授权撤销与权利
裁决只通过可追索的追加清偿更正；全部资金变动记入幂等台账，事件重放不会让客户或
权利人任何一边的余额增加。
"""
import json

from .store import one, rows

CASH_KINDS = ('payment', 'advance', 'recovery', 'recourse_recovery',
              'escrow_deposit', 'escrow_release', 'supplementary_payment')
BILL_KINDS = ('invoice', 'supplementary_invoice', 'credit_note')


def _chain_ok(db, chain, signed_at):
    # 转授权链只在母权利已公开登记且签署不早于其登记时完整
    if chain == 'root':
        return True
    parent = one(db, 'SELECT * FROM rights_credentials WHERE id=?', (chain,))
    return bool(parent) and parent['status'] != 'revoked' and signed_at >= parent['registered_at']


def _applicable(db, binary, territory, delivered_at, as_of):
    # 在 as_of 之前登记、对交付时刻生效、覆盖交付地域的最新许可版本
    found = rows(db, """SELECT * FROM rights_credentials
        WHERE binary=? AND status!='revoked' AND (territory='*' OR territory=?)
        AND effective_from<=? AND registered_at<=?
        ORDER BY effective_from DESC, registered_at DESC, id DESC""",
                 (binary, territory, delivered_at, as_of))
    return found[0] if found else None


def _current(db, ob):
    # 当前适用 = 最近一次更正，否则回到交付时钉定的许可；钉定记录本身永不改写
    c = one(db, 'SELECT * FROM corrections WHERE obligation=? ORDER BY at DESC, rowid DESC LIMIT 1', (ob['id'],))
    cid = c['credential'] if c else ob['credential']
    amount = c['amount'] if c else ob['amount']
    if not cid:
        return {'credential': None, 'beneficiary': None, 'amount': 0, 'license_version': None}
    cred = one(db, 'SELECT * FROM rights_credentials WHERE id=?', (cid,))
    return {'credential': cid, 'beneficiary': cred['beneficiary'], 'amount': amount,
            'license_version': cred['license_version']}


def _positions(db, oid):
    marks = ','.join('?' * len(CASH_KINDS))
    return {r['account']: r['total'] for r in rows(
        db, 'SELECT account, SUM(amount) AS total FROM ledger WHERE obligation=? AND kind IN (%s) GROUP BY account' % marks,
        (oid,) + CASH_KINDS)}


def _post(db, op, kind, oid, entries, at):
    posted = []
    for account, amount in entries:
        if not amount:
            continue
        db.execute('INSERT INTO ledger VALUES(?,?,?,?,?,?,?)',
                   ('::'.join((op, kind, oid, account)), op, kind, account, oid, amount, at))
        posted.append({'kind': kind, 'account': account, 'amount': amount})
    return posted


def _settle_holder_side(db, op, ob, beneficiary, amount, at, payment_kind, recovery_kind):
    """让有资格的权利人净得 amount、其余持有人归零；先动用合同监管账户，再动用财务。"""
    oid = ob['id']
    pos = _positions(db, oid)
    target = 'holder:' + beneficiary if beneficiary else None
    posted = []
    for account in sorted(pos):
        if not account.startswith('holder:'):
            continue
        want = amount if account == target else 0
        if pos[account] > want:
            delta = pos[account] - want
            posted += _post(db, op, recovery_kind, oid, [(account, -delta), ('finance', delta)], at)
            pos[account] = want
    if target:
        need = amount - pos.get(target, 0)
        for account in sorted(a for a in pos if a.startswith('escrow:') and pos[a] > 0):
            if need <= 0:
                break
            take = min(need, pos[account])
            posted += _post(db, op, 'escrow_release', oid, [(target, take), (account, -take)], at)
            need -= take
        if need > 0:
            posted += _post(db, op, payment_kind, oid, [(target, need), ('finance', -need)], at)
    return posted


def _obligation(db, oid):
    return one(db, 'SELECT * FROM obligations WHERE id=?', (oid,))


def _open_dispute(db, oid):
    return one(db, "SELECT * FROM disputes WHERE obligation=? AND status='open'", (oid,))


def _billed(db, oid):
    marks = ','.join('?' * len(BILL_KINDS))
    return one(db, 'SELECT COALESCE(SUM(amount),0) AS t FROM ledger WHERE obligation=? AND kind IN (%s)' % marks,
               (oid,) + BILL_KINDS)['t']


def run(db, x):
    op = x['op']
    if op == 'contract':
        old = one(db, 'SELECT * FROM contracts WHERE id=?', (x['id'],))
        if old:
            same = (old['customer'], old['escrow_account'], old['underwriter']) == (x['customer'], x['escrow_account'], x['underwriter'])
            return {'decision': 'reused' if same else 'contract_conflict'}
        db.execute('INSERT INTO contracts VALUES(?,?,?,?)', (x['id'], x['customer'], x['escrow_account'], x['underwriter']))
        return {'decision': 'registered'}
    if op == 'alias':
        old = one(db, 'SELECT * FROM binary_aliases WHERE name=?', (x['name'],))
        if old:
            return {'decision': 'reused' if old['binary'] == x['binary'] else 'alias_conflict'}
        db.execute('INSERT INTO binary_aliases VALUES(?,?)', (x['name'], x['binary']))
        return {'decision': 'registered'}
    if op == 'credential':
        old = one(db, 'SELECT * FROM rights_credentials WHERE id=?', (x['id'],))
        if old:
            same = (old['binary'], old['holder'], old['beneficiary'], old['license_version'], old['rate'],
                    old['chain'], old['territory'], old['signed_at'], old['registered_at'], old['effective_from']) == \
                   (x['binary'], x['holder'], x['beneficiary'], x['license_version'], x['rate'],
                    x['chain'], x['territory'], x['signed_at'], x['registered_at'], x['effective_from'])
            return {'decision': 'reused' if same else 'credential_conflict'}
        if x['rate'] < 0:
            return {'decision': 'invalid_rate'}
        if x['chain'] != 'root' and not one(db, 'SELECT id FROM rights_credentials WHERE id=?', (x['chain'],)):
            return {'decision': 'chain_broken'}
        status = 'active' if _chain_ok(db, x['chain'], x['signed_at']) else 'anomalous'
        db.execute('INSERT INTO rights_credentials VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                   (x['id'], x['binary'], x['holder'], x['beneficiary'], x['license_version'], x['rate'],
                    x['chain'], x['territory'], x['signed_at'], x['registered_at'], x['effective_from'], status))
        return {'decision': 'registered' if status == 'active' else 'registered_anomalous'}
    if op == 'revoke_credential':
        cred = one(db, 'SELECT * FROM rights_credentials WHERE id=?', (x['id'],))
        if not cred:
            return {'decision': 'unknown_credential'}
        if cred['status'] == 'revoked':
            return {'decision': 'reused'}
        db.execute("UPDATE rights_credentials SET status='revoked' WHERE id=?", (x['id'],))
        return {'decision': 'revoked'}
    if op == 'deliver':
        c = one(db, 'SELECT * FROM contracts WHERE id=?', (x['contract'],))
        if not c:
            return {'decision': 'unknown_contract'}
        old = one(db, 'SELECT * FROM deliveries WHERE id=?', (x['id'],))
        if old:
            same = (old['contract'], old['digest'], old['territory'], old['delivered_at'], old['confirmation']) == \
                   (x['contract'], x['digest'], x['territory'], x['at'], x['confirmation'])
            return {'decision': 'reused' if same else 'delivery_conflict'}
        if one(db, 'SELECT id FROM deliveries WHERE contract=? AND digest=?', (x['contract'], x['digest'])):
            return {'decision': 'redelivery'}
        if not one(db, "SELECT digest FROM manifests WHERE digest=? AND status='active'", (x['digest'],)):
            return {'decision': 'unknown_digest'}
        s = one(db, "SELECT components FROM sboms WHERE digest=? AND status='complete'", (x['digest'],))
        if not s:
            return {'decision': 'incomplete_evidence'}
        binaries = []
        for name in json.loads(s['components']):
            a = one(db, 'SELECT binary FROM binary_aliases WHERE name=?', (name,))
            if not a:
                return {'decision': 'unknown_component', 'name': name}
            if a['binary'] not in binaries:
                binaries.append(a['binary'])
        db.execute('INSERT INTO deliveries VALUES(?,?,?,?,?,?,?,?)',
                   (x['id'], x['contract'], c['customer'], x['digest'], x['territory'], x['at'],
                    json.dumps(binaries), x['confirmation']))
        created = []
        for b in binaries:
            oid = x['contract'] + '|' + b
            if one(db, 'SELECT id FROM obligations WHERE id=?', (oid,)):
                continue
            cred = _applicable(db, b, x['territory'], x['at'], x['at'])
            if cred:
                db.execute('INSERT INTO obligations VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                           (oid, x['contract'], c['customer'], b, x['digest'], x['territory'], x['at'],
                            cred['id'], cred['license_version'], cred['rate'], 'open'))
                _post(db, x['id'], 'invoice', oid, [('customer:' + c['customer'], cred['rate'])], x['at'])
            else:
                db.execute('INSERT INTO obligations VALUES(?,?,?,?,?,?,?,?,?,?,?)',
                           (oid, x['contract'], c['customer'], b, x['digest'], x['territory'], x['at'],
                            None, None, 0, 'unlicensed'))
            created.append(oid)
        return {'decision': 'delivered', 'obligations': created, 'components': binaries}
    if op == 'settle':
        ob = _obligation(db, x['obligation'])
        if not ob:
            return {'decision': 'unknown_obligation'}
        if ob['status'] == 'settled':
            return {'decision': 'reused'}
        if ob['status'] == 'unlicensed':
            return {'decision': 'unlicensed'}
        if _open_dispute(db, ob['id']):
            return {'decision': 'disputed'}
        cur = _current(db, ob)
        if not cur['credential']:
            return {'decision': 'unlicensed'}
        cred = one(db, 'SELECT * FROM rights_credentials WHERE id=?', (cur['credential'],))
        if cred['status'] == 'revoked':
            return {'decision': 'credential_revoked'}
        posted = _settle_holder_side(db, x['id'], ob, cur['beneficiary'], cur['amount'], x['at'], 'payment', 'recovery')
        db.execute("UPDATE obligations SET status='settled' WHERE id=?", (ob['id'],))
        return {'decision': 'settled', 'beneficiary': cur['beneficiary'], 'amount': cur['amount'], 'posted': posted}
    if op == 'dispute':
        ob = _obligation(db, x['obligation'])
        if not ob:
            return {'decision': 'unknown_obligation'}
        old = one(db, 'SELECT * FROM disputes WHERE id=?', (x['id'],))
        if old:
            same = (old['claimant'], old['credential']) == (x['claimant'], x['credential'])
            return {'decision': 'reused' if same else 'dispute_conflict'}
        if ob['status'] == 'settled':
            return {'decision': 'not_disputable'}
        if ob['status'] == 'unlicensed':
            return {'decision': 'unlicensed'}
        if _open_dispute(db, ob['id']):
            return {'decision': 'dispute_competition'}
        cred = one(db, 'SELECT * FROM rights_credentials WHERE id=?', (x['credential'],))
        if not cred:
            return {'decision': 'unknown_credential'}
        if cred['binary'] != ob['binary']:
            return {'decision': 'fingerprint_mismatch'}
        db.execute('INSERT INTO disputes VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (x['id'], ob['id'], x['claimant'], x['credential'], None, None, None, 'open', None, None))
        db.execute("UPDATE obligations SET status='disputed' WHERE id=?", (ob['id'],))
        return {'decision': 'disputed', 'obligation': ob['id']}
    if op == 'escrow':
        ob = _obligation(db, x['obligation'])
        if not ob:
            return {'decision': 'unknown_obligation'}
        if one(db, 'SELECT id FROM ledger WHERE op=?', (x['id'],)):
            return {'decision': 'reused'}
        d = _open_dispute(db, ob['id'])
        if not d:
            return {'decision': 'not_disputed'}
        c = one(db, 'SELECT * FROM contracts WHERE id=?', (ob['contract'],))
        if x['account'] != c['escrow_account']:
            return {'decision': 'wrong_escrow_account'}
        if d['mode']:
            return {'decision': 'mode_conflict'}
        cur = _current(db, ob)
        posted = _post(db, x['id'], 'escrow_deposit', ob['id'],
                       [('escrow:' + x['account'], cur['amount']), ('finance', -cur['amount'])], x['at'])
        db.execute("UPDATE disputes SET mode='escrow' WHERE id=?", (d['id'],))
        return {'decision': 'escrowed', 'amount': cur['amount'], 'posted': posted}
    if op == 'underwrite':
        ob = _obligation(db, x['obligation'])
        if not ob:
            return {'decision': 'unknown_obligation'}
        if one(db, 'SELECT id FROM ledger WHERE op=?', (x['id'],)):
            return {'decision': 'reused'}
        d = _open_dispute(db, ob['id'])
        if not d:
            return {'decision': 'not_disputed'}
        c = one(db, 'SELECT * FROM contracts WHERE id=?', (ob['contract'],))
        if x['underwriter'] != c['underwriter']:
            return {'decision': 'wrong_underwriter'}
        if d['mode']:
            return {'decision': 'mode_conflict'}
        cur = _current(db, ob)
        posted = _post(db, x['id'], 'indemnity', ob['id'],
                       [('underwriter:' + x['underwriter'], cur['amount'])], x['at'])
        db.execute("UPDATE disputes SET mode='underwritten', underwriter=? WHERE id=?", (x['underwriter'], d['id']))
        return {'decision': 'underwritten', 'amount': cur['amount'], 'posted': posted}
    if op == 'advance':
        ob = _obligation(db, x['obligation'])
        if not ob:
            return {'decision': 'unknown_obligation'}
        if one(db, 'SELECT id FROM ledger WHERE op=?', (x['id'],)):
            return {'decision': 'reused'}
        d = _open_dispute(db, ob['id'])
        if not d:
            return {'decision': 'not_disputed'}
        if d['mode'] != 'underwritten':
            return {'decision': 'not_underwritten'}
        if d['advance_recipient']:
            return {'decision': 'reused', 'recipient': d['advance_recipient']}
        candidates = []
        for cid in dict.fromkeys([ob['credential'], d['credential']]):
            cred = one(db, 'SELECT * FROM rights_credentials WHERE id=?', (cid,)) if cid else None
            if not cred or cred['status'] == 'revoked':
                continue
            score = 2 if cred['status'] == 'active' and _chain_ok(db, cred['chain'], cred['signed_at']) else 1
            candidates.append((score, 1 if cid == ob['credential'] else 0, cred))
        if not candidates:
            return {'decision': 'no_eligible_recipient'}
        cred = max(candidates, key=lambda t: (t[0], t[1]))[2]
        cur = _current(db, ob)
        posted = _post(db, x['id'], 'advance', ob['id'],
                       [('holder:' + cred['beneficiary'], cur['amount']), ('finance', -cur['amount'])], x['at'])
        db.execute('UPDATE disputes SET advance_recipient=? WHERE id=?', (cred['beneficiary'], d['id']))
        return {'decision': 'advanced', 'recipient': cred['beneficiary'], 'credential': cred['id'],
                'amount': cur['amount'], 'posted': posted}
    if op == 'adjudicate':
        ob = _obligation(db, x['obligation'])
        if not ob:
            return {'decision': 'unknown_obligation'}
        d = _open_dispute(db, ob['id'])
        if not d:
            closed = one(db, 'SELECT * FROM disputes WHERE obligation=? AND resolved_by=?', (ob['id'], x['id']))
            if closed:
                return {'decision': 'reused' if closed['winner'] == x['winner'] else 'adjudication_conflict'}
            return {'decision': 'not_disputed'}
        w = one(db, 'SELECT * FROM rights_credentials WHERE id=?', (x['winner'],))
        if not w:
            return {'decision': 'unknown_credential'}
        if w['binary'] != ob['binary']:
            return {'decision': 'fingerprint_mismatch'}
        cur = _current(db, ob)
        posted = _settle_holder_side(db, x['id'], ob, w['beneficiary'], cur['amount'], x['at'],
                                     'payment', 'recourse_recovery')
        if d['mode'] == 'underwritten':
            memo = one(db, "SELECT COALESCE(SUM(amount),0) AS t FROM ledger WHERE obligation=? AND kind='indemnity'",
                       (ob['id'],))['t']
            posted += _post(db, x['id'], 'indemnity_release', ob['id'],
                            [('underwriter:' + d['underwriter'], -memo)], x['at'])
        db.execute("UPDATE disputes SET status='resolved', winner=?, resolved_by=? WHERE id=?",
                   (x['winner'], x['id'], d['id']))
        db.execute("UPDATE obligations SET status='settled' WHERE id=?", (ob['id'],))
        db.execute('INSERT INTO corrections VALUES(?,?,?,?,?)', (x['id'], ob['id'], x['winner'], cur['amount'], x['at']))
        return {'decision': 'resolved', 'paid_to': w['beneficiary'], 'posted': posted}
    if op == 'withdraw_claim':
        ob = _obligation(db, x['obligation'])
        if not ob:
            return {'decision': 'unknown_obligation'}
        d = _open_dispute(db, ob['id'])
        if not d:
            closed = one(db, 'SELECT * FROM disputes WHERE obligation=? AND resolved_by=?', (ob['id'], x['id']))
            if closed:
                return {'decision': 'reused'}
            return {'decision': 'not_disputed'}
        cur = _current(db, ob)
        posted = _settle_holder_side(db, x['id'], ob, cur['beneficiary'], cur['amount'], x['at'], 'payment', 'recovery')
        if d['mode'] == 'underwritten':
            memo = one(db, "SELECT COALESCE(SUM(amount),0) AS t FROM ledger WHERE obligation=? AND kind='indemnity'",
                       (ob['id'],))['t']
            posted += _post(db, x['id'], 'indemnity_release', ob['id'],
                            [('underwriter:' + d['underwriter'], -memo)], x['at'])
        db.execute("UPDATE disputes SET status='withdrawn', resolved_by=? WHERE id=?", (x['id'], d['id']))
        db.execute("UPDATE obligations SET status='settled' WHERE id=?", (ob['id'],))
        return {'decision': 'withdrawn', 'paid_to': cur['beneficiary'], 'posted': posted}
    if op == 'reconcile':
        ob = _obligation(db, x['obligation'])
        if not ob:
            return {'decision': 'unknown_obligation'}
        if one(db, 'SELECT id FROM corrections WHERE id=?', (x['id'],)):
            return {'decision': 'reused'}
        if _open_dispute(db, ob['id']):
            return {'decision': 'disputed'}
        if one(db, "SELECT id FROM disputes WHERE obligation=? AND status='resolved'", (ob['id'],)):
            return {'decision': 'adjudicated'}
        target = _applicable(db, ob['binary'], ob['territory'], ob['delivered_at'], x['at'])
        t_cred = target['id'] if target else None
        t_ben = target['beneficiary'] if target else None
        t_amount = target['rate'] if target else 0
        cur = _current(db, ob)
        billed = _billed(db, ob['id'])
        pos = _positions(db, ob['id'])
        converged = all(net == (t_amount if account == 'holder:' + str(t_ben) else 0)
                        for account, net in pos.items() if account.startswith('holder:'))
        if cur['credential'] == t_cred and cur['amount'] == t_amount and billed == t_amount and converged:
            return {'decision': 'no_change'}
        posted = _settle_holder_side(db, x['id'], ob, t_ben, t_amount, x['at'],
                                     'supplementary_payment', 'recovery')
        if billed < t_amount:
            kind = 'invoice' if billed == 0 else 'supplementary_invoice'
            posted += _post(db, x['id'], kind, ob['id'],
                            [('customer:' + ob['customer'], t_amount - billed)], x['at'])
        elif billed > t_amount:
            posted += _post(db, x['id'], 'credit_note', ob['id'],
                            [('customer:' + ob['customer'], -(billed - t_amount))], x['at'])
        db.execute('INSERT INTO corrections VALUES(?,?,?,?,?)', (x['id'], ob['id'], t_cred, t_amount, x['at']))
        db.execute("UPDATE obligations SET status='settled' WHERE id=?", (ob['id'],))
        return {'decision': 'corrected', 'credential': t_cred, 'amount': t_amount, 'posted': posted}
    raise ValueError(op)


def balances(db):
    """客户、权利人、监管账户、承保方与财务各方的台账余额。"""
    total = {r['account']: r['total'] for r in
             rows(db, 'SELECT account, SUM(amount) AS total FROM ledger GROUP BY account')}
    by_kind = {}
    for r in rows(db, 'SELECT account, kind, SUM(amount) AS total FROM ledger GROUP BY account, kind'):
        by_kind.setdefault(r['account'], {})[r['kind']] = r['total']
    return {'total': total, 'by_kind': by_kind}


def statement(db, customer):
    """向客户说明成本：每项发行义务的钉定与当前许可、账单、争议与清偿凭据。"""
    items = []
    for ob in rows(db, 'SELECT * FROM obligations WHERE customer=? ORDER BY id', (customer,)):
        cur = _current(db, ob)
        d = one(db, 'SELECT status FROM disputes WHERE obligation=?', (ob['id'],))
        delivery = one(db, 'SELECT confirmation FROM deliveries WHERE contract=? AND digest=?',
                       (ob['contract'], ob['digest']))
        items.append({'obligation': ob['id'], 'binary': ob['binary'], 'digest': ob['digest'],
                      'delivered_at': ob['delivered_at'], 'territory': ob['territory'],
                      'pinned_license': ob['license_version'], 'license_version': cur['license_version'],
                      'amount': cur['amount'], 'billed': _billed(db, ob['id']), 'status': ob['status'],
                      'dispute': d['status'] if d else None,
                      'confirmation': delivery['confirmation'] if delivery else None})
    return {'customer': customer, 'total_billed': sum(i['billed'] for i in items), 'obligations': items}
