from .store import one,rows
from .provenance import trusted

def exception_valid(db,digest,environment,at):
    return bool(one(db,"SELECT id FROM exceptions WHERE digest=? AND environment=? AND revoked=0 AND expires>=? AND role1!=role2",(digest,environment,at)))

def candidate_ok(db,digest,environment,at):
    return trusted(db,digest) or (trusted(db,digest,allow_risk=True) and exception_valid(db,digest,environment,at))

def run(db,x):
    op=x['op']
    if op=='exception':
        if x['role1']==x['role2'] or x['expires']<=x['at']:return {'decision':'invalid_approval'}
        old=one(db,'SELECT * FROM exceptions WHERE id=?',(x['id'],))
        if old:return {'decision':'reused' if old['digest']==x['digest'] else 'exception_conflict'}
        db.execute('INSERT INTO exceptions VALUES(?,?,?,?,?,?,0)',(x['id'],x['digest'],x['environment'],x['role1'],x['role2'],x['expires']))
        return {'decision':'approved'}
    if op=='revoke_exception':
        db.execute('UPDATE exceptions SET revoked=1 WHERE id=?',(x['id'],))
        return {'decision':'revoked'}
    if op=='propose':
        if not candidate_ok(db,x['digest'],x['environment'],x['at']):return {'decision':'untrusted_candidate'}
        if x.get('parent_environment'):
            parent=one(db,"SELECT * FROM channels WHERE environment=? AND status='active'",(x['parent_environment'],))
            if not parent or parent['digest']!=x['digest']:return {'decision':'upstream_not_promoted'}
        active=one(db,"SELECT id FROM promotions WHERE environment=? AND status='pending'",(x['environment'],))
        if active:return {'decision':'promotion_competition'}
        old=one(db,'SELECT * FROM promotions WHERE id=?',(x['id'],))
        if old:return {'decision':'reused' if old['digest']==x['digest'] else 'promotion_id_conflict'}
        gen=(one(db,'SELECT generation FROM channels WHERE environment=?',(x['environment'],)) or {}).get('generation',0)+1
        db.execute('INSERT INTO promotions VALUES(?,?,?,?,?,?)',(x['id'],x['digest'],x['environment'],x.get('parent_environment'),'pending',gen))
        return {'decision':'pending','generation':gen}
    if op=='publish':
        p=one(db,'SELECT * FROM promotions WHERE id=?',(x['id'],))
        if not p or p['status']!='pending':return {'decision':'no_pending_promotion'}
        if not candidate_ok(db,p['digest'],p['environment'],x['at']):return {'decision':'candidate_invalidated'}
        if p['parent_environment']:
            parent=one(db,"SELECT * FROM channels WHERE environment=? AND status='active'",(p['parent_environment'],))
            if not parent or parent['digest']!=p['digest']:return {'decision':'upstream_changed'}
        current=one(db,'SELECT * FROM channels WHERE environment=?',(p['environment'],))
        if current and current['generation']+1!=p['generation']:return {'decision':'stale_channel'}
        db.execute('INSERT INTO channels VALUES(?,?,?,?) ON CONFLICT(environment) DO UPDATE SET digest=excluded.digest,generation=excluded.generation,status=excluded.status',
                   (p['environment'],p['digest'],p['generation'],'active'))
        db.execute('INSERT INTO channel_history VALUES(?,?,?,?)',(p['environment'],p['generation'],p['digest'],'active'))
        db.execute("UPDATE promotions SET status='published' WHERE id=?",(x['id'],))
        return {'decision':'published','generation':p['generation']}
    if op=='withdraw':
        current=one(db,'SELECT * FROM channels WHERE environment=?',(x['environment'],))
        if not current:return {'decision':'no_channel'}
        blockers=rows(db,"SELECT id FROM leases WHERE digest=? AND status IN ('active','risk')",(current['digest'],))
        blockers+=rows(db,"SELECT id FROM orphans WHERE environment=? AND digest=? AND status='unresolved'",(x['environment'],current['digest']))
        if blockers:return {'decision':'dependent_runtime','ids':[b['id'] for b in blockers]}
        historical=rows(db,'SELECT * FROM channel_history WHERE environment=? AND generation<? ORDER BY generation DESC',(x['environment'],current['generation']))
        target=next((h for h in historical if candidate_ok(db,h['digest'],x['environment'],x['at'])),None)
        if not target:return {'decision':'no_trusted_fallback'}
        generation=current['generation']+1
        db.execute('UPDATE channels SET digest=?,generation=?,status=? WHERE environment=?',(target['digest'],generation,'active',x['environment']))
        db.execute('INSERT INTO channel_history VALUES(?,?,?,?)',(x['environment'],generation,target['digest'],'rollback'))
        return {'decision':'rolled_back','digest':target['digest']}
    raise ValueError(op)
