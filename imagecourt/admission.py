from .store import one,rows
from .channel import candidate_ok

def run(db,x):
    op=x['op']
    if op=='workload':
        old=one(db,'SELECT * FROM workloads WHERE id=?',(x['id'],))
        if old:return {'decision':'reused' if (old['digest'],old['environment'],old['generation'])==(x['digest'],x['environment'],x['generation']) else 'workload_identity_conflict'}
        db.execute('INSERT INTO workloads VALUES(?,?,?,?,?)',(x['id'],x['environment'],x['digest'],x['generation'],'registered'))
        return {'decision':'registered'}
    if op=='admit':
        w=one(db,'SELECT * FROM workloads WHERE id=?',(x['workload'],))
        c=one(db,"SELECT * FROM channels WHERE environment=? AND status='active'",(w['environment'],)) if w else None
        if not w or w['generation']!=x['generation'] or not c or c['digest']!=w['digest'] or c['generation']!=x['channel_generation']:
            return {'decision':'identity_or_channel_mismatch'}
        if w['status']!='registered':return {'decision':'workload_not_admissible'}
        if not candidate_ok(db,w['digest'],w['environment'],x['at']):return {'decision':'source_invalidated'}
        old=one(db,'SELECT * FROM leases WHERE id=?',(x['id'],))
        if old:return {'decision':'reused' if old['workload']==x['workload'] else 'lease_identity_conflict'}
        if x['expires']<=x['at']:return {'decision':'invalid_lease'}
        db.execute('INSERT INTO leases VALUES(?,?,?,?,?,?)',(x['id'],w['id'],w['digest'],c['generation'],x['expires'],'active'))
        db.execute("UPDATE workloads SET status='running' WHERE id=?",(w['id'],))
        return {'decision':'admitted'}
    if op=='expire':
        lease=one(db,'SELECT * FROM leases WHERE id=?',(x['id'],))
        if not lease or x['at']<=lease['expires']:return {'decision':'not_expired'}
        db.execute("UPDATE leases SET status='expired' WHERE id=?",(x['id'],))
        db.execute("UPDATE workloads SET status='registered' WHERE id=? AND status='running'",(lease['workload'],))
        return {'decision':'expired'}
    if op=='renew':
        lease=one(db,'SELECT * FROM leases WHERE id=?',(x['id'],))
        if not lease or lease['status']!='active':return {'decision':'lease_unavailable'}
        w=one(db,'SELECT * FROM workloads WHERE id=?',(lease['workload'],))
        c=one(db,'SELECT * FROM channels WHERE environment=?',(w['environment'],))
        if not c or c['generation']!=lease['channel_generation'] or not candidate_ok(db,lease['digest'],w['environment'],x['at']):
            return {'decision':'renewal_invalidated'}
        if x['expires']<=x['at'] or x['at']>lease['expires']:return {'decision':'expired_lease'}
        db.execute('UPDATE leases SET expires=? WHERE id=?',(x['expires'],x['id']))
        return {'decision':'renewed'}
    if op=='orphan':
        old=one(db,'SELECT * FROM orphans WHERE id=?',(x['id'],))
        if old:return {'decision':'reused' if old['digest']==x['digest'] else 'orphan_conflict'}
        db.execute('INSERT INTO orphans VALUES(?,?,?,?)',(x['id'],x['environment'],x['digest'],'unresolved'))
        return {'decision':'isolated'}
    if op=='clear_orphan':
        o=one(db,'SELECT * FROM orphans WHERE id=?',(x['id'],))
        if not o or x['proof_digest']!=o['digest']:return {'decision':'invalid_clearance'}
        db.execute("UPDATE orphans SET status='cleared' WHERE id=?",(x['id'],))
        return {'decision':'cleared'}
    if op=='isolate':
        lease=one(db,'SELECT * FROM leases WHERE id=?',(x['id'],))
        if not lease:return {'decision':'unknown_lease'}
        db.execute("UPDATE leases SET status='isolated' WHERE id=?",(x['id'],))
        db.execute("UPDATE workloads SET status='isolated' WHERE id=?",(lease['workload'],))
        return {'decision':'isolated'}
    if op=='review':
        c=one(db,'SELECT * FROM channels WHERE environment=?',(x['environment'],))
        if not c:return {'decision':'no_channel'}
        risks=rows(db,"SELECT id FROM leases WHERE digest=? AND status='risk'",(c['digest'],))
        orphans=rows(db,"SELECT id FROM orphans WHERE environment=? AND status='unresolved'",(x['environment'],))
        return {'decision':'blocked' if risks or orphans else 'clear','risks':[r['id'] for r in risks],'orphans':[o['id'] for o in orphans]}
    raise ValueError(op)
