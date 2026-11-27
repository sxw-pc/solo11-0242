from .store import one,rows
from .channel import candidate_ok
from . import safety

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
    if op=='contract_pause':
        lease=one(db,'SELECT * FROM leases WHERE id=?',(x['id'],))
        if not lease:return {'decision':'unknown_lease'}
        if lease['status']!='active':return {'decision':'lease_unavailable'}
        w=one(db,'SELECT * FROM workloads WHERE id=?',(lease['workload'],))
        db.execute('INSERT INTO service_decisions VALUES(?,?,?,?,?,?,?)',
                   (x['decision_id'],lease['id'],w['id'],'contract_pause',x['responsibility'],x['at'],x.get('deadline_loss',0),x.get('detail','')))
        db.execute("UPDATE leases SET status='paused' WHERE id=?",(lease['id'],))
        db.execute("UPDATE workloads SET status='paused' WHERE id=?",(w['id'],))
        return {'decision':'paused','responsibility':x['responsibility'],'deadline_loss':x.get('deadline_loss',0)}
    if op=='stop_build':
        lease=one(db,'SELECT * FROM leases WHERE id=?',(x['id'],))
        if not lease:return {'decision':'unknown_lease'}
        if lease['status']!='active':return {'decision':'lease_unavailable'}
        w=one(db,'SELECT * FROM workloads WHERE id=?',(lease['workload'],))
        db.execute("UPDATE leases SET status='stopped' WHERE id=?",(lease['id'],))
        db.execute("UPDATE workloads SET status='stopped' WHERE id=?",(w['id'],))
        db.execute('INSERT INTO service_decisions VALUES(?,?,?,?,?,?,?)',
                   (x['decision_id'],lease['id'],w['id'],'stop_build','maintenance',x['at'],x.get('deadline_loss',0),x.get('detail','')))
        return {'decision':'stopped'}
    if op=='migrate':
        lease=one(db,'SELECT * FROM leases WHERE id=?',(x['id'],))
        if not lease:return {'decision':'unknown_lease'}
        if lease['status']!='active':return {'decision':'lease_unavailable'}
        w=one(db,'SELECT * FROM workloads WHERE id=?',(lease['workload'],))
        if not one(db,'SELECT 1 FROM rack_workloads WHERE rack=? AND workload=?',(x['source_rack'],w['id'])):
            return {'decision':'workload_not_on_source_rack'}
        standby=one(db,'SELECT * FROM racks WHERE id=?',(x['target_rack'],))
        if not standby or standby['standby_for']!=x['source_rack']:
            return {'decision':'target_not_standby_rack'}
        if safety._running_workloads(db,x['target_rack']):
            return {'decision':'target_rack_occupied'}
        partial=rows(db,"SELECT id FROM build_outputs WHERE workload=? AND state='partial'",(w['id'],))
        if partial:return {'decision':'partial_output_on_source','ids':[p['id'] for p in partial]}
        old=one(db,'SELECT * FROM workload_migrations WHERE id=?',(x['migration_id'],))
        if old:return {'decision':'reused'}
        db.execute('INSERT INTO workload_migrations VALUES(?,?,?,?,?,?)',
                   (x['migration_id'],w['id'],x['source_rack'],x['target_rack'],'in_progress',x['at'],
                    'awaiting resumed output evidence on standby rack'))
        return {'decision':'migration_started','migration':x['migration_id']}
    if op=='transfer':
        m=one(db,'SELECT * FROM workload_migrations WHERE id=?',(x['id'],))
        if not m:return {'decision':'unknown_migration'}
        if m['state']!='in_progress':return {'decision':'migration_not_open'}
        db.execute('DELETE FROM rack_workloads WHERE rack=? AND workload=?',(m['source_rack'],m['workload']))
        db.execute('INSERT INTO rack_workloads VALUES(?,?)',(m['target_rack'],m['workload']))
        return {'decision':'transferred'}
    if op=='build_output':
        w=one(db,'SELECT * FROM workloads WHERE id=?',(x['workload'],))
        if not w:return {'decision':'unknown_workload'}
        old=one(db,'SELECT * FROM build_outputs WHERE id=?',(x['id'],))
        if old:return {'decision':'reused'}
        if x['state'] not in ('partial','complete'):return {'decision':'invalid_output_state'}
        prior=one(db,'SELECT MAX(seq) AS s FROM build_outputs WHERE workload=?',(x['workload'],))
        seq=(prior['s'] or 0)+1
        if x['state']=='complete' and x['digest']!=w['digest']:
            return {'decision':'output_digest_mismatch'}
        db.execute('INSERT INTO build_outputs VALUES(?,?,?,?,?,?)',
                   (x['id'],x['workload'],x['rack'],x['digest'],seq,x['state'],x['at']))
        return {'decision':x['state'],'seq':seq}
    if op=='verify_migration':
        m=one(db,'SELECT * FROM workload_migrations WHERE id=?',(x['id'],))
        if not m:return {'decision':'unknown_migration'}
        if m['state']!='in_progress':return {'decision':'migration_not_open'}
        complete=one(db,"SELECT * FROM build_outputs WHERE workload=? AND rack=? AND state='complete' ORDER BY seq DESC LIMIT 1",
                     (m['workload'],m['target_rack']))
        if not complete:return {'decision':'no_complete_output_on_target'}
        chained=rows(db,'SELECT id FROM build_outputs WHERE workload=? ORDER BY seq',(m['workload'],))
        if not any(o['rack']==m['source_rack'] for o in chained):
            return {'decision':'missing_source_output_chain'}
        db.execute("UPDATE workload_migrations SET state='verified',evidence=? WHERE id=?",
                   (f"complete output {complete['id']} on {m['target_rack']}; chain of {len(chained)} outputs",x['id']))
        db.execute('INSERT INTO service_decisions VALUES(?,?,?,?,?,?,?)',
                   (x['decision_id'],x.get('lease_id',''),m['workload'],'migration','none',x['at'],0,m['id']))
        return {'decision':'migration_verified','migration':x['id'],'output':complete['id']}
    if op=='restart':
        acceptance=one(db,'SELECT * FROM repair_acceptances WHERE rack=?',(x['rack'],))
        if not acceptance:return {'decision':'repair_not_accepted'}
        lease=one(db,'SELECT * FROM leases WHERE id=?',(x['id'],))
        if not lease:return {'decision':'unknown_lease'}
        if lease['status'] not in ('paused','stopped','isolated'):return {'decision':'lease_not_restartable'}
        w=one(db,'SELECT * FROM workloads WHERE id=?',(lease['workload'],))
        c=one(db,'SELECT * FROM channels WHERE environment=?',(w['environment'],))
        if not c or c['digest']!=w['digest'] or c['generation']!=lease['channel_generation']:
            return {'decision':'channel_changed_during_outage'}
        if not candidate_ok(db,w['digest'],w['environment'],x['at']):
            return {'decision':'source_invalidated'}
        db.execute("UPDATE leases SET status='active' WHERE id=?",(lease['id'],))
        db.execute("UPDATE workloads SET status='running' WHERE id=?",(w['id'],))
        return {'decision':'restarted','rack':x['rack']}
    if op=='notice':
        lease=one(db,'SELECT * FROM leases WHERE id=?',(x['lease_id'],))
        if not lease:return {'decision':'unknown_lease'}
        old=one(db,'SELECT * FROM customer_notices WHERE id=?',(x['id'],))
        if old:return {'decision':'reused'}
        db.execute('INSERT INTO customer_notices VALUES(?,?,?,?,?,?,?)',
                   (x['id'],x['lease_id'],x['kind'],'sent',x['at'],x.get('detail',''),None))
        return {'decision':'notice_sent'}
    if op=='correct_notice':
        bad=one(db,'SELECT * FROM customer_notices WHERE id=?',(x['id'],))
        if not bad:return {'decision':'unknown_notice'}
        if bad['state']!='sent':return {'decision':'notice_already_corrected'}
        db.execute("UPDATE customer_notices SET state='corrected' WHERE id=?",(x['id'],))
        db.execute('INSERT INTO customer_notices VALUES(?,?,?,?,?,?,?)',
                   (x['new_id'],bad['lease_id'],x['kind'],'sent',x['at'],x['detail'],bad['id']))
        return {'decision':'notice_corrected','original':x['id'],'replacement':x['new_id']}
    raise ValueError(op)
