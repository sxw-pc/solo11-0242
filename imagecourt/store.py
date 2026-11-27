import json, sqlite3
from contextlib import contextmanager

SCHEMA="""
CREATE TABLE IF NOT EXISTS manifests(digest TEXT PRIMARY KEY,tag TEXT,batch TEXT,generation INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS attestations(id TEXT PRIMARY KEY,digest TEXT,signer TEXT,source TEXT,recipe TEXT,generation INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS sboms(digest TEXT PRIMARY KEY,components TEXT,revision INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS risks(id TEXT PRIMARY KEY,digest TEXT,severity INTEGER,revision INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS signer_scope(signer TEXT,source TEXT,PRIMARY KEY(signer,source));
CREATE TABLE IF NOT EXISTS channels(environment TEXT PRIMARY KEY,digest TEXT,generation INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS promotions(id TEXT PRIMARY KEY,digest TEXT,environment TEXT,parent_environment TEXT,status TEXT,generation INTEGER);
CREATE TABLE IF NOT EXISTS exceptions(id TEXT PRIMARY KEY,digest TEXT,environment TEXT,role1 TEXT,role2 TEXT,expires INTEGER,revoked INTEGER);
CREATE TABLE IF NOT EXISTS channel_history(environment TEXT,generation INTEGER,digest TEXT,status TEXT,PRIMARY KEY(environment,generation));
CREATE TABLE IF NOT EXISTS channel_windows(environment TEXT PRIMARY KEY,start INTEGER,expires INTEGER,generation INTEGER);
CREATE TABLE IF NOT EXISTS workloads(id TEXT PRIMARY KEY,environment TEXT,digest TEXT,generation INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS leases(id TEXT PRIMARY KEY,workload TEXT,digest TEXT,channel_generation INTEGER,expires INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS orphans(id TEXT PRIMARY KEY,environment TEXT,digest TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS revocations(id TEXT PRIMARY KEY,digest TEXT,generation INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,subsystem TEXT,payload TEXT,result TEXT);
CREATE TABLE IF NOT EXISTS rack_feeds(rack TEXT,feed TEXT,breaker TEXT,PRIMARY KEY(rack,feed));
CREATE TABLE IF NOT EXISTS rack_workloads(rack TEXT,workload TEXT,PRIMARY KEY(rack,workload));
CREATE TABLE IF NOT EXISTS breaker_commands(id TEXT PRIMARY KEY,breaker TEXT,action TEXT,ack TEXT);
CREATE TABLE IF NOT EXISTS voltage_samples(id TEXT PRIMARY KEY,breaker TEXT,source TEXT,volts INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS electrical_permits(id TEXT PRIMARY KEY,rack TEXT,status TEXT,issued_at INTEGER,scope TEXT,disposition TEXT,evidence TEXT,supersedes TEXT,revoked_at INTEGER,revoke_reason TEXT);
CREATE TABLE IF NOT EXISTS racks(id TEXT PRIMARY KEY,generation INTEGER,standby_for TEXT);
CREATE TABLE IF NOT EXISTS backfeed_paths(id TEXT PRIMARY KEY,rack TEXT,breaker TEXT,label TEXT,state TEXT,cleared_at INTEGER);
CREATE TABLE IF NOT EXISTS repair_parts(serial TEXT PRIMARY KEY,rack TEXT,position TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS repair_windows(rack TEXT PRIMARY KEY,start INTEGER,expires INTEGER,generation INTEGER);
CREATE TABLE IF NOT EXISTS switch_commands(id TEXT PRIMARY KEY,rack TEXT,breaker TEXT,action TEXT,state TEXT,at INTEGER,reason TEXT);
CREATE TABLE IF NOT EXISTS switch_positions(id TEXT PRIMARY KEY,breaker TEXT,position TEXT,source TEXT,trusted INTEGER,at INTEGER);
CREATE TABLE IF NOT EXISTS lockouts(id TEXT PRIMARY KEY,rack TEXT,breaker TEXT,technician TEXT,state TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS probe_calibrations(probe TEXT,calibrated_at INTEGER,valid_until INTEGER,generation INTEGER,PRIMARY KEY(probe,generation));
CREATE TABLE IF NOT EXISTS permit_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,permit_id TEXT,event TEXT,at INTEGER,detail TEXT);
CREATE TABLE IF NOT EXISTS field_entries(id TEXT PRIMARY KEY,permit_id TEXT,rack TEXT,technician TEXT,state TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS workload_migrations(id TEXT PRIMARY KEY,workload TEXT,source_rack TEXT,target_rack TEXT,state TEXT,at INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS build_outputs(id TEXT PRIMARY KEY,workload TEXT,rack TEXT,digest TEXT,seq INTEGER,state TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS service_decisions(id TEXT PRIMARY KEY,lease_id TEXT,workload TEXT,kind TEXT,responsibility TEXT,at INTEGER,deadline_loss INTEGER,detail TEXT);
CREATE TABLE IF NOT EXISTS customer_notices(id TEXT PRIMARY KEY,lease_id TEXT,kind TEXT,state TEXT,at INTEGER,detail TEXT,supersedes TEXT);
CREATE TABLE IF NOT EXISTS repair_acceptances(rack TEXT PRIMARY KEY,at INTEGER,permit_id TEXT,detail TEXT);
"""

def connect(path):
    db=sqlite3.connect(path,isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA busy_timeout=3000')
    db.executescript(SCHEMA)
    return db

@contextmanager
def tx(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield
        db.execute('COMMIT')
    except BaseException:
        db.execute('ROLLBACK')
        raise

def one(db,sql,args=()):
    row=db.execute(sql,args).fetchone()
    return dict(row) if row else None

def rows(db,sql,args=()):
    return [dict(x) for x in db.execute(sql,args)]

def execute(db,subsystem,payload):
    from . import provenance,channel,admission,electrical_control,power_meter
    fn={'provenance':provenance.run,'channel':channel.run,'admission':admission.run,
        'electrical':electrical_control.run,'meter':power_meter.run}[subsystem]
    with tx(db):
        result=fn(db,payload)
        db.execute('INSERT INTO events(subsystem,payload,result) VALUES(?,?,?)',
                   (subsystem,json.dumps(payload,sort_keys=True,ensure_ascii=False),json.dumps(result,sort_keys=True,ensure_ascii=False)))
        return result

def replay(path):
    source=connect(path)
    events=rows(source,'SELECT subsystem,payload,result FROM events ORDER BY seq')
    target=connect(':memory:')
    errors=[]
    for index,item in enumerate(events,1):
        actual=execute(target,item['subsystem'],json.loads(item['payload']))
        if actual!=json.loads(item['result']):errors.append({'step':index,'reason':'decision'})
    tables=[x[0] for x in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence','events') ORDER BY name")]
    for table in tables:
        before=[tuple(x) for x in source.execute(f'SELECT * FROM {table} ORDER BY rowid')]
        after=[tuple(x) for x in target.execute(f'SELECT * FROM {table} ORDER BY rowid')]
        if before!=after:errors.append({'table':table,'reason':'state'})
    source.close();target.close()
    return {'verified':not errors,'decisions':len(events),'errors':errors}
