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
CREATE TABLE IF NOT EXISTS structural_zones(id TEXT PRIMARY KEY,site TEXT,load_limit INTEGER,revision INTEGER,status TEXT,drawing_revision TEXT);
CREATE TABLE IF NOT EXISTS structural_elements(id TEXT PRIMARY KEY,zone TEXT,kind TEXT,shared INTEGER,rated_limit INTEGER,current_limit INTEGER,shoring_id TEXT);
CREATE TABLE IF NOT EXISTS structural_sensors(id TEXT PRIMARY KEY,location TEXT,calibration TEXT,uncertainty REAL,status TEXT);
CREATE TABLE IF NOT EXISTS shaking_samples(id TEXT PRIMARY KEY,zone TEXT,sensor TEXT,at INTEGER,acceleration INTEGER,aftershock_seq INTEGER);
CREATE TABLE IF NOT EXISTS structural_inspections(id TEXT PRIMARY KEY,zone TEXT,engineer TEXT,at INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS field_evidence(id TEXT PRIMARY KEY,zone TEXT,kind TEXT,engineer TEXT,at INTEGER,location TEXT,measurement TEXT,severity TEXT);
CREATE TABLE IF NOT EXISTS engineer_assessments(id TEXT PRIMARY KEY,zone TEXT,engineer TEXT,at INTEGER,drawing_revision TEXT,safe_load INTEGER,basis TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS shoring_works(id TEXT PRIMARY KEY,zone TEXT,element TEXT,engineer TEXT,completed_at INTEGER,measured_load INTEGER,monitoring_cycle INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS site_racks(id TEXT PRIMARY KEY,zone TEXT,mass INTEGER,function TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS rack_anchors(id TEXT PRIMARY KEY,rack TEXT,element TEXT,installed_at INTEGER,displacement REAL,checked_at INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS rack_relocations(id TEXT PRIMARY KEY,rack TEXT,from_zone TEXT,to_zone TEXT,engineer TEXT,at INTEGER,verified_at INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS mirror_services(id TEXT PRIMARY KEY,rack TEXT,function TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS mirror_switchovers(id TEXT PRIMARY KEY,service TEXT,from_rack TEXT,to_rack TEXT,at INTEGER,check_ref TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS service_restorations(id TEXT PRIMARY KEY,service TEXT,rack TEXT,at INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS reentry_certificates(id TEXT PRIMARY KEY,zone TEXT,engineer TEXT,assessment TEXT,at INTEGER,strategy TEXT,accessible INTEGER,occupant_limit INTEGER,retained_racks TEXT,removed_racks TEXT,deload_deadline INTEGER,monitoring_cycle INTEGER,aftershock_seq INTEGER,void_reason TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS structural_notices(id TEXT PRIMARY KEY,recipient TEXT,zone TEXT,engineer TEXT,at INTEGER,supersedes TEXT,subject TEXT,body TEXT,status TEXT);
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
    from . import provenance,channel,admission,structure,rack
    fn={'provenance':provenance.run,'channel':channel.run,'admission':admission.run,'structure':structure.run,'rack':rack.run}[subsystem]
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
