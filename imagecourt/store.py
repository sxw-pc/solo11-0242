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
CREATE TABLE IF NOT EXISTS cooling_loops(id TEXT PRIMARY KEY,site TEXT,flow_limit INTEGER,temp_limit INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS water_samples(id TEXT PRIMARY KEY,loop TEXT,point TEXT,at INTEGER,flow INTEGER,temperature INTEGER);
CREATE TABLE IF NOT EXISTS cooling_builds(id TEXT PRIMARY KEY,batch TEXT,loop TEXT,starts INTEGER,ends INTEGER);
CREATE TABLE IF NOT EXISTS water_reports(id TEXT PRIMARY KEY,loop TEXT,period TEXT,volume INTEGER,status TEXT);
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
    from . import provenance,channel,admission,cooling
    fn={'provenance':provenance.run,'channel':channel.run,'admission':admission.run,'cooling':cooling.run}[subsystem]
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
