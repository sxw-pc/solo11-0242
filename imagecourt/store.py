import hashlib, json, sqlite3
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
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,subsystem TEXT,payload TEXT,result TEXT,payload_hash TEXT,result_hash TEXT,prev_hash TEXT,record_hash TEXT);
CREATE TABLE IF NOT EXISTS artifact_copies(id TEXT PRIMARY KEY,digest TEXT,tenant TEXT,site TEXT,payload TEXT,state TEXT DEFAULT 'present');
CREATE TABLE IF NOT EXISTS preservation_orders(id TEXT PRIMARY KEY,tenant TEXT,digest TEXT,scope TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS erase_requests(id TEXT PRIMARY KEY,tenant TEXT,digest TEXT,at INTEGER,status TEXT);

-- Erasure & minimal-hold extension (see tests/test_erasure_hold.py)
CREATE TABLE IF NOT EXISTS artifact_segments(
  id TEXT PRIMARY KEY,copy_id TEXT,tenant TEXT,digest TEXT,site TEXT,
  seg_key TEXT,category TEXT,start_off INTEGER,end_off INTEGER,content TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS artifact_caches(
  id TEXT PRIMARY KEY,tenant TEXT,digest TEXT,site TEXT,copy_id TEXT,payload TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS runtime_artifacts(
  id TEXT PRIMARY KEY,tenant TEXT,digest TEXT,site TEXT,lease_id TEXT,workload_id TEXT,
  copy_id TEXT,payload TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS artifact_backups(
  id TEXT PRIMARY KEY,tenant TEXT,digest TEXT,site TEXT,copy_id TEXT,payload TEXT,state TEXT);
CREATE TABLE IF NOT EXISTS court_signers(
  signer TEXT PRIMARY KEY,authority TEXT,accredited_at INTEGER);
CREATE TABLE IF NOT EXISTS custody_keys(
  key_ref TEXT PRIMARY KEY,order_id TEXT,custodian TEXT,purpose TEXT,
  fingerprint TEXT,status TEXT,created_at INTEGER,destroyed_at INTEGER);
CREATE TABLE IF NOT EXISTS custody_items(
  id TEXT PRIMARY KEY,order_id TEXT,tenant TEXT,digest TEXT,range_index INTEGER,
  start_off INTEGER,end_off INTEGER,sealed_blob TEXT,commitment TEXT,
  source_copy_id TEXT,status TEXT,created_at INTEGER);
CREATE TABLE IF NOT EXISTS custody_access(
  id TEXT PRIMARY KEY,order_id TEXT,item_id TEXT,at INTEGER,
  accessor TEXT,purpose TEXT,result TEXT);
CREATE TABLE IF NOT EXISTS judicial_escrows(
  id TEXT PRIMARY KEY,custodian TEXT,endpoint TEXT,reachable INTEGER,updated_at INTEGER);
CREATE TABLE IF NOT EXISTS judicial_extractions(
  id TEXT PRIMARY KEY,request_id TEXT,order_id TEXT,escrow_id TEXT,custodian TEXT,
  at INTEGER,mode TEXT,ranges_json TEXT,receipt TEXT,commitment TEXT,status TEXT,reason TEXT);
CREATE TABLE IF NOT EXISTS escrow_deliveries(
  id TEXT PRIMARY KEY,extraction_id TEXT,order_id TEXT,range_index INTEGER,
  start_off INTEGER,end_off INTEGER,content TEXT,commitment TEXT,at INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS erasure_facts(
  id TEXT PRIMARY KEY,request_id TEXT,at INTEGER,kind TEXT,target_type TEXT,
  target_id TEXT,site TEXT,status TEXT,detail_json TEXT,commitment TEXT);
CREATE TABLE IF NOT EXISTS erasure_certificates(
  id TEXT PRIMARY KEY,request_id TEXT,tenant TEXT,digest TEXT,at INTEGER,status TEXT,
  mode TEXT,scope_json TEXT,ranges_json TEXT,commitments_json TEXT,retained_json TEXT,
  facts_json TEXT,receipt_id TEXT,chain_head TEXT,blockers_json TEXT,issued_at INTEGER);
CREATE TABLE IF NOT EXISTS customer_receipts(
  id TEXT PRIMARY KEY,request_id TEXT,tenant TEXT,digest TEXT,at INTEGER,
  channel TEXT,status TEXT,certificate_id TEXT,detail_json TEXT);
CREATE TABLE IF NOT EXISTS event_redactions(
  seq INTEGER PRIMARY KEY,request_id TEXT,field_path TEXT,original_hash TEXT,
  redacted_at INTEGER,certificate_id TEXT);
CREATE TABLE IF NOT EXISTS retention_faults(
  fault_key TEXT PRIMARY KEY,kind TEXT,active INTEGER,at INTEGER);
"""

# Columns added to tables that existed in the seeded schema.
_MIGRATIONS={
 'artifact_copies':[('state',"TEXT DEFAULT 'present'")],
 'preservation_orders':[
   ('order_kind',"TEXT"),('signer',"TEXT"),('issued_at',"INTEGER"),('matter',"TEXT"),
   ('ranges_json',"TEXT"),('mode',"TEXT"),('custodian',"TEXT"),('key_ref',"TEXT"),
   ('purpose',"TEXT"),('case_ref',"TEXT"),('revoked_at',"INTEGER"),('disposition',"TEXT")],
 'erase_requests':[
   ('scope_json',"TEXT"),('commitments_json',"TEXT"),('mode',"TEXT"),
   ('idempotency_key',"TEXT"),('completed_at',"INTEGER"),('certificate_id',"TEXT")],
 'events':[
   ('payload_hash',"TEXT"),('result_hash',"TEXT"),('prev_hash',"TEXT"),('record_hash',"TEXT")],
}

def _migrate(db):
    for table,columns in _MIGRATIONS.items():
        existing={r[1] for r in db.execute(f'PRAGMA table_info({table})')}
        for name,decl in columns:
            if name not in existing:
                db.execute(f'ALTER TABLE {table} ADD COLUMN {name} {decl}')

def connect(path):
    db=sqlite3.connect(path,isolation_level=None)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA busy_timeout=3000')
    db.executescript(SCHEMA)
    _migrate(db)
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

def canonical(value):
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'))

def sha256_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def _next_seq_hash(db,seq,subsystem,payload_hash,result_hash):
    prev=one(db,'SELECT record_hash FROM events ORDER BY seq DESC LIMIT 1')
    prev_hash=prev['record_hash'] if prev and prev['record_hash'] else 'genesis'
    record_hash=hashlib.sha256(
        '|'.join([str(seq),prev_hash,subsystem,payload_hash or '',result_hash or '']).encode('utf-8')
    ).hexdigest()
    return prev_hash,record_hash

def execute(db,subsystem,payload):
    from . import provenance,channel,admission,retention
    fn={'provenance':provenance.run,'channel':channel.run,'admission':admission.run,'retention':retention.run}[subsystem]
    with tx(db):
        result=fn(db,payload)
        payload_text=json.dumps(payload,sort_keys=True,ensure_ascii=False)
        result_text=json.dumps(result,sort_keys=True,ensure_ascii=False)
        payload_hash=sha256_text(payload_text)
        result_hash=sha256_text(result_text)
        seq=(one(db,'SELECT COALESCE(MAX(seq),0)+1 AS s FROM events') or {'s':1})['s']
        prev_hash,record_hash=_next_seq_hash(db,seq,subsystem,payload_hash,result_hash)
        db.execute(
            'INSERT INTO events(seq,subsystem,payload,result,payload_hash,result_hash,prev_hash,record_hash)'
            ' VALUES(?,?,?,?,?,?,?,?)',
            (seq,subsystem,payload_text,result_text,payload_hash,result_hash,prev_hash,record_hash))
        return result

def _verify_history(source,errors):
    events=rows(source,'SELECT seq,subsystem,payload,payload_hash,result_hash,prev_hash,record_hash FROM events ORDER BY seq')
    history_ok=True
    previous=None
    for e in events:
        expected_prev=(previous or {}).get('record_hash') if previous and previous['record_hash'] else 'genesis'
        if e['record_hash']:
            if (e['prev_hash'] or 'genesis')!=expected_prev:
                errors.append({'step':e['seq'],'reason':'history_chain'});history_ok=False
            expected=hashlib.sha256('|'.join([
                str(e['seq']),e['prev_hash'] or 'genesis',e['subsystem'],
                e['payload_hash'] or '',e['result_hash'] or '']).encode('utf-8')).hexdigest()
            if expected!=e['record_hash']:
                errors.append({'step':e['seq'],'reason':'history_hash'});history_ok=False
        redaction=one(source,'SELECT original_hash FROM event_redactions WHERE seq=?',(e['seq'],))
        if redaction:
            if redaction['original_hash']!=e['payload_hash']:
                errors.append({'step':e['seq'],'reason':'redaction_commitment'});history_ok=False
        elif e['payload_hash']:
            if sha256_text(e['payload'])!=e['payload_hash']:
                errors.append({'step':e['seq'],'reason':'payload_tampered'});history_ok=False
        previous=e
    return history_ok,len(events),len(rows(source,'SELECT seq FROM event_redactions'))

def _table_diff(source,target,table):
    before=[tuple(x) for x in source.execute(f'SELECT * FROM {table} ORDER BY rowid')]
    after=[tuple(x) for x in target.execute(f'SELECT * FROM {table} ORDER BY rowid')]
    if before==after:
        return None
    sample=[]
    for i,(b,a) in enumerate(zip(before,after)):
        if b!=a:
            sample.append({'row':i,'source':repr(b)[:240],'replayed':repr(a)[:240]})
            if len(sample)>=3:
                break
    if len(before)!=len(after):
        sample.append({'row_count_source':len(before),'row_count_replayed':len(after)})
    return sample

def replay(path):
    source=connect(path)
    events=rows(source,'SELECT subsystem,payload,result FROM events ORDER BY seq')
    target=connect(':memory:')
    errors=[]
    for index,item in enumerate(events,1):
        actual=execute(target,item['subsystem'],json.loads(item['payload']))
        if actual!=json.loads(item['result']):
            errors.append({'step':index,'reason':'decision',
                          'expected':json.loads(item['result']),'actual':actual})
    tables=[x[0] for x in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence','events') ORDER BY name")]
    for table in tables:
        diff=_table_diff(source,target,table)
        if diff is not None:
            errors.append({'table':table,'reason':'state','diff':diff})
    history_verified,event_count,redaction_count=_verify_history(source,errors)
    source.close();target.close()
    return {'verified':not errors,'decisions':len(events),'errors':errors,
            'history_verified':history_verified,'events':event_count,'redactions':redaction_count}
