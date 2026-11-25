import json
from .store import one,rows

def trusted(db,digest,allow_risk=False):
    manifest=one(db,'SELECT * FROM manifests WHERE digest=?',(digest,))
    att=one(db,"SELECT * FROM attestations WHERE digest=? AND status='valid' ORDER BY generation DESC LIMIT 1",(digest,))
    sbom=one(db,"SELECT * FROM sboms WHERE digest=? AND status='complete'",(digest,))
    revoked=one(db,"SELECT id FROM revocations WHERE digest=? AND status='active'",(digest,))
    if not manifest or manifest['status']!='active' or not att or not sbom or revoked:return False
    severe=one(db,"SELECT id FROM risks WHERE digest=? AND severity>=7 AND status='open'",(digest,))
    return allow_risk or not severe

def run(db,x):
    op=x['op']
    if op=='scope':
        db.execute('INSERT OR IGNORE INTO signer_scope VALUES(?,?)',(x['signer'],x['source']))
        return {'decision':'authorized'}
    if op=='manifest':
        if not x['digest'].startswith('sha256:') or x['generation']<1:return {'decision':'invalid_digest'}
        old=one(db,'SELECT * FROM manifests WHERE digest=?',(x['digest'],))
        if old:return {'decision':'reused' if (old['tag'],old['batch'],old['generation'])==(x['tag'],x['batch'],x['generation']) else 'digest_identity_conflict'}
        db.execute('INSERT INTO manifests VALUES(?,?,?,?,?)',(x['digest'],x['tag'],x['batch'],x['generation'],'active'))
        return {'decision':'registered'}
    if op=='attest':
        m=one(db,'SELECT * FROM manifests WHERE digest=?',(x['digest'],))
        if not m or m['batch']!=x['batch']:return {'decision':'unknown_build'}
        if not one(db,'SELECT 1 FROM signer_scope WHERE signer=? AND source=?',(x['signer'],x['source'])):
            return {'decision':'signer_out_of_scope'}
        latest=one(db,'SELECT MAX(generation) AS g FROM attestations WHERE digest=?',(x['digest'],))
        if x['generation']<=(latest['g'] or 0):return {'decision':'stale_attestation'}
        if x['recipe']!=x['expected_recipe']:return {'decision':'recipe_mismatch'}
        db.execute('INSERT INTO attestations VALUES(?,?,?,?,?,?,?)',(x['id'],x['digest'],x['signer'],x['source'],x['recipe'],x['generation'],'valid'))
        return {'decision':'attested'}
    if op=='sbom':
        m=one(db,'SELECT 1 FROM manifests WHERE digest=?',(x['digest'],))
        if not m:return {'decision':'unknown_digest'}
        old=one(db,'SELECT revision FROM sboms WHERE digest=?',(x['digest'],))
        if old and x['revision']<=old['revision']:return {'decision':'stale_sbom'}
        if not x['components'] or len(set(x['components']))!=len(x['components']):return {'decision':'incomplete_sbom'}
        db.execute('INSERT INTO sboms VALUES(?,?,?,?) ON CONFLICT(digest) DO UPDATE SET components=excluded.components,revision=excluded.revision,status=excluded.status',
                   (x['digest'],json.dumps(x['components']),x['revision'],'complete'))
        return {'decision':'complete'}
    if op=='risk':
        old=one(db,'SELECT * FROM risks WHERE id=?',(x['id'],))
        if old and x['revision']<=old['revision']:return {'decision':'stale_risk'}
        if not one(db,'SELECT 1 FROM sboms WHERE digest=?',(x['digest'],)):return {'decision':'missing_sbom'}
        db.execute('INSERT INTO risks VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET severity=excluded.severity,revision=excluded.revision,status=excluded.status',
                   (x['id'],x['digest'],x['severity'],x['revision'],x.get('status','open')))
        return {'decision':'blocked' if x['severity']>=7 and x.get('status','open')=='open' else 'accepted'}
    if op=='revoke':
        m=one(db,'SELECT * FROM manifests WHERE digest=?',(x['digest'],))
        if not m:return {'decision':'unknown_digest'}
        old=one(db,'SELECT * FROM revocations WHERE id=?',(x['id'],))
        if old:return {'decision':'reused' if old['digest']==x['digest'] else 'revocation_conflict'}
        db.execute('INSERT INTO revocations VALUES(?,?,?,?)',(x['id'],x['digest'],x['generation'],'active'))
        db.execute("UPDATE leases SET status='risk' WHERE digest=? AND status='active'",(x['digest'],))
        db.execute("UPDATE channels SET status='risk' WHERE digest=?",(x['digest'],))
        return {'decision':'revoked','affected':len(rows(db,"SELECT id FROM leases WHERE digest=? AND status='risk'",(x['digest'],)))}
    raise ValueError(op)
