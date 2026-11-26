import argparse,json
from pathlib import Path
from .store import connect,execute,replay

def main():
    p=argparse.ArgumentParser()
    p.add_argument('command',choices=['provenance','channel','admission','settlement','demo','replay'])
    p.add_argument('--db',default='demo.sqlite')
    p.add_argument('--fixture')
    a=p.parse_args()
    if a.command=='replay':
        result=replay(a.db)
        print(json.dumps(result,ensure_ascii=False))
        if not result['verified']:raise SystemExit(2)
        return
    db=connect(a.db)
    tasks=[(a.command,a.fixture)] if a.command!='demo' else [
        ('provenance','fixtures/provenance_normal.json'),('channel','fixtures/channel_normal.json'),
        ('admission','fixtures/admission_normal.json'),('provenance','fixtures/provenance_failure.json'),
        ('channel','fixtures/channel_failure.json'),('admission','fixtures/admission_failure.json')]
    results=[]
    for subsystem,file in tasks:
        if not file:p.error('--fixture required')
        data=json.loads(Path(file).read_text(encoding='utf-8'))
        results.append({'fixture':file,'results':[execute(db,subsystem,x) for x in (data if isinstance(data,list) else [data])]})
    print(json.dumps(results,ensure_ascii=False,indent=2))
    db.close()

if __name__=='__main__':main()
