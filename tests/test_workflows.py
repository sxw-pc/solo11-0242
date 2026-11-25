import json,tempfile,unittest
from pathlib import Path
import imagecourt
from imagecourt.store import connect,execute,replay

ROOT=Path(__file__).resolve().parents[1]
assert Path(imagecourt.__file__).resolve().is_relative_to(ROOT)
print('MODULE_PATH',imagecourt.__file__)

class ImageCourtTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'state.sqlite'
        self.db=connect(str(self.path))
    def tearDown(self):self.db.close();self.tmp.cleanup()
    def step(self,sub,**x):return execute(self.db,sub,x)
    def fixture(self,sub,name):
        data=json.loads((ROOT/'fixtures'/name).read_text(encoding='utf-8'))
        return [execute(self.db,sub,x) for x in data]
    def ready(self):
        self.fixture('provenance','provenance_normal.json')
        self.fixture('channel','channel_normal.json')

    def test_source_identity_and_attestation(self):
        r=self.fixture('provenance','provenance_normal.json')
        self.assertEqual(r[-1]['decision'],'accepted')
        self.assertEqual(self.step('provenance',op='manifest',digest='sha256:aaa',tag='different',batch='b1',generation=1)['decision'],'digest_identity_conflict')
        self.assertEqual(self.step('provenance',op='attest',id='late',digest='sha256:aaa',batch='b1',signer='builder-a',source='repo-a',recipe='r1',expected_recipe='r1',generation=1)['decision'],'stale_attestation')
    def test_missing_source_and_sbom(self):
        r=self.fixture('provenance','provenance_failure.json')
        self.assertEqual([x['decision'] for x in r],['registered','signer_out_of_scope','incomplete_sbom'])
    def test_risk_exception_scope_and_expiry(self):
        self.ready()
        self.step('provenance',op='risk',id='severe',digest='sha256:aaa',severity=9,revision=1)
        self.assertEqual(self.step('channel',op='propose',id='p-prod',digest='sha256:aaa',environment='prod',at=15)['decision'],'untrusted_candidate')
        self.assertEqual(self.step('channel',op='exception',id='e',digest='sha256:aaa',environment='prod',role1='security',role2='owner',expires=20,at=15)['decision'],'approved')
        self.assertEqual(self.step('channel',op='propose',id='p-prod',digest='sha256:aaa',environment='prod',at=16)['decision'],'pending')
        self.assertEqual(self.step('channel',op='publish',id='p-prod',at=21)['decision'],'candidate_invalidated')
    def test_competing_promotion_and_upstream(self):
        self.fixture('provenance','provenance_normal.json')
        self.assertEqual(self.step('channel',op='propose',id='p1',digest='sha256:aaa',environment='stage',parent_environment='dev',at=10)['decision'],'upstream_not_promoted')
        self.step('channel',op='propose',id='p1',digest='sha256:aaa',environment='dev',at=10)
        self.assertEqual(self.step('channel',op='propose',id='p2',digest='sha256:aaa',environment='dev',at=10)['decision'],'promotion_competition')
    def test_admission_binds_channel_and_workload_generation(self):
        self.ready();self.fixture('admission','admission_normal.json')
        self.assertEqual(self.step('admission',op='admit',id='x',workload='web-1',generation=0,channel_generation=1,at=15,expires=30)['decision'],'identity_or_channel_mismatch')
        self.assertEqual(self.step('admission',op='renew',id='lease-1',at=20,expires=60)['decision'],'renewed')
    def test_revocation_crosses_all_three_subsystems(self):
        self.ready();self.fixture('admission','admission_normal.json')
        r=self.step('provenance',op='revoke',id='revoke-1',digest='sha256:aaa',generation=2)
        self.assertEqual(r['decision'],'revoked')
        self.assertEqual(self.step('admission',op='renew',id='lease-1',at=20,expires=70)['decision'],'lease_unavailable')
        self.assertEqual(self.step('channel',op='propose',id='new',digest='sha256:aaa',environment='prod',at=20)['decision'],'untrusted_candidate')
        self.assertEqual(replay(str(self.path))['verified'],True)
    def test_orphan_blocks_withdrawal(self):
        self.ready();self.fixture('admission','admission_normal.json')
        self.step('admission',op='isolate',id='lease-1')
        self.step('admission',op='orphan',id='o',environment='stage',digest='sha256:aaa')
        self.assertEqual(self.step('channel',op='withdraw',environment='stage',at=30)['decision'],'dependent_runtime')
        self.step('admission',op='clear_orphan',id='o',proof_digest='sha256:aaa')
        self.assertEqual(self.step('admission',op='review',environment='stage')['decision'],'clear')
    def test_pending_promotion_rechecks_upstream_after_revoke(self):
        self.ready()
        self.assertEqual(self.step('channel',op='propose',id='p-prod',digest='sha256:aaa',environment='prod',parent_environment='stage',at=20)['decision'],'pending')
        self.step('provenance',op='revoke',id='rev',digest='sha256:aaa',generation=2)
        self.assertEqual(self.step('channel',op='publish',id='p-prod',at=21)['decision'],'candidate_invalidated')
    def test_fixture_replay_and_rows(self):
        for sub,name in [('provenance','provenance_normal.json'),('channel','channel_normal.json'),('admission','admission_normal.json'),('provenance','provenance_failure.json'),('channel','channel_failure.json'),('admission','admission_failure.json')]:self.fixture(sub,name)
        self.assertEqual(self.step('admission',op='review',environment='stage')['decision'],'blocked')
        result=replay(str(self.path));self.assertTrue(result['verified'],result)

if __name__=='__main__':unittest.main()
