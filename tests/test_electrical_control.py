import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, replay


class ElectricalControlTests(unittest.TestCase):
    def test_permit_ignores_live_backfeed_and_running_workload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'power.sqlite')
            db = connect(path)
            execute(db, 'admission', {'op': 'workload', 'id': 'build-1', 'environment': 'prod',
                'digest': 'sha256:a', 'generation': 1})
            for feed, breaker in [('primary', 'b1'), ('reserve', 'b2')]:
                execute(db, 'electrical', {'op': 'feed', 'rack': 'rack-1', 'feed': feed, 'breaker': breaker})
                execute(db, 'electrical', {'op': 'breaker_ack', 'id': f'cmd-{breaker}',
                    'breaker': breaker, 'action': 'open', 'ack': f'ack-{breaker}'})
            execute(db, 'electrical', {'op': 'workload', 'rack': 'rack-1', 'workload': 'build-1'})
            execute(db, 'meter', {'op': 'sample', 'id': 'sample-1', 'breaker': 'b2',
                'source': 'independent-probe', 'volts': 230, 'at': 41})
            self.assertEqual(execute(db, 'electrical', {'op': 'permit', 'id': 'permit-1',
                'rack': 'rack-1', 'at': 42})['decision'], 'safe')
            self.assertEqual(execute(db, 'meter', {'op': 'inspect', 'breaker': 'b2'}),
                {'decision': 'observed', 'volts': 230, 'source': 'independent-probe'})
            db.close()
            self.assertTrue(replay(path)['verified'])


if __name__ == '__main__':
    unittest.main()
