import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, replay


class CoolingBaseline(unittest.TestCase):
    def test_loop_sample_build_and_report_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'cooling.sqlite')
            db = connect(path)
            execute(db, 'provenance', {'op': 'manifest', 'digest': 'sha256:demo',
                                       'tag': 'demo:1', 'batch': 'batch-a', 'generation': 1})
            self.assertEqual(execute(db, 'cooling', {'op': 'loop', 'id': 'l', 'site': 'site-a',
                                                    'flow_limit': 100, 'temp_limit': 30})['decision'], 'loop_recorded')
            self.assertEqual(execute(db, 'cooling', {'op': 'sample', 'id': 's', 'loop': 'l',
                                                    'point': 'outfall', 'at': 5,
                                                    'flow': 10, 'temperature': 25})['decision'], 'water_sampled')
            self.assertEqual(execute(db, 'cooling', {'op': 'build', 'id': 'b', 'batch': 'batch-a',
                                                    'digest': 'sha256:demo', 'loop': 'l',
                                                    'starts': 1, 'ends': 10})['decision'], 'build_linked')
            self.assertEqual(execute(db, 'cooling', {'op': 'report', 'id': 'r', 'loop': 'l',
                                                    'period': '2026-11'})['volume'], 10)
            db.close()
            self.assertTrue(replay(path)['verified'])
