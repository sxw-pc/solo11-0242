import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, replay


class EnergyBaseline(unittest.TestCase):
    def test_build_reading_and_draft_claim_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'energy.sqlite')
            db = connect(path)
            execute(db, 'provenance', {'op': 'manifest', 'digest': 'sha256:demo',
                                       'tag': 'demo:1', 'batch': 'batch-a', 'generation': 1})
            self.assertEqual(execute(db, 'energy', {'op': 'meter', 'id': 'm', 'site': 'site-a',
                                                   'period': '2026-11', 'kwh': 100,
                                                   'source': 'grid', 'revision': 1})['decision'], 'meter_recorded')
            self.assertEqual(execute(db, 'energy', {'op': 'build', 'id': 'b', 'batch': 'batch-a',
                                                   'digest': 'sha256:demo', 'site': 'site-a',
                                                   'starts': 1, 'ends': 5})['decision'], 'build_recorded')
            self.assertEqual(execute(db, 'energy', {'op': 'claim', 'id': 'c', 'run': 'b',
                                                   'reading': 'm', 'kwh': 10})['decision'], 'draft_claim')
            db.close()
            self.assertTrue(replay(path)['verified'])
