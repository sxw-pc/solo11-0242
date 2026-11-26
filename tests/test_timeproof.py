import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, replay


class TimeProofBaseline(unittest.TestCase):
    def test_source_stamp_and_certificate_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'clock.sqlite')
            db = connect(path)
            self.assertEqual(execute(db, 'timeproof', {'op': 'source', 'id': 's',
                                                      'operator': 'time-a', 'offset_min': -2,
                                                      'offset_max': 2})['decision'], 'clock_recorded')
            self.assertEqual(execute(db, 'timeproof', {'op': 'stamp', 'id': 't',
                                                      'event_key': 'publish-a', 'source': 's',
                                                      'local_at': 10, 'claimed_utc': 11})['decision'], 'stamp_recorded')
            self.assertEqual(execute(db, 'timeproof', {'op': 'certificate', 'id': 'c',
                                                      'event_key': 'publish-a'})['at'], 11)
            db.close()
            self.assertTrue(replay(path)['verified'])
