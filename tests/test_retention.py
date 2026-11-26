import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, one, replay


class RetentionBaseline(unittest.TestCase):
    def test_copy_hold_and_erase_request_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'retention.sqlite')
            db = connect(path)
            execute(db, 'provenance', {'op': 'manifest', 'digest': 'sha256:demo',
                                       'tag': 'demo:1', 'batch': 'batch', 'generation': 1})
            self.assertEqual(execute(db, 'retention', {'op': 'copy', 'id': 'copy-a',
                                                      'digest': 'sha256:demo', 'tenant': 'tenant-a',
                                                      'site': 'site-a', 'payload': 'synthetic-client-byte'})['decision'], 'copy_recorded')
            self.assertEqual(execute(db, 'retention', {'op': 'hold', 'id': 'hold-a',
                                                      'tenant': 'tenant-a', 'digest': 'sha256:demo',
                                                      'scope': 'case-a'})['decision'], 'hold_recorded')
            self.assertEqual(execute(db, 'retention', {'op': 'erase', 'id': 'erase-a',
                                                      'tenant': 'tenant-a', 'digest': 'sha256:demo',
                                                      'at': 5})['copies'], 1)
            self.assertEqual(one(db, 'SELECT payload FROM artifact_copies WHERE id=?',
                                 ('copy-a',))['payload'], 'synthetic-client-byte')
            db.close()
            self.assertTrue(replay(path)['verified'])
