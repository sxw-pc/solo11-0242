import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, replay


class StructureBaseline(unittest.TestCase):
    def test_shaking_inspection_changes_rack_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'structure.sqlite')
            db = connect(path)
            self.assertEqual(execute(db, 'structure', {'op': 'zone', 'id': 'z',
                                                       'site': 'site-a', 'load_limit': 10,
                                                       'revision': 1})['decision'], 'zone_recorded')
            self.assertEqual(execute(db, 'rack', {'op': 'rack', 'id': 'r1', 'zone': 'z',
                                                  'mass': 5, 'function': 'mirror'})['decision'], 'rack_installed')
            execute(db, 'structure', {'op': 'sample', 'id': 's', 'zone': 'z',
                                      'sensor': 'accel-a', 'at': 2, 'acceleration': 8})
            self.assertEqual(execute(db, 'structure', {'op': 'inspect', 'id': 'i',
                                                       'zone': 'z', 'engineer': 'engineer-a',
                                                       'at': 3, 'threshold': 5})['decision'], 'restricted')
            self.assertEqual(execute(db, 'rack', {'op': 'rack', 'id': 'r2', 'zone': 'z',
                                                  'mass': 2, 'function': 'mirror'})['decision'], 'rack_denied')
            db.close()
            self.assertTrue(replay(path)['verified'])
