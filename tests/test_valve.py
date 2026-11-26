import tempfile
import unittest
from pathlib import Path

from imagecourt.store import connect, execute, one, replay


class ValveBaseline(unittest.TestCase):
    def test_command_is_only_an_intent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / 'valve.sqlite')
            db = connect(path)
            execute(db, 'cooling', {'op': 'loop', 'id': 'l', 'site': 'site-a',
                                    'flow_limit': 100, 'temp_limit': 30})
            self.assertEqual(execute(db, 'cooling', {'op': 'valve', 'id': 'v', 'loop': 'l',
                                                     'position': 'recirculate', 'at': 5})['decision'], 'valve_command_sent')
            self.assertEqual(one(db, 'SELECT status FROM valve_intents WHERE id=?', ('v',))['status'], 'sent')
            db.close()
            self.assertTrue(replay(path)['verified'])
