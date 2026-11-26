import unittest

from imagecourt import store
from imagecourt.royalty_capture import provisional_dues


class RoyaltyCaptureTest(unittest.TestCase):
    def test_provisional_dues_count_listed_components_and_leases(self):
        db = store.connect(":memory:")
        db.execute("INSERT INTO sboms VALUES(?,?,?,?)", ("sha256:one", '["library-a"]', 1, "complete"))
        db.execute("INSERT INTO leases VALUES(?,?,?,?,?,?)", ("l1", "w1", "sha256:one", 1, 10, "active"))
        self.assertEqual(provisional_dues(db, "sha256:one", 7), 7)
        db.close()


if __name__ == "__main__":
    unittest.main()
