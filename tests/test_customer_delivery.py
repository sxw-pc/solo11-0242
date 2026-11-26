import unittest

from imagecourt.store import connect
from imagecourt.edge_transfer import record
from imagecourt.customer_delivery import provisional_bytes


class CustomerDeliveryTest(unittest.TestCase):
    def test_transfer_start_increases_provisional_bytes(self):
        db = connect(":memory:")
        record(db, "e1", "sha256:artifact", "customer-x", 16)
        self.assertEqual(provisional_bytes(db, "sha256:artifact", "customer-x"), 16)
        db.close()


if __name__ == "__main__":
    unittest.main()
