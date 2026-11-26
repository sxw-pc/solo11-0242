import unittest

from imagecourt.store import connect
from imagecourt.tenant_config import record, export
from imagecourt.foreign_runtime import import_bundle, permits_egress


class PortSeedTest(unittest.TestCase):
    def test_target_import_ignores_customer_egress_boundary(self):
        db = connect(':memory:')
        record(db, 'C1', 'tenant-A', 'digest-1', 2048, 2, 'approved', 2, 'secret-A')
        export(db, 'B1', 'C1')
        self.assertEqual('imported', import_bundle(db, 'I1', 'B1', 'target-X'))
        self.assertTrue(permits_egress(db, 'I1', 'unapproved'))
        db.close()


if __name__ == '__main__':
    unittest.main()
