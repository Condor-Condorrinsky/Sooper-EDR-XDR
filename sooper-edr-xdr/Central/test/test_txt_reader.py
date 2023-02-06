import unittest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from txt_reader import *


class TestTxtReader(unittest.TestCase):
    def test_grep(self):
        path = os.getcwd()
        path = os.path.join(path, 'sooper-edr-xdr')
        path = os.path.join(path, 'Central')
        path = os.path.join(path, 'test')
        path = os.path.join(path, 'resources')
        path = os.path.join(path, 'empire_psexec.json')
        regex = 'AUDIT_FAILURE'
        options = r'/i'

        self.assertEqual(True, grep(path, regex, options))
        self.assertEqual(True, search(path, regex))


if __name__ == '__main__':
    unittest.main()
