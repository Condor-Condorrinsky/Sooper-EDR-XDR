import unittest
import os, os.path, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from evtx_reader import *

class TestEvtxReader(unittest.TestCase):

    def setUp(self) -> None:
        path = os.getcwd()
        path = os.path.join(path, 'sooper-edr-xdr')
        path = os.path.join(path, 'Central')
        path = os.path.join(path, 'test')
        path = os.path.join(path, 'resources')

        test_file_path = os.path.join(path, 'test.evtx')
        dump_file_path = os.path.join(path, 'output.xml')

        self.testFilePath = test_file_path
        self.dumpFilePath = dump_file_path

    def test_parse_evtx_to_xml(self):
        test = parse_evtx_to_xml(self.testFilePath)
        assert test

    def test_dump_xmlstr_to_file(self):
        data = parse_evtx_to_xml(self.testFilePath)
        assert data
        dump_xmlstr_to_file(data, self.dumpFilePath)
