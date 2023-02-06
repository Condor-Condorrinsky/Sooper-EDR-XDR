import unittest
import os, os.path, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pcap_reader import *

class TestPcapReader(unittest.TestCase):

    def test_readPcap(self):
        path = os.getcwd()
        path = os.path.join(path, 'sooper-edr-xdr')
        path = os.path.join(path, 'Central')
        path = os.path.join(path, 'test')
        path = os.path.join(path, 'resources')
        path = os.path.join(path, '6_3_R3.pcap')

        count = read_pcap(path)
        assert count == 6

        count = read_pcap(path, 'arp', None)
        assert count == 4

        count = read_pcap(path, None, 5)
        assert count == 5

        count = read_pcap(path, 'arp', 3)
        assert count == 3

