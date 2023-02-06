import unittest
import os, os.path, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from zircolite_handler import *

class TestZircoliteHandler(unittest.TestCase):

    def test_scan_evtx(self):
        scan_evtx('resources/test.evtx', '../zircrules/rules_windows_sysmon.json')
