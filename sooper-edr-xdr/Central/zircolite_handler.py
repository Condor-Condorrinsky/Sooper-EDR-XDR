import subprocess
import os
from utilities import get_timestamp

def scan_evtx(filepath: str, rulepath: str) -> str:
    outpath = ''.join([os.path.abspath(os.path.dirname(__file__)), '/zircevents/detected_events_', get_timestamp(), '.json'])
    cmd_args = ['--evtx', filepath, '--ruleset', rulepath, '--outfile', outpath]
    output = launch_zircolite(cmd_args)
    return output

def launch_zircolite(args: list) -> str:
    cwd = os.path.abspath(os.path.dirname(__file__))
    zircpath = '/'.join([cwd, 'libs', 'ZircoliteEngine', 'zircolite'])
    args.insert(0, zircpath)
    return subprocess.check_output(args).decode('ASCII')

# if __name__ == '__main__':
#     evtx = os.path.abspath(os.path.dirname(__file__)) + '/test/resources/test.evtx'
#     rule = os.path.abspath(os.path.dirname(__file__)) + '/zircrules/rules_windows_sysmon.json'
#     scan_evtx(evtx, rule)
