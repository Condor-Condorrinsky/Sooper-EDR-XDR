import subprocess
import os, os.path
from datetime import datetime
from flask import send_from_directory
from zipfile import ZipFile

# /getnetconfig
def get_netconfig() -> str:
    # Unix
    if os.name == 'posix':
        return subprocess.check_output(["ip", "a"])
    # Windows
    elif os.name == 'nt':
        return subprocess.check_output(["ipconfig"])

# Pomocnicza
def get_timestamp() -> str:
    return datetime.now().strftime("%d-%m-%Y_%H:%M:%S")

# Pomocnicza
def create_pcap_name(interface: str) -> str:
    raw_name_list = [interface, get_timestamp()]
    raw_name = '_'.join(raw_name_list)
    full_name_list = [raw_name, '.pcap']
    return ''.join(full_name_list)

# /sniffoninterface?interface=xxx&count=yyy
def sniff_on_interface(interface: str, count: int):
    if int(count) < 1:
        raise ValueError('Count must be positive')
    filename = os.path.join("pcaps", create_pcap_name(interface))
    if os.name == 'posix':
        subprocess.run(["tcpdump", "-i", interface, "-c", count, "-w", filename])
        return "Created a new pcap file on server with name: {fname}".format(fname = filename)
    else:
        return

# /pcaps
def list_pcaps() -> str:
    return subprocess.check_output(["ls", "pcaps"])

# /pcaps/<path:path>
def send_file(filename: str):
    return send_from_directory('pcaps', filename, as_attachment = True)

# NIE DZIALA BO SCIAGA TO JAKO PLIK PLAINTEXT A NIE BINARY
# /pcaps/(argumenty po plusie)
def send_many_pcaps(files: list):
    zipname = ''.join([get_timestamp(), ".zip"])
    full_zipname = ''.join(["pcaps/", get_timestamp(), ".zip"])
    with ZipFile(full_zipname, "w") as zipped:
        for file in files:
            zipped.write(''.join(["pcaps/", file]))
    return send_from_directory('pcaps', zipname, as_attachment = True)

# /exec
def execute_command(command: list) -> str:
    return subprocess.check_output(command)
