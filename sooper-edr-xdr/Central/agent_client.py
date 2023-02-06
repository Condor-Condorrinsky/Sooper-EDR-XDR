import requests
import os
from utilities import get_timestamp

AGENT_URL = 'http://localhost:5000/'

def receive_netconfig() -> str:
    final_url = ''.join([AGENT_URL, 'getnetconfig'])
    return requests.get(final_url).text

def receive_sniff_on_interface(interface: str, count: int) -> str:
    final_url = ''.join([AGENT_URL, 'sniffoninterface?interface=', interface, '&count=', str(count)])
    return requests.get(final_url).text

def receive_pcaps() -> str:
    final_url = ''.join([AGENT_URL, 'pcaps'])
    return requests.get(final_url).text

def receive_pcap_by_path(filename: str) -> str:
    final_url = ''.join([AGENT_URL, 'pcaps/', filename])
    data = requests.get(final_url).content
    cwd = os.path.abspath(os.path.dirname(__file__))
    with open(''.join([cwd, '/received/' + filename]), 'wb') as f:
        f.write(data)
    return filename

def receive_pcap_bulk(filenames: list) -> str:
    final_url = ''.join([AGENT_URL, 'pcapsbulk?files=', '+'.join(filenames)])
    data = requests.get(final_url).content
    cwd = os.path.abspath(os.path.dirname(__file__))
    filename = get_timestamp() + '.zip'
    with open(''.join([cwd, '/received/' + filename]), 'wb') as f:
        f.write(data)
    return filename

def execute(command: list) -> str:
    strcmd = '+'.join(command)
    final_url = ''.join([AGENT_URL, 'exec?command=', strcmd])
    return requests.get(final_url).text


# if __name__ == '__main__':
#     print(receive_netconfig())
#     print(receive_sniff_on_interface('wlp0s20f3', 3))
#     print(receive_pcaps())
#     receive_pcap_by_path('wlp0s20f3_05-01-2023_15:33:03.pcap')
#     receive_pcap_bulk(['wlp0s20f3_05-01-2023_15:33:03.pcap', 'wlp0s20f3_05-01-2023_15:32:25.pcap'])
#     print(execute(['uname', '-r']))
