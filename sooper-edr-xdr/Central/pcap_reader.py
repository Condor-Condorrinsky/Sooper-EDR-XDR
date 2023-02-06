import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
from scapy.all import *

def read_pcap(pcapPath: str, bpf: str = None, count: int = None) -> int:
    content = ''
    file = None
    if bpf is None:
        file = rdpcap(pcapPath)
    else:
        file = sniff(offline=pcapPath, filter=bpf)
    i = 0
    for packet in file:
        packet_content = packet.show(dump=True)
        if packet_content:
            # ''.join([content, packet_content])
            content += packet_content
        if isinstance(count, int) and count > 0 and i >= count :
            break
        i += 1
    return content

def dump_pcap_to_file(string_to_dump: str, filepath: str):
    with open(filepath, "w+") as pcapfile:
        pcapfile.write(string_to_dump)

