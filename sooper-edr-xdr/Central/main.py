import click
import importlib
from agent_client import *
rules = importlib.import_module("detection-rules")
from evtx_reader import *
from logger_client import *
from pcap_reader import *
from txt_reader import *
from utilities import *
from zircolite_handler import *

@click.group()
def cli():
    pass

@click.command(name='sendcommand')
@click.option('-n', '--net-config', is_flag=True,
    help='Get netconfig of Agent\'s machine')
@click.option('-s', '--sniff', nargs=2, type=(str, int),
    help='Sniff using tcpdump on an Agent\'s machine; you need to specify the interface and number of packets to collect')
@click.option('-l', '--list', 'list_', is_flag=True,
    help='List all pcaps collected on Agent\'s machine')
@click.option('-p', '--pcap', type=str,
    help='Download pcap with a specified name from Agent\'s machine')
@click.option('-m', '--many-pcap', multiple=True,
    help='Download multiple pcaps as a zip file; you need to place this flag before every file name you want to download')
@click.option('-e', '--exec', 'exec_', type=str,
    help='Execute given command on Agent\'s machine; the command needs to be encased in single quotes')
def sendcommand(net_config, sniff, list_, pcap, many_pcap, exec_):

    """Perform action on the Remote Agent"""

    if net_config == True:
        data = receive_netconfig()
    elif sniff is not None:
        inter, cnt = sniff
        data = receive_sniff_on_interface(inter, cnt)
    elif list_ == True:
        data = receive_pcaps()
    elif pcap is not None:
        dwnld = receive_pcap_by_path(pcap)
        data = f"New pcap file {dwnld} has been downloaded and placed in \"received\" directory"
    elif many_pcap:
        dwnld = receive_pcap_bulk(many_pcap)
        data = f"New zip file {dwnld} has been downloaded and placed in \"received\" directory"
    elif exec_ is not None:
        execargs = exec_.replace('\'', '').split()
        data = execute(execargs)

    log(data)

@click.command(name='dumpevtx')
@click.option('-p', '--print', 'print_', is_flag=True,
    help='Print contents of evtx to the terminal')
@click.option('-o', '--output', type=str,
    help='Output file for parsed data; should have .xml extension')
@click.argument('evtx')
def dumpevtx(evtx, output, print_):
    
    """Read evtx file as xml and dump result"""

    if output is None and print_ == False:
        data = 'No action specified (\"-p\" or \"-o\"). Quiting!'
        click.echo(data)
        return

    xmlstr = parse_evtx_to_xml(evtx)
    if print_ == True:
        click.echo(xmlstr)
        data = f"Read evtx file {evtx} and dumped contents to terminal"
    elif output is not None:
        dump_xmlstr_to_file(xmlstr, output)
        data = f"Read evtx file {evtx} and dumped contents to file {output}"

    log(data)

@click.command(name='readpcap')
@click.option('-b', '--bpf', type=str,
    help='A BPF compliant filter to pass for parser')
@click.option('-c', '--count', type=int,
    help='Print only first c packets')
@click.option('-o', '--output', type=str,
    help='Path to output file')
@click.argument('pcap')
def readpcap(pcap, bpf, count, output):

    """Read given pcap file and dump its contents"""

    if count is not None and bpf is not None:
        c = int(count)
        data = read_pcap(pcap, bpf, c)
    elif bpf is not None:
        data = read_pcap(pcap, bpf, None)
    elif count is not None:
        c = int(count)
        data = read_pcap(pcap, None, c)
    else:
        data = read_pcap(pcap)

    if output:
        dump_pcap_to_file(data, output)
        message = f"Read pcap file {pcap} and dumped into {output}"
    else:
        message = f"Read pcap file {pcap} and dumped into terminal"
        click.echo(data)

    log(message)

@click.command(name='readtxt')
@click.option('-m', '--mode', is_flag=True,
    help='By default program uses grep to parse plaintext. Use this flag to utilize python \'re\' module')
@click.option('-r', '--regex', type=str,
    help='If using grep - text to grep for, if using re - regex string to search for')
@click.option('-p', '--option', type=str,
    help='A single option in format \'-x\' (encasement in single quotes is mandatory!) to pass to grep; for re this is ignored')
@click.argument('txt')
def readtxt(txt, regex, mode, option):
    
    """Perform grep operation or filter plaintext by a regex"""

    if mode == False:
        data = grep(txt, regex, option)
    elif mode == True:
        data = search(txt, regex)

    log(data)

@click.command(name='sigma')
@click.argument('filepath')
@click.argument('ruleset')
def handlezircolite(filepath, ruleset):

    """Scan evtx file using SIGMA ruleset"""

    data = scan_evtx(filepath, ruleset)
    header = f'Zircolite search results in file {filepath}:\n'
    mess = header + data
    log(mess)

@click.command(name='detectionrules')
@click.argument('rulenr')
@click.argument('filepath')
def detectionrules(rulenr, filepath):

    """Check detection rule on file (rule nr, file path)"""
    
    action = desc = ""

    if rulenr == "1":
        action, desc = rules.rule1_user_enumeration(filepath)
    elif rulenr == "2":
        action, desc = rules.rule2_priviledge_escalation(filepath)
    elif rulenr == "3":
        action, desc = rules.rule3_brute_force(filepath)
    elif rulenr == "4":
        action, desc = rules.rule4_credential_access(filepath)
    elif rulenr == "5":
        action, desc = rules.rule5_event_log_cleared(filepath)
    elif rulenr == "6":
        action, desc = rules.rule6_disable_event_logging(filepath)
    elif rulenr == "7":
        action, desc = rules.rule7_special_member_login(filepath)
    elif rulenr == "8":
        action, desc = rules.rule8_json_account_discovery(filepath)
    
    if action == 'local':
        log(desc)
    elif action == 'remote':
        log(desc)
        send_log(desc)
    	

if __name__ == "__main__":
    cli.add_command(sendcommand)
    cli.add_command(dumpevtx)
    cli.add_command(readpcap)
    cli.add_command(readtxt)
    cli.add_command(handlezircolite)
    cli.add_command(detectionrules)
    cli()
