# Serwer należy uruchamiać z prawami root'a/administratora

from flask import Flask, request
from agent_ops import *
import os

server = Flask(__name__)

@server.route('/getnetconfig', methods=['GET'])
def GET_netconfig():
    return get_netconfig()

@server.route('/sniffoninterface', methods=['GET'])
def GET_sniffoninterface():
    inter = request.args.get('interface')
    cnt = request.args.get('count')
    return sniff_on_interface(inter, cnt)

@server.route('/pcaps', methods=['GET'])
def GET_pcaps():
    return list_pcaps()

@server.route('/pcaps/<path:path>', methods = ['GET'])
def GET_pcap_by_path(path):
    return send_file(path)

@server.route('/pcapsbulk')
def GET_pcap_bulk():
    files = request.args.get('files').split(' ')
    return send_many_pcaps(files)

@server.route('/exec', methods = ['GET'])
def GET_exec():
    command = request.args.get('command').split(' ')
    return execute_command(command)

if __name__ == '__main__':
    print(os.getcwd())
    server.run(host='localhost', port=5000, debug=False) # debug=True spada z rowerka???
