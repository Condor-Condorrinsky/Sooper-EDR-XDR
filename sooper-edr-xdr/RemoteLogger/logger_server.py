from flask import Flask, request, jsonify
import json

server = Flask(__name__)

@server.route('/postlog', methods=['POST'])
def receive_log():
    received = json.dumps(request.get_json(force=True))
    print('Received new log!\n')
    log = json.loads(received)["logdata"]
    print(log)
    ret = {'Status':'Log received'}
    return jsonify(ret)

if __name__ == '__main__':
    server.run(host='localhost', port=6000, debug=False)
