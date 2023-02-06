import requests

LOGGER_URL = 'http://localhost:6000/'

def send_log(log: str) -> str:
    result = requests.post(''.join([LOGGER_URL, 'postlog']), json={"logdata":log})
    return result.text

# if __name__ == '__main__':
#     message = 'trolololo123'
#     rec = send_log(message)
#     print(rec)
