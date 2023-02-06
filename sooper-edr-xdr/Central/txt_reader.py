import re
import os
import subprocess

def grep(file_path, regex, option):
    cmd = []
    if os.name == 'nt':
        cmd.append("findstr")
    elif os.name == 'posix':
        cmd.append("grep")
    else:
        return
    if option is None:
        cmd.append(regex)
        cmd.append(file_path)
    else:
        cmd.append(option)
        cmd.append(regex)
        cmd.append(file_path)
    return subprocess.check_output(cmd).decode('ASCII')

def search(file_path, regex):
    content = ''
    with open(file_path) as file:
        for line in file:
            res = re.search(regex, line)
            if res:
                content += line
    return content
