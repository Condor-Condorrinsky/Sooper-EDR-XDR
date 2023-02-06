import click
from datetime import datetime, date

def get_timestamp() -> str:
    return datetime.now().strftime("%d-%m-%Y_%H:%M:%S")

def get_datestamp() -> str:
    return date.today().strftime("%d-%m-%Y")

def create_log_filename() -> str:
    return ''.join(['sooper-edr-xdr_', get_datestamp(), '.log'])

def write_to_logfile(logfile: str, message: str):
    with open(logfile, "a") as logf:
        logf.write('\n')
        logf.write(message)
        logf.write('\n')

def log(data: str):
    click.echo(data)
    write_to_logfile(create_log_filename(), get_timestamp())
    write_to_logfile(create_log_filename(), data)
