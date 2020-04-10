import cs_methods
import os
import re
import sys
from datetime import datetime, timezone

read_only = ['cat', 'cd', 'clear', 'env', 'eventlog', 'filehash', 'getsid', 'history', 'ipconfig', 'ls',
             'mount', 'netstat', 'ps', 'reg query']
active_responder = ['cp', 'encrypt', 'get', 'kill', 'map', 'memdump', 'mkdir', 'mv', 'reg set' 'reg delete', 'reg load'
                    'reg unload', 'restart', 'rm', 'runscript', 'shutdown', 'unmap', 'xmemdump', 'zip']
rtr_admin = ['put', 'run']
mac_os = ['cat', 'cd', 'clear', 'cp', 'get', 'help', 'history', 'ipconfig', 'kill', 'ls', 'mkdir', 'mount', 'mv',
          'netstat', 'ps', 'rm', 'zip']


def execute_command(full_cmd: str) -> int:
    reg_pattern = re.compile("reg.+")
    base_cmd = full_cmd.split(' ', 2)
    try:
        if reg_pattern.match(full_cmd):
            base_cmd = str(base_cmd[0]) + ' ' + str(base_cmd[1])
        else:
            base_cmd = base_cmd[0]
        if base_cmd in read_only:
            response = cs_methods.run_batch_cmd(base_cmd, full_cmd)
            print_cmd_response(response['combined']['resources'])
        elif base_cmd in active_responder:
            response = cs_methods.run_batch_ar_cmd(base_cmd, full_cmd)
            print_cmd_response(response['combined']['resources'])
        elif base_cmd in rtr_admin:
            response = cs_methods.run_batch_admin_cmd(base_cmd, full_cmd)
            print_cmd_response(response['combined']['resources'])
        elif base_cmd.lower() == 'bulk':
            path = full_cmd.replace('bulk ', '')
            path = os.path.abspath(path)
            commands = file_to_list(path)
            for command in commands:
                print(command)
                execute_command(command)
        elif base_cmd.lower() == 'exit':
            return 2
        else:
            print("Error! {} is invalid!".format('"' + str(full_cmd) + '"'))
    except KeyError:
        pass
    return 0


def print_cmd_response(response: dict):
    # print(response)  # debug
    for host in response:
        print("Host ID : {}".format(response[host]['aid']))
        print("Complete: {}".format(response[host]['complete']))
        print("Stdout  : {}".format(response[host]['stdout']))
        print("Stderr  : {}".format(response[host]['stderr']))
        print("Errors  : {}".format(response[host]['errors']))
        print()


def to_readable(num, suffix='B'):
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f %s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s%s" % (num, 'Yi', suffix)


def file_to_list(path: str) -> list:
    if os.path.isfile(path):
        with open(path) as infile:
            hosts = infile.readlines()
        hosts = [host.strip() for host in hosts]
    else:
        print("Error! File path does not exist.")
        sys.exit(1)

    return hosts


def print_host_info(hosts_info: list):
    if len(hosts_info) > 0:
        print("{:<20} {:<36} {:<32} {:<16} {:<16} {:<24} {:<24}".format('Hostname', 'Host ID', 'Last Seen',
                                                                        'OS Version', 'Manufacturer', 'Product',
                                                                        'Agent Version'))
    for host_info in hosts_info:
        # convert last_seen to relative time
        last_seen = datetime.strptime(host_info['last_seen'], '%Y-%m-%dT%H:%M:%SZ')
        last_seen = last_seen.replace(tzinfo=timezone.utc).astimezone(tz=None)
        delta = datetime.now().replace(tzinfo=None).astimezone(tz=None) - last_seen
        last_seen_relative = str(delta.days) + " days, " + str(delta.seconds // 3600) + " hrs, " + \
                             str((delta.seconds // 60) % 60) + " mins ago"

        # print host info
        print("{:<20} {:<36} {:<32} {:<16} {:<16} {:<24} {:<24}".format(host_info['hostname'], host_info['device_id'],
                                                                        last_seen_relative, host_info['os_version'],
                                                                        host_info['system_manufacturer'],
                                                                        host_info['system_product_name'],
                                                                        host_info['agent_version']))


def is_expiring(life_time: int, req_time: datetime) -> bool:
    passed_mins = ((datetime.now() - req_time).total_seconds()) / 60
    if passed_mins >= life_time:  # token expired
        return True
    else:
        return False


def pretty_print_post(req):
    print('{}\n{}\r\n{}\r\n\r\n{}'.format(
        '-----------START-----------',
        req.method + ' ' + req.url,
        '\r\n'.join('{}: {}'.format(k, v) for k, v in req.headers.items()),
        req.body,
    ))
