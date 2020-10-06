import cs_methods
import csv
import os
import re
import sys
from datetime import datetime, timezone

read_only = ['cat', 'cd', 'clear', 'csrutil', 'env', 'eventlog', 'filehash', 'getsid', 'history', 'ifconfig',
             'ipconfig', 'ls', 'mount', 'netstat', 'ps', 'reg query', 'users']
active_responder = ['cp', 'encrypt', 'get', 'kill', 'map', 'memdump', 'mkdir', 'mv', 'reg set' 'reg delete', 'reg load'
                    'reg unload', 'restart', 'rm', 'runscript', 'shutdown', 'umount', 'unmap', 'xmemdump', 'zip']
rtr_admin = ['put', 'run']


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


def execute_command(full_cmd: str, outfile) -> int:
    reg_pattern = re.compile("reg.+")
    base_cmd = full_cmd.split(' ', 2)
    try:
        if reg_pattern.match(full_cmd):
            base_cmd = str(base_cmd[0]) + ' ' + str(base_cmd[1])
        else:
            base_cmd = base_cmd[0]
        if base_cmd in read_only:
            response = cs_methods.run_batch_cmd(base_cmd, full_cmd)
            print_cmd_response(response['combined']['resources'], outfile)
        elif base_cmd in active_responder:
            response = cs_methods.run_batch_ar_cmd(base_cmd, full_cmd)
            print_cmd_response(response['combined']['resources'], outfile)
        elif base_cmd in rtr_admin:
            response = cs_methods.run_batch_admin_cmd(base_cmd, full_cmd)
            print_cmd_response(response['combined']['resources'], outfile)
        elif base_cmd.lower() == 'bulk':
            path = full_cmd.replace('bulk ', '')
            path = os.path.abspath(path)
            commands = file_to_list(path)
            for command in commands:
                print(command)
                execute_command(command, outfile)
        elif base_cmd.lower() == 'exit':
            return 2
        else:
            print("Error! {} is invalid!".format('"' + str(full_cmd) + '"'))
    except KeyError:
        pass
    return 0


def print_host_info(hosts_info: list, outfile):
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
        if outfile is not None:
            outfile.write(str(host_info['hostname']) + '\t' + str(host_info['device_id']) + '\t' +
                          last_seen_relative + '\t' + str(host_info['os_version']) + '\t' +
                          str(host_info['system_manufacturer']) + '\t' + str(host_info['system_product_name']) + '\t' +
                          str(host_info['agent_version']) + '\n')


def print_rtr_comms_status(rtr_status: dict, outfile):
    rtr_status = list(rtr_status.values())
    if len(rtr_status) > 0:
        print("{:<36} {:<12} {:<18}".format('Host ID', 'Complete', 'Offline Queued'))
    for host in rtr_status:
        print("{:<36} {:<12} {:<18}".format(host['aid'], str(host['complete']), str(host['offline_queued'])))
        if outfile is not None:
            outfile.write(str(host['aid']) + '\t' + str(host['complete']) + '\t' + str(host['offline_queued']) + '\n')


def print_cmd_response(response: dict, outfile):
    # print(response, response.keys())  # debug
    for key, value in response.items():
        print("Host ID : {}".format(value['aid']))
        print("Complete: {}".format(value['complete']))
        print("Queued  : {}".format(value['offline_queued']))
        print("Stdout  : {}".format(value['stdout']))
        print("Stderr  : {}".format(value['stderr']))
        print("Errors  : {}".format(value['errors']))
        print()
        if outfile is not None:
            stdout = str(value['stdout']).replace('\r', ' ').replace('\n', ' ')
            stderr = str(value['stderr']).replace('\r', ' ').replace('\n', ' ')
            errors = str(value['errors']).replace('\r', ' ').replace('\n', ' ')
            outfile.write(str(value['session_id']) + '\t' + str(value['task_id']) + '\t' +
                          str(value['aid']) + '\t' + str(value['base_command']) + '\t' +
                          str(value['complete']) + '\t' + str(value['offline_queued']) + '\t' +
                          str(value['query_time']) + '\t' + stdout + '\t' + stderr + '\t' + errors + '\n')


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
