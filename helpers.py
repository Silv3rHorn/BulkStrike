import cs_methods
import os
import re
from datetime import datetime, timezone
from tabulate import tabulate

read_only = ['cat', 'cd', 'clear', 'csrutil', 'env', 'eventlog', 'filehash', 'getsid', 'history', 'ifconfig',
             'ipconfig', 'ls', 'mount', 'netstat', 'ps', 'reg query', 'users']
active_responder = ['cp', 'encrypt', 'get', 'kill', 'map', 'memdump', 'mkdir', 'mv', 'reg set' 'reg delete', 'reg load'
                    'reg unload', 'restart', 'rm', 'shutdown', 'tar', 'umount', 'unmap', 'update',
                    'xmemdump', 'zip']
rtr_admin = ['put', 'run', 'runscript', 'put-and-run']


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
        return []

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
            print_cmd_response(response['combined']['resources'])
            if outfile is not None:
                log_cmd_response(response['combined']['resources'], outfile)
        elif base_cmd in active_responder:
            response = cs_methods.run_batch_ar_cmd(base_cmd, full_cmd)
            print_cmd_response(response['combined']['resources'])
            if outfile is not None:
                log_cmd_response(response['combined']['resources'], outfile)
        elif base_cmd in rtr_admin:
            response = cs_methods.run_batch_admin_cmd(base_cmd, full_cmd)
            print_cmd_response(response['combined']['resources'])
            if outfile is not None:
                log_cmd_response(response['combined']['resources'], outfile)
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


def print_host_info(hosts_info: list):
    headers = ['Hostname', 'Host ID', 'Last Seen', 'OS Version', 'Manufacturer', 'Product', 'Agent Version']
    data = list()

    for host_info in hosts_info:
        # convert last_seen to relative time
        last_seen = datetime.strptime(host_info['last_seen'], '%Y-%m-%dT%H:%M:%SZ')
        last_seen = last_seen.replace(tzinfo=timezone.utc).astimezone(tz=None)
        delta = datetime.now().replace(tzinfo=None).astimezone(tz=None) - last_seen
        last_seen_relative = str(delta.days) + " days, " + str(delta.seconds // 3600) + " hrs, " + \
                             str((delta.seconds // 60) % 60) + " mins ago"
        data.append([host_info['hostname'], host_info['device_id'], last_seen_relative, host_info['os_version'],
                     host_info['system_manufacturer'], host_info['system_product_name'], host_info['agent_version']])

    print(tabulate(data, headers, tablefmt='pretty'))


def print_host_logins(host_logins: list):
    headers = ['Host ID', 'Hostname', 'Username', 'Last Seen', 'First Seen']
    data = list()

    for host_login in host_logins:
        for key, value in host_login['logins'].items():
            data.append([host_login['host_id'], host_login['hostname'], key, value['last_seen'], value['first_seen']])

    print(tabulate(data, headers, tablefmt='pretty'))


def print_rtr_comms_status(rtr_status: dict):
    headers = ['Host ID', 'Session ID', 'Connected', 'Offline Queued']
    data = list()

    rtr_status = list(rtr_status.values())
    for host in rtr_status:
        data.append([host['aid'], host['session_id'], str(host['complete']), str(host['offline_queued'])])

    print(tabulate(data, headers, tablefmt='pretty'))


def print_cmd_response(response: dict):
    # print(response, response.keys())  # debug
    for key, value in response.items():
        print("Host ID : {}".format(value['aid']))
        print("Complete: {}".format(value['complete']))
        print("Queued  : {}".format(value['offline_queued']))
        print("Stdout  : {}".format(value['stdout']))
        print("Stderr  : {}".format(value['stderr']))
        print("Errors  : {}".format(value['errors']))
        print()


def print_qsessions_metadata(sessions: list):
    headers = ['Session ID', 'Created At', 'Updated At', 'Deleted At', 'Host ID', 'Status', 'Cmd String', 'Cmd Status']
    data = list()

    for session in sessions:
        session_id = session['id']
        created_at = session['created_at']
        updated_at = session['updated_at']
        deleted_at = session['deleted_at']
        aid = session['aid']
        status = session['status']
        commands = session['Commands']
        for command in commands:
            data.append([session_id, created_at, updated_at, deleted_at, aid, status, command['command_string'],
                         command['status']])

    print(tabulate(data, headers, tablefmt='pretty'))


def log_host_info(hosts_info: list, outfile):
    for host_info in hosts_info:
        # convert last_seen to relative time
        last_seen = datetime.strptime(host_info['last_seen'], '%Y-%m-%dT%H:%M:%SZ')
        last_seen = last_seen.replace(tzinfo=timezone.utc).astimezone(tz=None)
        delta = datetime.now().replace(tzinfo=None).astimezone(tz=None) - last_seen
        last_seen_relative = str(delta.days) + " days, " + str(delta.seconds // 3600) + " hrs, " + \
                             str((delta.seconds // 60) % 60) + " mins ago"

        outfile.write(str(host_info['hostname']) + '\t' + str(host_info['device_id']) + '\t' +
                      last_seen_relative + '\t' + str(host_info['os_version']) + '\t' +
                      str(host_info['system_manufacturer']) + '\t' + str(host_info['system_product_name']) + '\t' +
                      str(host_info['agent_version']) + '\n')


def log_rtr_comms_status(rtr_status: dict, outfile):
    rtr_status = list(rtr_status.values())
    for host in rtr_status:
        outfile.write(str(host['aid']) + '\t' + str(host['session_id']) + '\t' + str(host['complete']) + '\t' +
                      str(host['offline_queued']) + '\n')


def log_cmd_response(response: dict, outfile):
    # print(response, response.keys())  # debug
    for key, value in response.items():
        stdout = str(value['stdout']).replace('\r', ' ').replace('\n', ' ')
        stderr = str(value['stderr']).replace('\r', ' ').replace('\n', ' ')
        errors = str(value['errors']).replace('\r', ' ').replace('\n', ' ')
        outfile.write(str(value['aid']) + '\t' + str(value['session_id']) + '\t' +
                      str(value['complete']) + '\t' + str(value['offline_queued']) + '\t' +
                      str(value['query_time']) + '\t' + stdout + '\t' + stderr + '\t' + errors + '\n')


def log_qsessions_metadata(sessions: list, outfile):
    for session in sessions:
        session_id = str(session['id'])
        created_at = str(session['created_at'])
        updated_at = str(session['updated_at'])
        deleted_at = str(session['deleted_at'])
        aid = str(session['aid'])
        status = str(session['status'])
        commands = session['Commands']
        for command in commands:
            outfile.write(session_id + '\t' + created_at + '\t' + updated_at + '\t' + deleted_at + '\t' + aid + '\t' +
                          status + '\t' + str(command['cloud_request_id']) + '\t' + str(command['command_string']) +
                          '\t' + str(command['created_at']) + '\t' + str(command['updated_at']) + '\t' +
                          str(command['deleted_at']) + '\t' + str(command['status']) + '\n')


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
