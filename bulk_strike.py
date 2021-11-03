#!/usr/bin/python
# -*- coding: utf-8 -*-

import argparse
import base64
import os
import sys
import cs_methods
import helpers
from datetime import datetime

# GLOBALS/PARAMS
HOME_DIR = os.path.expanduser('~')
DIR_PATH = os.path.join(HOME_DIR, '.bulkstrike')
CRED_PATH = os.path.join(DIR_PATH, "credentials")
TOKEN_PATH = os.path.join(DIR_PATH, "token")


def init(read_creds: bool = True, read_token: bool = True):
    if read_creds:
        if os.path.isfile(CRED_PATH):  # previously saved credentials exist
            with open(CRED_PATH) as infile:
                lines = infile.readlines()
                try:
                    cs_methods.CLIENT_ID = lines[0].split(":")[1].strip()
                    cs_methods.SECRET = lines[1].split(":")[1].strip()
                    if len(lines) > 2:
                        cs_methods.SERVER = lines[2].split(": ")[1].strip()
                except IndexError:
                    print("Error! Credential file format is invalid. Please run bulkstrike configure again.")
                    os.remove(CRED_PATH)
                    sys.exit(1)
        else:
            print("Error! No CrowdStrike ID or Secret available.")
            sys.exit(1)

    if read_token:
        if os.path.isfile(TOKEN_PATH):
            with open(TOKEN_PATH) as infile:
                auth_token = infile.readline()
            cs_methods.TOKEN = auth_token
            cs_methods.HEADERS['Authorization'] = 'Bearer {}'.format(cs_methods.TOKEN)
        else:
            print("Error! No CrowdStrike authentication token available.")
            sys.exit(1)
    else:
        cs_methods.BYTE_CREDS = '{name}:{password}'.format(name=cs_methods.CLIENT_ID,
                                                           password=cs_methods.SECRET).encode('utf-8')
        cs_methods.HEADERS['Authorization'] = 'Bearer {}'.format(base64.b64encode(cs_methods.BYTE_CREDS).decode())


def configure():
    if not os.path.isdir(DIR_PATH):
        os.mkdir(DIR_PATH)
    elif os.path.isfile(CRED_PATH):  # previously saved credentials exist
        init(read_creds=True, read_token=False)

    masked_client_id = cs_methods.CLIENT_ID[-4:].rjust(len(cs_methods.CLIENT_ID), "*")
    masked_secret = cs_methods.SECRET[-4:].rjust(len(cs_methods.SECRET), "*")

    temp_client_id = input("CrowdStrike Client ID [{}]: ".format(masked_client_id))
    temp_secret = input("CrowdStrike Secret [{}]: ".format(masked_secret))
    temp_server = input("CrowdStrike API Server [{}]: ".format(cs_methods.SERVER)).rstrip('/')
    if temp_client_id != '':
        cs_methods.CLIENT_ID = temp_client_id
    if temp_secret != '':
        cs_methods.SECRET = temp_secret
    if temp_server != '':
        cs_methods.SERVER = temp_server
    with open(CRED_PATH, 'w') as outfile:
        outfile.writelines(["Client ID: {}".format(cs_methods.CLIENT_ID), "\nSecret: {}".format(cs_methods.SECRET),
                            "\nAPI Server: {}".format(cs_methods.SERVER)])
    init(read_creds=False, read_token=False)


def req_token():
    init(read_creds=True, read_token=False)
    access_token = cs_methods.get_token(new_token=True)
    if access_token is not None:
        print("Authentication token successfully requested: {}".format(access_token))


def get_info(host: str, file: str, log: bool):
    if host is not None:
        req_hosts = host.split(',')
        response = cs_methods.get_host_info(req_hosts)
    elif file is not None:
        req_hosts = helpers.file_to_list(file)
        response = cs_methods.get_host_info(req_hosts)
    else:
        print("Error! No host id or hostname provided.")
        sys.exit(1)
    hosts_info = response.get('resources', {})

    search_str = "',hostname:'".join(req_hosts)
    response = cs_methods.find_hosts("hostname:'" + search_str + "'")
    if len(response) > 0:
        new_host_ids = list(set(response) - set(req_hosts))
        response = cs_methods.get_host_info(new_host_ids)
        for host_info in response.get('resources', {}):
            hosts_info.append(host_info)

    helpers.print_host_info(hosts_info)
    if log:
        timestamp = datetime.now().strftime("%Y-%m-%d@%H%M%S")
        filename = "hosts_info_" + timestamp + ".tsv"
        with open(filename, 'w') as outfile:
            outfile.write("Hostname\tHost ID\tLast Seen\tOS Version\tManufacturer\tProduct\tAgent Version\n")
            helpers.log_host_info(hosts_info, outfile)


def get_logins(host: str, file: str, log: bool, clean: bool):
    if host is not None:
        req_hosts = host.split(',')
    elif file is not None:
        req_hosts = helpers.file_to_list(file)
    else:
        print("Error! No host id or hostname provided.")
        sys.exit(1)

    # get hostnames
    hosts_info = dict()
    resources = cs_methods.get_host_info(req_hosts).get('resources', {})
    for resource in resources:
        hosts_info[resource['device_id']] = resource['hostname']

    hosts_logins = list()
    if len(hosts_info) > 0:
        req_hosts = list(hosts_info.keys())
        resources = cs_methods.get_host_logins(req_hosts)

        for resource in resources:
            recent_logins = resource['recent_logins']
            agg_logins = dict()
            for recent_login in recent_logins:
                username = recent_login['user_name']
                if clean and (username.startswith('root@') or username.startswith('_') or username.startswith('daemon')
                              or username.startswith('postgres') or username.startswith('nobody') or 'DWM-' in username
                              or 'UMFD-' in username or username.endswith('$') or 'LOCAL SERVICE' in username
                              or 'NETWORK SERVICE' in username):
                    continue
                if username in agg_logins:
                    agg_logins[username]['count'] += 1
                    if recent_login['login_time'] > agg_logins[username]['last_seen']:
                        agg_logins[username]['last_seen'] = recent_login['login_time']
                    elif recent_login['login_time'] < agg_logins[username]['last_seen']:
                        agg_logins[username]['first_seen'] = recent_login['login_time']
                else:
                    agg_logins[username] = dict()
                    agg_logins[username]['first_seen'] = recent_login['login_time']
                    agg_logins[username]['last_seen'] = recent_login['login_time']
                    agg_logins[username]['count'] = 1
            hosts_logins.append({"host_id": resource['device_id'], "hostname": hosts_info[resource['device_id']],
                                 "logins": agg_logins})

    helpers.print_host_logins(hosts_logins)
    if log:
        timestamp = datetime.now().strftime("%Y-%m-%d@%H%M%S")
        filename = "hosts_logins_" + timestamp + ".tsv"
        with open(filename, 'w') as outfile:
            outfile.write("Host ID\tHostname\tUsername\tLast Seen\tFirst Seen\tCount\n")
            for host_login in hosts_logins:
                for key, value in host_login['logins'].items():
                    outfile.write(host_login['host_id'] + '\t' + host_login['hostname'] + '\t' + key + '\t' +
                                  value['last_seen'] + '\t' + value['first_seen'] + '\t' + str(value['count']) + '\n')


def list_files(action: str):
    if action == 'list_files':
        files = cs_methods.list_files()['resources']
    else:
        files = cs_methods.list_scripts()['resources']
    if len(files) > 0:
        print("{:<65} {:<32} {:<16} {:<10} {:<48} {:<16}".format('ID', 'Name', 'FileType', 'Size', 'Creator',
                                                                 'LastModified'))
        for file in files:
            size = helpers.to_readable(file['size'])
            print("{:<65} {:<32} {:<16} {:<10} {:<48} {:<16}".format(file['id'], file['name'],
                                                                     file['file_type'], size, file['created_by'],
                                                                     file['modified_timestamp']))
    else:
        print("No RTR response files/scripts on CrowdStrike Cloud!")


def get_file(action: str, file_id: str):
    if file_id is not None:
        if action == 'get_file':
            info = cs_methods.get_file(file_id)['resources']
        else:
            info = cs_methods.get_script(file_id)['resources']
        if len(info) == 1:
            for key, value in info[0].items():
                print(key + ": " + str(value))
        else:
            print("Error! File/Script ID is invalid.")
    else:
        print("Error! No file/script ID is provided.")


def delete_file(action: str, file_id: str):
    if file_id is not None:
        if action == "delete_file":
            response = cs_methods.delete_file(file_id)
        else:
            response = cs_methods.delete_script(file_id)
        if 'errors' not in response:
            print("Deletion successful.")
    else:
        print("Error! No file/script id is provided.")


def upload_file(path: str, description: str):
    if path is None:
        print("Error! No file path provided.")
    elif description is None:
        print("Error! No description provided.")
    elif os.path.isfile(path):
        response = cs_methods.upload_file(path, description)
        if 'errors' not in response:
            print("{} was uploaded.".format(response[1]))
    else:
        print("Error! File path is invalid.")


def upload_script(path: str, permission: str, description: str):
    if path is None:
        print("Error! No script path provided.")
    elif permission is None:
        print("Error! No script permission provided.")
    elif not permission.lower() in ('private', 'group', 'public'):
        print("Error! Invalid script permissions provided. Please choose between private, group or public")
    elif os.path.isfile(path):
        if description is None:
            description = ''
        response = cs_methods.upload_script(path, permission, description)
        if 'errors' not in response:
            print("Script was successfully uploaded.")
    else:
        print("Error! File path is invalid.")


def start_rtr(host: str, file: str, log: bool, queue: bool):
    host_ids = []
    if host is not None:
        host_ids = host.split(',')
    elif file is not None:
        host_ids = helpers.file_to_list(file)

    response = cs_methods.init_rtr_session(host_ids, queue)

    helpers.print_rtr_comms_status(response['resources'])
    if log:
        timestamp = datetime.now().strftime("%Y-%m-%d@%H%M%S")
        filename = "rtr_hosts_" + timestamp + ".tsv"
        with open(filename, 'w') as outfile:
            outfile.write("Host ID\tSession ID\tConnected\tOffline Queued\n")
            helpers.log_rtr_comms_status(response['resources'], outfile)

    if len(response['errors']) == 0:
        print("RTR session started...")
        print("type 'bulk <file path>' to execute multiple commands")

        choice = 1
        if log:
            timestamp = datetime.now().strftime("%Y-%m-%d@%H%M%S")
            filename = "rtr_response_" + timestamp + ".tsv"
            with open(filename, 'w') as outfile:
                outfile.write("Host ID\tSession ID\tComplete\tOffline Queued\tQuery Duration\tStdout\tStderr\tErrors\n")
                while choice != 2:
                    full_cmd = input("(type exit to end) > ")
                    choice = helpers.execute_command(full_cmd, outfile)
        else:
            while choice != 2:
                full_cmd = input("(type exit to end) > ")
                choice = helpers.execute_command(full_cmd, None)
    else:
        print("RTR session was not started.")
        sys.exit(1)


def get_qsessions(to_print: bool) -> list:
    response = cs_methods.get_qsessions()
    if len(response['errors']) == 0:
        resources = response.get('resources', {})
        if to_print:
            for session_id in resources:
                print(session_id)
        return resources
    sys.exit(1)


def get_qsessions_metadata(log: bool):
    session_ids = get_qsessions(False)
    if session_ids is None:
        print("Error! No session metadata to return.")
        sys.exit(1)

    sessions = cs_methods.get_qsessions_metadata(session_ids).get('resources', {})
    helpers.print_qsessions_metadata(sessions)
    if log:
        timestamp = datetime.now().strftime("%Y-%m-%d@%H%M%S")
        filename = "qsessions_metadata_" + timestamp + ".tsv"
        with open(filename, 'w') as outfile:
            outfile.write("Session ID\tCreated At\tUpdated At\tDeleted At\tHost ID\tStatus\tCloud Request ID\t"
                          "Cmd String\tCmd Created At\tCmd Updated At\tCmd Deleted At\tCmd Status\n")
            helpers.log_qsessions_metadata(sessions, outfile)


def del_qsession(qsessionid: str):
    response = cs_methods.delete_qsession(qsessionid)
    if response is None:
        print("Session ({}) was successfully deleted.".format(qsessionid))


def del_qsession_cmd(qsessionid: str, cloudreqid: str):
    response = cs_methods.delete_qsession_command(qsessionid, cloudreqid)
    if 'errors' not in response:
        print("Command ({0}) of session ({1}) was successfully deleted.".format(cloudreqid, qsessionid))


def main():
    argument_parser = argparse.ArgumentParser(description=(
        'BulkStrike enables the usage of CrowdStrike Real Time Response (RTR) to bulk execute commands on '
        'multiple machines.\n'
    ), formatter_class=argparse.RawTextHelpFormatter)

    argument_parser.add_argument('action', metavar='action', default=None, help=(
        '                Req Arguments              Description\n'
        'configure       NIL                        provide CrowdStrike Client ID and/or Secret.\n'
        'req_token       NIL                        request for CrowdStrike authentication token.\n'
        'get_info        -s or -f [--log]           get system info of provided host ids or hostnames.\n'
        'get_logins      -s or -f [--log] [--clean] get recent logins of provided host ids.\n'
        'list_files      NIL                        list basic info of all RTR response files on CrowdStrike Cloud.\n'
        'get_file        -i                         get detailed info of a RTR response file on CrowdStrike Cloud.\n'
        'upload_file     -f and -d                  upload a RTR response file to CrowdStrike Cloud.\n'
        'delete_file     -i                         delete a RTR response file from CrowdStrike Cloud.\n'
        'list_scripts    NIL                        list basic info of all RTR response files on CrowdStrike Cloud.\n'
        'get_script      -i                         get detailed info of a RTR response file on CrowdStrike Cloud.\n'
        'upload_script   -f and -p [-d]             upload a RTR response file to CrowdStrike Cloud.\n'
        'delete_script   -i                         delete a RTR response file from CrowdStrike Cloud.\n'
        'start_rtr       -s or -f [--log] [--queue] initialise rtr session on specified hosts.\n'
        'get_qsessions   NIL                        get session ids of RTR sessions that had commands queued.\n'
        'get_qsess_data  NIL [--log]                get metadata of RTR sessions that had commands queued.\n'
        'del_qsession    -q                         delete a currently queued RTR session.\n'
        'del_qsess_cmd   -q and -c                  delete a currently queued RTR session command.\n'))

    argument_parser.add_argument('-c', '--cloudreqid', default=None, help=(
        'cloud request id of currently queued RTR session command'))
    argument_parser.add_argument('-d', '--description', default=None, help=(
        'description of RTR response file or script'))
    argument_parser.add_argument('-f', '--file', default=None, help=(
        'path of file containing host ids or hostnames'))
    argument_parser.add_argument('-i', '--id', default=None, help=(
        'id of RTR response file or script'))
    argument_parser.add_argument('-p', '--permission', default=None, help=(
        'permission of RTR response script (private, group, public)'))
    argument_parser.add_argument('-q', '--qsessionid', default=None, help=(
        'session id of currently queued RTR session'))
    argument_parser.add_argument('-s', '--host', default=None, help=(
        'host id or hostname'))

    argument_parser.add_argument('--log', action='store_true', help="write raw server response to tsv file in current "
                                                                    "working directory")
    argument_parser.add_argument('--queue', action='store_true', help="queue commands to offline hosts")
    argument_parser.add_argument('--clean', action='store_true', help="exclude less important details from output")

    options = argument_parser.parse_args()
    if options.file is not None:
        options.file = os.path.abspath(options.file)
    options.action = options.action.lower()

    if options.action == 'configure':
        configure()
        return()
    elif options.action == 'req_token':
        req_token()
        return()

    init(read_creds=True, read_token=True)
    if options.action == 'get_info':
        get_info(options.host, options.file, options.log)
    elif options.action == 'get_logins':
        get_logins(options.host, options.file, options.log, options.clean)
    elif options.action == 'start_rtr':
        start_rtr(options.host, options.file, options.log, options.queue)
    elif options.action in ('list_files', 'list_scripts'):
        list_files(options.action)
    elif options.action in ('get_file', 'get_script'):
        get_file(options.action, options.id)
    elif options.action in ('delete_file', 'delete_script'):
        delete_file(options.action, options.id)
    elif options.action == 'upload_file':
        upload_file(options.file, options.description)
    elif options.action == 'upload_script':
        upload_script(options.file, options.permission, options.description)
    elif options.action == 'get_qsessions':
        get_qsessions(True)
    elif options.action == 'get_qsess_data':
        get_qsessions_metadata(options.log)
    elif options.action == 'del_qsession':
        del_qsession(options.qsessionid)
    elif options.action == 'del_qsess_cmd':
        del_qsession_cmd(options.qsessionid, options.cloudreqid)


if __name__ == '__main__':
    if not main():
        sys.exit(1)
    else:
        sys.exit(0)
