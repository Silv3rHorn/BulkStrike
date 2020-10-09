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
                cs_methods.CLIENT_ID = infile.readline().split(":")[1].strip()
                cs_methods.SECRET = infile.readline().split(":")[1].strip()
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
    if temp_client_id != '':
        cs_methods.CLIENT_ID = temp_client_id
    if temp_secret != '':
        cs_methods.SECRET = temp_secret
    with open(CRED_PATH, 'w') as outfile:
        outfile.writelines(["Client ID: {}".format(cs_methods.CLIENT_ID), "\nSecret: {}".format(cs_methods.SECRET)])
    init(read_creds=False, read_token=False)


def req_token():
    init(read_creds=True, read_token=False)
    cs_methods.get_token(new_token=True)


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
            outfile.write("Host ID\tComplete\tOffline Queued\n")
            helpers.log_rtr_comms_status(response['resources'], outfile)

    if len(response['errors']) == 0:
        print("RTR session started...")
        print("type 'bulk <file path>' to execute multiple commands")

        choice = 1
        if log:
            timestamp = datetime.now().strftime("%Y-%m-%d@%H%M%S")
            filename = "rtr_response_" + timestamp + ".tsv"
            with open(filename, 'w') as outfile:
                outfile.write("Host ID\tComplete\tOffline Queued\tQuery Duration\tStdout\tStderr\tErrors\n")
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


def main():
    argument_parser = argparse.ArgumentParser(description=(
        'BulkStrike enables the usage of CrowdStrike Real Time Response (RTR) to bulk collect artifacts '
        'from multiple machines.\n'
    ), formatter_class=argparse.RawTextHelpFormatter)

    argument_parser.add_argument('action', metavar='action', default=None, help=(
        '                Req Arguments              Description\n'
        'configure       NIL                        provide CrowdStrike Client ID and/or Secret.\n'
        'req_token       NIL                        request for CrowdStrike authentication token.\n'
        'get_info        -s or -f [--log]           get system info of provided host id or hostname.\n'
        'list_files      NIL                        list basic info of all RTR response files on CrowdStrike Cloud.\n'
        'get_file        -i                         get detailed info of a RTR response file on CrowdStrike Cloud.\n'
        'upload_file     -f and -d                  upload a RTR response file to CrowdStrike Cloud.\n'
        'delete_file     -i                         delete a RTR response file from CrowdStrike Cloud.\n'
        'list_scripts    NIL                        list basic info of all RTR response files on CrowdStrike Cloud.\n'
        'get_script      -i                         get detailed info of a RTR response file on CrowdStrike Cloud.\n'
        'upload_script   -f and -p [-d]             upload a RTR response file to CrowdStrike Cloud.\n'
        'delete_script   -i                         delete a RTR response file from CrowdStrike Cloud.\n'
        'start_rtr       -s or -f [--log] [--queue] initialise rtr session on specified hosts.\n'))
    argument_parser.add_argument('-s', '--host', default=None, help=(
        'host id or hostname'))
    argument_parser.add_argument('-f', '--file', default=None, help=(
        'path of file containing host ids or hostnames'))
    argument_parser.add_argument('-i', '--id', default=None, help=(
        'id of RTR response file or script'))
    argument_parser.add_argument('-d', '--description', default=None, help=(
        'description of RTR response file or script'))
    argument_parser.add_argument('-p', '--permission', default=None, help=(
        'permission of RTR response script (private, group, public'))
    argument_parser.add_argument('--log', action='store_true', help="write raw server response to tsv file in current "
                                                                    "working directory")
    argument_parser.add_argument('--queue', action='store_true', help="queue commands to offline hosts")

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


if __name__ == '__main__':
    if not main():
        sys.exit(1)
    else:
        sys.exit(0)
