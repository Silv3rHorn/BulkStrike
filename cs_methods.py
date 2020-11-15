import base64
import helpers
import json
import os
import requests
import sys
from datetime import datetime
from bulk_strike import TOKEN_PATH

# GLOBALS/PARAMS
CLIENT_ID = ''
SECRET = ''
SERVER = 'https://api.crowdstrike.com'
USE_SSL = True
BYTE_CREDS = '{name}:{password}'.format(name=CLIENT_ID, password=SECRET).encode('utf-8')
HEADERS = {  # Headers to be sent in requests
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'Authorization': 'Basic {}'.format(base64.b64encode(BYTE_CREDS).decode())
}
TOKEN = ''
TOKEN_LIFE_TIME = 28
TOKEN_REQ_TIME = datetime.min
BATCH_ID = ''
BATCH_LIFE_TIME = 5
BATCH_REQ_TIME = datetime.now()


def http_request(method: str, url_suffix: str, params: dict = None, data: dict = None, headers: dict = HEADERS,
                 files: dict = None, safe: bool = False, get_token_flag: bool = True) -> dict:
    """
        A wrapper for requests lib to send our requests and handle requests and responses better.
        :param method: HTTP method for the request.
        :param url_suffix: The suffix of the URL (endpoint)
        :param params: The URL params to be passed.
        :param data: The body data of the request.
        :param headers: Request headers
        :param files: The files data of the request
        :param safe: If set to true will return None in case of http error
        :param get_token_flag: If set to True will call get_token()
        :return: Returns the http request response json
    """
    response = ""

    if get_token_flag:
        token = get_token()
        headers['Authorization'] = 'Bearer {}'.format(token)
    url = SERVER + url_suffix
    try:
        response = requests.request(
            method,
            url,
            verify=USE_SSL,
            params=params,
            data=data,
            headers=headers,
            files=files
        )
    except requests.exceptions.RequestException:
        print('Error in connection to the server. Please make sure you entered the URL correctly.')
    try:
        resp_json = response.json()
        # print(url_suffix, response.status_code)  # debug
        if response.status_code not in {200, 201, 202}:
            reason = response.reason
            resources = resp_json.get('resources', {})
            if resources and type(resources) is dict:
                for host_id, resource in resources.items():
                    errors = resource.get('errors', [])
                    if errors:
                        error_message = errors[0].get('message')
                        reason += f'\nHost ID {host_id} - {error_message}'
            elif resp_json.get('errors'):
                errors = resp_json.get('errors', [])
                for error in errors:
                    reason += f"\n{error.get('message')}"
            err_msg = 'Error in API call to CrowdStrike Falcon: code: {code} - reason: {reason}'.format(
                code=response.status_code,
                reason=reason
            )
            # try to create a new token
            if response.status_code in (401, 403):
                if helpers.is_expiring(TOKEN_LIFE_TIME, TOKEN_REQ_TIME):
                    get_token(new_token=True)
                    return http_request(method, url_suffix, params, data, HEADERS, files, safe, get_token_flag=False)
            elif safe:
                return None
            print(err_msg)
        return resp_json
    except ValueError as exception:
        if url_suffix == '/real-time-response/entities/sessions/v1' and method == 'DELETE':  # empty json when success
            pass
        else:
            raise ValueError(f'Failed to parse json object from response: {exception} - {response.content}')


def get_token(new_token: bool = False) -> str:
    """
        Retrieves the token from the server if it's expired and updates the global HEADERS to include it
        :param new_token: If set to True will generate a new token regardless of time passed
        :return: Token
    """
    global HEADERS, TOKEN
    auth_token = TOKEN

    if new_token:
        auth_token = get_token_request()
    else:
        if helpers.is_expiring(TOKEN_LIFE_TIME, TOKEN_REQ_TIME):
            auth_token = get_token_request()

    HEADERS['Authorization'] = 'Bearer {}'.format(auth_token)
    TOKEN = auth_token
    with open(TOKEN_PATH, 'w') as outfile:
        outfile.write(auth_token)
    return auth_token


def get_token_request() -> str:
    """
        Sends token request
        :return: Token
    """
    global TOKEN_REQ_TIME

    body = {
        'client_id': CLIENT_ID,
        'client_secret': SECRET
    }
    headers = {
        'Authorization': HEADERS['Authorization']
    }
    token_res = http_request('POST', '/oauth2/token', data=body, headers=headers, safe=True,
                             get_token_flag=False)
    try:
        TOKEN_REQ_TIME = datetime.now()
        return token_res.get('access_token')
    except AttributeError:
        print("Authorization Error: User has no authorization to create a token. Please make sure you entered the "
              "credentials correctly.")
        sys.exit(1)


def find_hosts(hostnames: str) -> list:
    """
    Find specific hosts based on hostname(s)
    :param hostnames:  Hostname(s)
    :return: List of host id(s)
    """
    uri_path = '/devices/queries/devices/v1'
    params = dict()
    params['filter'] = [hostnames]
    response = http_request('GET', uri_path, params, get_token_flag=False)

    return response.get('resources', {})


def get_host_info(host_ids: list) -> dict:
    """
        Get info about one of more hosts
        :param host_ids: List of host id(s) to get info about
    """
    uri_path = '/devices/entities/devices/v1'
    params = dict()
    params['ids'] = host_ids
    return http_request('GET', uri_path, params, get_token_flag=False)


def upload_file(path: str, description: str) -> tuple:
    """
        Uploads a file given its path
        :param path: The path of the file to upload
        :param description: file description
        :return: Response JSON which contains errors (if exist) and how many resources were affected and the file name
    """
    name = os.path.basename(path)

    endpoint_url = '/real-time-response/entities/put-files/v1'
    headers = {
        # 'Content-Type': 'multipart/form-data',
        'Accept': 'application/json',
        'Authorization': HEADERS['Authorization']
    }
    body = {
        # 'name': (None, name),
        'description': (None, description),
        'file': (name, open(path, 'rb'))
    }

    response = http_request('POST', endpoint_url, headers=headers, files=body)
    return response, name


def get_file(file_id: str) -> dict:
    """
        Get put-files based on the ID's given
        :param file_id: ID of file to get
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/put-files/v1'
    params = {
        'ids': file_id
    }
    response = http_request('GET', endpoint_url, params=params)
    return response


def delete_file(file_id: str) -> dict:
    """
        Delete a put-file based on the ID given
        :param file_id: ID of file to delete
        :return: Response JSON which contains errors (if exist) and how many resources were affected
    """
    endpoint_url = '/real-time-response/entities/put-files/v1'
    params = {
        'ids': file_id
    }
    response = http_request('DELETE', endpoint_url, params=params)
    return response


def list_files() -> dict:
    """
        Get a list of put-file ID's that are available to the user for the put command.
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/put-files/v1'
    response = http_request('GET', endpoint_url)
    return response


def upload_script(path: str, permission_type: str, description: str) -> dict:
    """
        Uploads a script by either given content or file
        :param path: The path of the script to upload
        :param permission_type: Permissions type of script to upload
        :param description: Script description
        :return: Response JSON which contains errors (if exist) and how many resources were affected
    """
    name = os.path.basename(path)
    endpoint_url = '/real-time-response/entities/scripts/v1'

    body = dict()
    body['name'] = (None, name)
    body['permission_type'] = (None, permission_type)
    body['description'] = (None, description)
    body['file'] = (name, open(path, 'rb'))

    headers = {
        'Authorization': HEADERS['Authorization'],
        'Accept': 'application/json'
    }

    response = http_request('POST', endpoint_url, files=body, headers=headers)
    return response


def get_script(script_id: str) -> dict:
    """
        Retrieves a script given its ID
        :param script_id: ID of script to get
        :return: Response JSON which contains errors (if exist) and retrieved resource
    """
    endpoint_url = '/real-time-response/entities/scripts/v1'
    params = {
        'ids': script_id
    }
    response = http_request('GET', endpoint_url, params=params)
    return response


def delete_script(script_id: str) -> dict:
    """
        Deletes a script given its ID
        :param script_id: ID of script to delete
        :return: Response JSON which contains errors (if exist) and how many resources were affected
    """
    endpoint_url = '/real-time-response/entities/scripts/v1'
    params = {
        'ids': script_id
    }
    response = http_request('DELETE', endpoint_url, params=params)
    return response


def list_scripts() -> dict:
    """
        Retrieves list of scripts
        :return: Response JSON which contains errors (if exist) and retrieved resources
    """
    endpoint_url = '/real-time-response/entities/scripts/v1'
    response = http_request('GET', endpoint_url)
    return response


def init_rtr_session(host_ids: list, queue: bool) -> dict:
    """
        Start a session with one or more hosts
        :param host_ids: List of host agent ID’s to initialize a RTR session on
        :param queue: Boolean to queue commands for offline hosts
        :return: The session batch ID to execute the command on
    """
    global BATCH_ID, BATCH_REQ_TIME

    endpoint_url = '/real-time-response/combined/batch-init-session/v1'
    body = json.dumps({
        'host_ids': host_ids,
        'queue_offline': queue
    })
    response = http_request('POST', endpoint_url, data=body)
    BATCH_REQ_TIME = datetime.now()
    BATCH_ID = response.get('batch_id')

    return response


def refresh_rtr_session() -> dict:
    """
        Batch refresh a RTR session on multiple hosts. RTR sessions will expire after 10 minutes unless refreshed
        :return:
    """
    global BATCH_REQ_TIME

    endpoint_url = '/real-time-response/combined/batch-refresh-session/v1'
    body = json.dumps({
        'batch_id': BATCH_ID
    })
    response = http_request('POST', endpoint_url, data=body)
    BATCH_REQ_TIME = datetime.now()
    return response


def delete_rtr_session() -> dict:
    """
        Retrieves a script given its ID
        :return: Response JSON which contains errors (if exist) and retrieved resource
    """
    endpoint_url = '/real-time-response/entities/sessions/v1'

    if helpers.is_expiring(BATCH_LIFE_TIME, BATCH_REQ_TIME):
        refresh_rtr_session()

    params = {
        'session_id': BATCH_ID
    }
    response = http_request('DELETE', endpoint_url, params=params)
    return response


def run_batch_admin_cmd(command_type: str, full_command: str) -> dict:
    """
        Batch executes a RTR administrator command across the hosts mapped to the given batch id
        :param command_type: Command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
    """
    endpoint_url = '/real-time-response/combined/batch-admin-command/v1'

    if helpers.is_expiring(BATCH_LIFE_TIME, BATCH_REQ_TIME):
        refresh_rtr_session()

    params = {
        'timeout_duration': '10m'
    }
    body = json.dumps({
        'base_command': command_type,
        'batch_id': BATCH_ID,
        'command_string': full_command
    })
    response = http_request('POST', endpoint_url, params=params, data=body)

    return response


def run_batch_ar_cmd(command_type: str, full_command: str) -> dict:
    """
        Batch executes a RTR active-responder command across the hosts mapped to the given batch id
        :param command_type: Command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
    """
    endpoint_url = '/real-time-response/combined/batch-active-responder-command/v1'

    if helpers.is_expiring(BATCH_LIFE_TIME, BATCH_REQ_TIME):
        refresh_rtr_session()

    params = {
        'timeout_duration': '10m'
    }
    body = json.dumps({
        'base_command': command_type,
        'batch_id': BATCH_ID,
        'command_string': full_command
    })
    response = http_request('POST', endpoint_url, params=params, data=body)

    return response


def run_batch_cmd(command_type: str, full_command: str) -> dict:
    """
        Batch executes a RTR active-responder command across the hosts mapped to the given batch id
        :param command_type: Command type we are going to execute, for example: ls or cd.
        :param full_command: Full command string for the command.
    """
    endpoint_url = '/real-time-response/combined/batch-command/v1'

    if helpers.is_expiring(BATCH_LIFE_TIME, BATCH_REQ_TIME):
        refresh_rtr_session()

    params = {
        'timeout_duration': '2m'
    }
    body = json.dumps({
        'base_command': command_type,
        'batch_id': BATCH_ID,
        'command_string': full_command
    })
    response = http_request('POST', endpoint_url, params=params, data=body)

    return response


def get_qsessions() -> dict:
    """
        Get session ids of currently queued RTR sessions
    """
    endpoint_url = '/real-time-response/queries/sessions/v1'

    if helpers.is_expiring(BATCH_LIFE_TIME, BATCH_REQ_TIME):
        refresh_rtr_session()

    params = {
        'sort': 'created_at|desc',
        'filter': 'commands_queued:1'
    }
    response = http_request('GET', endpoint_url, params=params)

    return response


def get_qsessions_metadata(session_ids: list) -> dict:
    """
        Get metadata of currently queued RTR sessions by session IDs
        :param session_ids: List of session ids to retrieve metadata for
    """
    endpoint_url = '/real-time-response/entities/queued-sessions/GET/v1'

    if helpers.is_expiring(BATCH_LIFE_TIME, BATCH_REQ_TIME):
        refresh_rtr_session()

    body = json.dumps({
        'ids': session_ids
    })
    response = http_request('POST', endpoint_url, data=body)

    return response


def delete_qsession(session_id: str) -> dict:
    """
        Delete a queued RTR session by session ID
        :param session_id: Session ID of session to delete
    """
    endpoint_url = '/real-time-response/entities/sessions/v1'

    if helpers.is_expiring(BATCH_LIFE_TIME, BATCH_REQ_TIME):
        refresh_rtr_session()

    params = {
        'session_id': session_id
    }
    response = http_request('DELETE', endpoint_url, params=params)

    return response


def delete_qsession_command(session_id: str, cloud_request_id: str) -> dict:
    """
        Delete a queued RTR session command by session ID and cloud request ID
        :param session_id:
        :param cloud_request_id:
    """

    endpoint_url = '/real-time-response/entities/queued-sessions/command/v1'

    if helpers.is_expiring(BATCH_LIFE_TIME, BATCH_REQ_TIME):
        refresh_rtr_session()

    params = {
        'session_id': session_id,
        'cloud_request_id': cloud_request_id
    }
    response = http_request('DELETE', endpoint_url, params=params)

    return response
