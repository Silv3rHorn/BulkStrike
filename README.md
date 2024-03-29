# BulkStrike
![](https://img.shields.io/badge/python-3-blue.svg)

BulkStrike enables the usage of CrowdStrike Real Time Response (RTR) to bulk collect artifacts from multiple machines.

## Dependencies
None if using [release executable](https://github.com/Silv3rHorn/BulkStrike/releases).
Else, refer to requirements.txt

## Usage
* From CrowdStrike Falcon web console, click on _Support_ | _API Clients and Keys_
* _Add new API client_ and ensure at least the following _API Scopes_
    * _Hosts_ - `Read`
    * _Real time response_ - `Read` and `Write`
* It is recommended to also have `Write` scope for _Real time response (admin)_ otherwise some RTR commands (e.g. `put`) will not execute
* Input your Client ID and Secret via `bulk_strike configure`
* Request for an Authentication Token via `bulk_strike req_token`
* Start using BulkStrike!
* More help available via `bulk_stike -h` 
```bash
usage: bulk_strike.py [-h] [-c CLOUDREQID] [-d DESCRIPTION] [-f FILE] [-i ID]
                      [-p PERMISSION] [-q QSESSIONID] [-s HOST] [--log]
                      [--queue]
                      action

BulkStrike enables the usage of CrowdStrike Real Time Response (RTR) to bulk execute commands on multiple machines.

positional arguments:
  action                                Req Arguments              Description
                        configure       NIL                        provide CrowdStrike Client ID, Secret and API server.
                        req_token       NIL                        request for CrowdStrike authentication token.
                        get_info        -s or -f [--log]           get system info of provided host id or hostname.
                        get_logins      -s or -f [--log] [--clean] get recent logins of provided host ids.
                        list_files      NIL                        list basic info of all RTR response files on CrowdStrike Cloud.
                        get_file        -i                         get detailed info of a RTR response file on CrowdStrike Cloud.
                        upload_file     -f and -d                  upload a RTR response file to CrowdStrike Cloud.
                        delete_file     -i                         delete a RTR response file from CrowdStrike Cloud.
                        list_scripts    NIL                        list basic info of all RTR response files on CrowdStrike Cloud.
                        get_script      -i                         get detailed info of a RTR response file on CrowdStrike Cloud.
                        upload_script   -f and -p [-d]             upload a RTR response file to CrowdStrike Cloud.
                        delete_script   -i                         delete a RTR response file from CrowdStrike Cloud.
                        start_rtr       -s or -f [--log] [--queue] initialise rtr session on specified hosts.
                        get_qsessions   NIL                        get session ids of RTR sessions that had commands queued.
                        get_qsess_data  NIL [--log]                get metadata of RTR sessions that had commands queued.
                        del_qsession    -q                         delete a currently queued RTR session.
                        del_qsess_cmd   -q and -c                  delete a currently queued RTR session command.

optional arguments:
  -h, --help            show this help message and exit
  -c CLOUDREQID, --cloudreqid CLOUDREQID
                        cloud request id of currently queued RTR session command
  -d DESCRIPTION, --description DESCRIPTION
                        description of RTR response file or script
  -f FILE, --file FILE  path of file containing host ids or hostnames
  -i ID, --id ID        id of RTR response file or script
  -p PERMISSION, --permission PERMISSION
                        permission of RTR response script (private, group, public)
  -q QSESSIONID, --qsessionid QSESSIONID
                        session id of currently queued RTR session
  -s HOST, --host HOST  host id or hostname
  --log                 write raw server response to tsv file in current working directory
  --queue               queue commands to offline hosts
  --clean               exclude less important details from output
```

## Demo
![](demo.gif)

## Future Work
1. Create parallel thread to keep RTR session alive
2. Download retrieved file (via `get file`) to local disk
3. ~~Retry the initiating/starting of RTR session to offline host until it comes online~~

## Credits
[Demisto's CrowdStrikeFalcon Integrations code](https://github.com/demisto/content/blob/f8a0f42576a05b27389faf9f89518bbab4dd21cc/Integrations/CrowdStrikeFalcon/CrowdStrikeFalcon.py)
