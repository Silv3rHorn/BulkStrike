# BulkStrike
![](https://img.shields.io/badge/python-3.7-blue.svg)

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
usage: bulk_strike.py action [-s HOST] [-f FILE] [-i ID] [-d DESCRIPTION]
                      [-p PERMISSION]               

positional arguments:
  action                                Req Arguments    Description
                        configure       NIL              provide CrowdStrike Client ID and/or Secret.
                        req_token       NIL              request for CrowdStrike authentication token.
                        get_info        -s or -f         get system info of provided host id or hostname.
                        list_files      NIL              list basic info of all RTR response files on CrowdStrike Cloud.
                        get_file        -i               get detailed info of a RTR response file on CrowdStrike Cloud.
                        upload_file     -f and -d        upload a RTR response file to CrowdStrike Cloud.
                        delete_file     -i               delete a RTR response file from CrowdStrike Cloud.
                        list_scripts    NIL              list basic info of all RTR response files on CrowdStrike Cloud.
                        get_script      -i               get detailed info of a RTR response file on CrowdStrike Cloud.
                        upload_script   -f and -p [-d]   upload a RTR response file to CrowdStrike Cloud.
                        delete_script   -i               delete a RTR response file from CrowdStrike Cloud.
                        start_rtr       -s or -f         initialise rtr session on specified hosts.

optional arguments:
  -h, --help            show this help message and exit
  -s HOST, --host HOST  host id or hostname
  -f FILE, --file FILE  path of file containing host ids or hostnames
  -i ID, --id ID        id of RTR response file or script
  -d DESCRIPTION, --description DESCRIPTION
                        description of RTR response file or script
  -p PERMISSION, --permission PERMISSION
                        permission of RTR response script (private, group, public)
```

## Future Work
1. Create parallel thread to keep RTR session alive
2. Download retrieved file (via `get file`) to local disk
3. Retry the initiating/starting of RTR session to offline host until it comes online

## Credits
[Demisto's CrowdStrikeFalcon Integrations code](https://github.com/demisto/content/blob/f8a0f42576a05b27389faf9f89518bbab4dd21cc/Integrations/CrowdStrikeFalcon/CrowdStrikeFalcon.py)
