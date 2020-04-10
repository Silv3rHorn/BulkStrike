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

## Credits
[Demisto's CrowdStrikeFalcon Integrations code](https://github.com/demisto/content/blob/f8a0f42576a05b27389faf9f89518bbab4dd21cc/Integrations/CrowdStrikeFalcon/CrowdStrikeFalcon.py)
