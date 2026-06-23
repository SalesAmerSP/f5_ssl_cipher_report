#!/usr/bin/env python3
"""Report BIG-IP LTM virtual servers and their SSL profiles/ciphers via iControl REST."""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import shlex
import sys
from dataclasses import dataclass
from typing import Any, NoReturn

import requests
import urllib3

__version__ = "1.1.0"


@dataclass
class Config:
    """Resolved runtime configuration produced by get_args()."""

    host: str
    username: str
    password: str
    fullciphers: bool
    verbose: bool
    csv: str | None
    verify: bool | str
    timeout: float


def get_args() -> Config:
    """Parse CLI arguments, resolve credentials/TLS settings, and return a Config."""
    cmdargs = argparse.ArgumentParser()
    cmdargs.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    cmdargs.add_argument('--host', action='store', required=False, type=str,
                         help='ip of BIG-IP REST interface, typically the mgmt ip (or F5_HOST env var)')
    cmdargs.add_argument('--username', action='store', required=False, type=str,
                         help='username for REST authentication (or F5_USERNAME env var)')
    # Accepted but intentionally unsupported: catch it so we can return a helpful
    # message instead of argparse's generic "unrecognized arguments" error.
    cmdargs.add_argument('--password', nargs='?', const=True, default=None, help=argparse.SUPPRESS)
    cmdargs.add_argument('--csv', action='store', required=False, type=str,
                         help='CSV filename for report (optional)')
    cmdargs.add_argument('--fullciphers', action='store_true', required=False,
                         help='flag for displaying list of all ciphers in profile')
    cmdargs.add_argument('--verbose', action='store_true', required=False,
                         help='prints additional information during execution')
    cmdargs.add_argument('--ca-bundle', action='store', required=False, type=str,
                         help='path to a CA bundle used to verify the BIG-IP management certificate')
    cmdargs.add_argument('--insecure', action='store_true', required=False,
                         help='disable TLS certificate verification of the BIG-IP management interface (not recommended)')
    cmdargs.add_argument('--timeout', action='store', required=False, type=float, default=30,
                         help='per-request timeout in seconds (default: 30)')
    parsed_args = cmdargs.parse_args()
    if parsed_args.password is not None:
        cmdargs.error('--password is not supported for security reasons: it exposes the '
                      'credential in your shell history and the process list. Use the F5_PASSWORD '
                      'environment variable instead, or omit it to be prompted securely. Since you '
                      'just typed it, scrub it from your shell history now '
                      "(e.g. 'history -d <line>' for bash, or 'history delete <n>' for zsh).")
    host = parsed_args.host or os.environ.get('F5_HOST')
    if not host:
        cmdargs.error('host is required: pass --host or set the F5_HOST environment variable')
    username = parsed_args.username or os.environ.get('F5_USERNAME')
    if not username:
        cmdargs.error('username is required: pass --username or set the F5_USERNAME environment variable')
    password = os.environ.get('F5_PASSWORD')
    if not password:
        password = getpass.getpass('Password for ' + username + '@' + host + ': ')
    if parsed_args.insecure:
        verify: bool | str = False
    elif parsed_args.ca_bundle:
        verify = parsed_args.ca_bundle
    else:
        verify = True
    return Config(host=host, username=username, password=password,
                  fullciphers=parsed_args.fullciphers, verbose=parsed_args.verbose,
                  csv=parsed_args.csv, verify=verify, timeout=parsed_args.timeout)


def abort_script(reason: object) -> NoReturn:
    """Print an error and exit with status 2."""
    print('*** Aborting script execution! ***')
    if len(str(reason)) > 0:
        print('ERROR: ' + str(reason))
    sys.exit(2)


class BigIp:
    """Thin iControl REST client: one authenticated, reused session per BIG-IP."""

    def __init__(self, host: str, username: str, password: str,
                 verify: bool | str, timeout: float = 30) -> None:
        self.base_uri = 'https://' + host + '/mgmt/tm'
        self.verify = verify
        self.timeout = timeout
        self.session = requests.session()
        self.session.headers.update({'Content-type': 'application/json'})
        self.session.auth = (username, password)

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Issue a request relative to the BIG-IP /mgmt/tm base; abort on any error."""
        try:
            response = self.session.request(method, self.base_uri + path, verify=self.verify,
                                            timeout=self.timeout, **kwargs)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            abort_script(str(e))
        return response

    def get_json(self, path: str) -> Any:
        """GET a path and return the parsed JSON body."""
        return json.loads(self._request('GET', path).text)

    def post_json(self, path: str, payload: dict[str, Any]) -> Any:
        """POST a JSON payload to a path and return the parsed JSON body."""
        return json.loads(self._request('POST', path, data=json.dumps(payload)).text)


def retrieve_ssl_profiles(bigip: BigIp, profile_type: str, label: str, tmm_flag: str,
                          fullciphers: bool, verbose: bool) -> dict[str, dict[str, str]]:
    """Return {name: {name, cipherstring, parent, [cipherlist]}} for an SSL profile type.

    profile_type is the REST collection ('client-ssl' / 'server-ssl'), label is the
    word used in output ('Client' / 'Server'), and tmm_flag is the tmm option used to
    expand the cipher list ('--clientciphers' / '--serverciphers').
    """
    profiles: dict[str, dict[str, str]] = {}
    for profile in bigip.get_json('/ltm/profile/' + profile_type).get('items', []):
        name = str(profile['name'])
        cipherstring = str(profile['ciphers'])
        parent = str(profile['defaultsFrom']) if 'defaultsFrom' in profile else 'none'
        if verbose:
            print('Found ' + label + ' SSL profile: ' + name)
            print(' -> Ciphers: ' + cipherstring)
        entry = {'name': name, 'cipherstring': cipherstring, 'parent': parent}
        if fullciphers:
            if verbose:
                print(' -> Retrieving complete cipher list')
            api_payload = {"command": "run",
                           "utilCmdArgs": "-c " + shlex.quote("tmm " + tmm_flag + " " + cipherstring)}
            entry['cipherlist'] = bigip.post_json('/util/bash', api_payload)['commandResult']
        profiles[name] = entry
    return profiles


def fetch_virtual_profiles(bigip: BigIp, virtual: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the profile list attached to a single virtual server."""
    if 'subPath' in virtual:
        path = ('/ltm/virtual/~' + virtual['partition'] + '~' + virtual['subPath']
                + '~' + virtual['name'] + '/profiles')
    else:
        path = '/ltm/virtual/~' + virtual['partition'] + '~' + virtual['name'] + '/profiles'
    return bigip.get_json(path).get('items', [])


def retrieve_virtual_servers(bigip: BigIp, verbose: bool) -> list[dict[str, Any]]:
    """Return all virtual servers, each annotated with its fetched 'profiles' list."""
    virtual_servers = bigip.get_json('/ltm/virtual').get('items', [])
    for current_virtual_server in virtual_servers:
        if verbose:
            print("Found virtual server " + current_virtual_server['name'])
        # Fetch each virtual's profiles once here so the console and CSV reports
        # can both read them without a second round of REST calls.
        current_virtual_server['profiles'] = fetch_virtual_profiles(bigip, current_virtual_server)
    return virtual_servers


def print_ssl_profile(profile_name: str, context: str, cipher_dict: dict[str, dict[str, str]],
                      fullcipherflag: bool) -> None:
    """Print one SSL profile's cipher string, parent, and (optionally) full cipher list."""
    print(' -> Profile found: ' + profile_name + ' (Context: ' + context + ')')
    print('   -> Cipher string: ' + cipher_dict[profile_name]['cipherstring'])
    print('   -> Parent profile: ' + cipher_dict[profile_name]['parent'])
    if fullcipherflag:
        print('   -> Complete cipher list: \n' + cipher_dict[profile_name]['cipherlist'])


def create_ssl_report(fullcipherflag: bool, CLIENT_CIPHER_DICT: dict[str, dict[str, str]],
                      SERVER_CIPHER_DICT: dict[str, dict[str, str]],
                      LTM_VIRTUAL_LIST: list[dict[str, Any]], verbose: bool) -> None:
    """Print the per-virtual-server SSL profile report to stdout."""
    for current_virtual in LTM_VIRTUAL_LIST:
        print('*********************\nVirtual server: ' + current_virtual['fullPath']
              + ' (' + current_virtual['destination'] + ')')
        for current_virtual_profile in current_virtual['profiles']:
            name = current_virtual_profile['name']
            context = current_virtual_profile['context']
            if context == 'clientside' and name in CLIENT_CIPHER_DICT:
                print_ssl_profile(name, context, CLIENT_CIPHER_DICT, fullcipherflag)
            elif context == 'serverside' and name in SERVER_CIPHER_DICT:
                print_ssl_profile(name, context, SERVER_CIPHER_DICT, fullcipherflag)
            elif verbose:
                print('   -> Non-SSL Profile')


def create_ssl_csv(csvfile: str, CLIENT_CIPHER_DICT: dict[str, dict[str, str]],
                   SERVER_CIPHER_DICT: dict[str, dict[str, str]],
                   LTM_VIRTUAL_LIST: list[dict[str, Any]]) -> None:
    """Write a per-virtual-server summary (client/server profile + parent) to a CSV file."""
    try:
        outputcsv = open(csvfile, mode="w", newline='')
    except OSError as e:
        abort_script(str(e))
        return
    with outputcsv:
        report_writer = csv.writer(outputcsv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        report_writer.writerow(['Virtual Server Path', 'Virtual Server Destination',
                                'CLIENT SSL PROFILE', 'PARENT CLIENT SSL PROFILE',
                                'SERVER SSL PROFILE', 'PARENT SERVER SSL PROFILE'])
        for current_virtual in LTM_VIRTUAL_LIST:
            current_client_profile = 'none'
            current_client_parent_profile = 'none'
            current_server_profile = 'none'
            current_server_parent_profile = 'none'
            for current_virtual_profile in current_virtual['profiles']:
                name = current_virtual_profile['name']
                if current_virtual_profile['context'] == 'clientside' and name in CLIENT_CIPHER_DICT:
                    current_client_profile = name
                    current_client_parent_profile = CLIENT_CIPHER_DICT[name]['parent']
                elif current_virtual_profile['context'] == 'serverside' and name in SERVER_CIPHER_DICT:
                    current_server_profile = name
                    current_server_parent_profile = SERVER_CIPHER_DICT[name]['parent']
            report_writer.writerow([current_virtual['fullPath'], current_virtual['destination'],
                                    current_client_profile, current_client_parent_profile,
                                    current_server_profile, current_server_parent_profile])


def main() -> None:
    """Entry point: gather profiles and virtuals, then print the report and optional CSV."""
    cfg = get_args()
    if cfg.verify is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    bigip = BigIp(cfg.host, cfg.username, cfg.password, cfg.verify, cfg.timeout)
    client_ssl_profile_list = retrieve_ssl_profiles(bigip, 'client-ssl', 'Client', '--clientciphers',
                                                    cfg.fullciphers, cfg.verbose)
    server_ssl_profile_list = retrieve_ssl_profiles(bigip, 'server-ssl', 'Server', '--serverciphers',
                                                    cfg.fullciphers, cfg.verbose)
    virtual_server_list = retrieve_virtual_servers(bigip, cfg.verbose)
    create_ssl_report(cfg.fullciphers, client_ssl_profile_list, server_ssl_profile_list,
                      virtual_server_list, cfg.verbose)
    if cfg.csv:
        create_ssl_csv(cfg.csv, client_ssl_profile_list, server_ssl_profile_list, virtual_server_list)
    print('\nReport complete.')


if __name__ == "__main__":
    main()
