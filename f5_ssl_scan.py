#!/usr/bin/env python3

import argparse
import csv
import getpass
import json
import os
import shlex
import sys

import requests
import urllib3

__version__ = "1.1.0"


def get_args():
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
        verify = False
    elif parsed_args.ca_bundle:
        verify = parsed_args.ca_bundle
    else:
        verify = True
    BIG_IP = {'host': host, 'username': username, 'password': password,
              'fullciphers': parsed_args.fullciphers, 'verbose': parsed_args.verbose, 'csv': parsed_args.csv,
              'verify': verify, 'timeout': parsed_args.timeout}
    return BIG_IP


def abort_script(reason):
    print('*** Aborting script execution! ***')
    if len(str(reason)) > 0:
        print('ERROR: ' + str(reason))
    sys.exit(2)


class BigIp:
    """Thin iControl REST client: one authenticated, reused session per BIG-IP."""

    def __init__(self, host, username, password, verify, timeout=30):
        self.base_uri = 'https://' + host + '/mgmt/tm'
        self.verify = verify
        self.timeout = timeout
        self.session = requests.session()
        self.session.headers.update({'Content-type': 'application/json'})
        self.session.auth = (username, password)

    def _request(self, method, path, **kwargs):
        try:
            response = self.session.request(method, self.base_uri + path, verify=self.verify,
                                            timeout=self.timeout, **kwargs)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            abort_script(str(e))
        return response

    def get_json(self, path):
        return json.loads(self._request('GET', path).text)

    def post_json(self, path, payload):
        return json.loads(self._request('POST', path, data=json.dumps(payload)).text)


def retrieve_ssl_profiles(bigip, profile_type, label, tmm_flag, fullciphers, verbose):
    """Return {name: {name, cipherstring, parent, [cipherlist]}} for an SSL profile type.

    profile_type is the REST collection ('client-ssl' / 'server-ssl'), label is the
    word used in output ('Client' / 'Server'), and tmm_flag is the tmm option used to
    expand the cipher list ('--clientciphers' / '--serverciphers').
    """
    profiles = {}
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


def fetch_virtual_profiles(bigip, virtual):
    if 'subPath' in virtual:
        path = ('/ltm/virtual/~' + virtual['partition'] + '~' + virtual['subPath']
                + '~' + virtual['name'] + '/profiles')
    else:
        path = '/ltm/virtual/~' + virtual['partition'] + '~' + virtual['name'] + '/profiles'
    return bigip.get_json(path).get('items', [])


def retrieve_virtual_servers(bigip, verbose):
    virtual_servers = bigip.get_json('/ltm/virtual').get('items', [])
    for current_virtual_server in virtual_servers:
        if verbose:
            print("Found virtual server " + current_virtual_server['name'])
        # Fetch each virtual's profiles once here so the console and CSV reports
        # can both read them without a second round of REST calls.
        current_virtual_server['profiles'] = fetch_virtual_profiles(bigip, current_virtual_server)
    return virtual_servers


def print_ssl_profile(profile_name, context, cipher_dict, fullcipherflag):
    print(' -> Profile found: ' + profile_name + ' (Context: ' + context + ')')
    print('   -> Cipher string: ' + cipher_dict[profile_name]['cipherstring'])
    print('   -> Parent profile: ' + cipher_dict[profile_name]['parent'])
    if fullcipherflag:
        print('   -> Complete cipher list: \n' + cipher_dict[profile_name]['cipherlist'])


def create_ssl_report(fullcipherflag, CLIENT_CIPHER_DICT, SERVER_CIPHER_DICT, LTM_VIRTUAL_LIST, verbose):
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


def create_ssl_csv(csvfile, CLIENT_CIPHER_DICT, SERVER_CIPHER_DICT, LTM_VIRTUAL_LIST):
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


def main():
    BIG_IP = get_args()
    if BIG_IP['verify'] is False:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    bigip = BigIp(BIG_IP['host'], BIG_IP['username'], BIG_IP['password'], BIG_IP['verify'], BIG_IP['timeout'])
    client_ssl_profile_list = retrieve_ssl_profiles(bigip, 'client-ssl', 'Client', '--clientciphers',
                                                    BIG_IP['fullciphers'], BIG_IP['verbose'])
    server_ssl_profile_list = retrieve_ssl_profiles(bigip, 'server-ssl', 'Server', '--serverciphers',
                                                    BIG_IP['fullciphers'], BIG_IP['verbose'])
    virtual_server_list = retrieve_virtual_servers(bigip, BIG_IP['verbose'])
    create_ssl_report(BIG_IP['fullciphers'], client_ssl_profile_list, server_ssl_profile_list,
                      virtual_server_list, BIG_IP['verbose'])
    if BIG_IP['csv']:
        create_ssl_csv(BIG_IP['csv'], client_ssl_profile_list, server_ssl_profile_list, virtual_server_list)
    print('\nReport complete.')


if __name__ == "__main__":
    main()
