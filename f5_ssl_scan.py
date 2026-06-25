#!/usr/bin/env python3
"""Report BIG-IP LTM virtual servers and their SSL profiles/ciphers via iControl REST."""

from __future__ import annotations

import argparse
import csv
import datetime
import getpass
import json
import logging
import os
import re
import shlex
import ssl
import sys
import warnings
from dataclasses import dataclass
from typing import Any, NoReturn

import requests
import urllib3

# Runtime guard for bare `python f5_ssl_scan.py` runs that bypass pip (which
# already enforces >=3.10 via the dependencies). UP036 is suppressed because the
# check is intentional, not dead code.
if sys.version_info < (3, 10):  # noqa: UP036
    sys.exit("f5_ssl_scan.py requires Python 3.10 or newer")

__version__ = "1.3.0"

LOG = logging.getLogger('f5_ssl_scan')

# Security-support end-of-life dates for CPython releases (source: python.org).
# Python exposes no stdlib API for this, so it is maintained here.
PYTHON_EOL = {
    (3, 9): "2025-10-31",
    (3, 10): "2026-10-31",
    (3, 11): "2027-10-31",
    (3, 12): "2028-10-31",
    (3, 13): "2029-10-31",
    (3, 14): "2030-10-31",
}
# EOL date of the interpreter currently running this script (None if unknown).
PYTHON_EOL_DATE = PYTHON_EOL.get((sys.version_info.major, sys.version_info.minor))


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
    min_tls: str | None
    debug: bool


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
    cmdargs.add_argument('--debug', action='store_true', required=False,
                         help='emit detailed diagnostic logging to stderr (each REST request, '
                              'status, and timing, plus urllib3 connection logs). Credentials '
                              'are never logged.')
    cmdargs.add_argument('--ca-bundle', action='store', required=False, type=str,
                         help='path to a CA bundle used to verify the BIG-IP management certificate')
    cmdargs.add_argument('--insecure', action='store_true', required=False,
                         help='disable TLS certificate verification of the BIG-IP management interface (not recommended)')
    cmdargs.add_argument('--timeout', action='store', required=False, type=float, default=30,
                         help='per-request timeout in seconds (default: 30)')
    cmdargs.add_argument('--min-tls', action='store', required=False,
                         choices=['1.0', '1.1', '1.2', '1.3'],
                         help='minimum TLS version for connecting to the BIG-IP management '
                              'interface. Lower it (e.g. 1.0) to reach legacy TMOS whose httpd '
                              'predates TLS 1.2 (such as 13.1), which otherwise closes the '
                              'connection mid-handshake. Values below 1.2 are insecure and '
                              'intended only for old management interfaces.')
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
    if parsed_args.min_tls in ('1.0', '1.1'):
        print('WARNING: --min-tls ' + parsed_args.min_tls + ' permits legacy TLS '
              + parsed_args.min_tls + '; use only to reach old management interfaces.',
              file=sys.stderr)
    return Config(host=host, username=username, password=password,
                  fullciphers=parsed_args.fullciphers, verbose=parsed_args.verbose,
                  csv=parsed_args.csv, verify=verify, timeout=parsed_args.timeout,
                  min_tls=parsed_args.min_tls, debug=parsed_args.debug)


def configure_logging(debug: bool) -> None:
    """Enable detailed stderr logging when --debug is set.

    urllib3's logger is surfaced because it records each request line and status
    *without* the Authorization header. http.client debug is deliberately NOT
    enabled: it would print the basic-auth credentials to the log.
    """
    if not debug:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s'))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    logging.getLogger('urllib3').setLevel(logging.DEBUG)


def abort_script(reason: object) -> NoReturn:
    """Print an error and exit with status 2."""
    print('*** Aborting script execution! ***')
    if len(str(reason)) > 0:
        print('ERROR: ' + str(reason))
    sys.exit(2)


def build_tls_context(min_tls: str, verify: bool | str) -> ssl.SSLContext:
    """Build an SSLContext that allows a lower minimum TLS version than the default.

    The cert-verification posture mirrors `verify` so it matches normal requests
    behavior. For TLS < 1.2 the OpenSSL security level is dropped to 0 as well,
    because modern OpenSSL otherwise rejects the legacy ciphers/short keys that
    old TMOS management httpd presents.
    """
    ctx = ssl.create_default_context()
    with warnings.catch_warnings():
        # ssl.TLSVersion.TLSv1/TLSv1_1 are deprecated; the user has explicitly
        # opted into legacy TLS and is already warned, so silence the redundant noise.
        warnings.simplefilter('ignore', DeprecationWarning)
        ctx.minimum_version = {
            '1.0': ssl.TLSVersion.TLSv1,
            '1.1': ssl.TLSVersion.TLSv1_1,
            '1.2': ssl.TLSVersion.TLSv1_2,
            '1.3': ssl.TLSVersion.TLSv1_3,
        }[min_tls]
    if min_tls in ('1.0', '1.1'):
        ctx.set_ciphers('DEFAULT@SECLEVEL=0')
    if verify is False:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):
        ctx.load_verify_locations(verify)
    return ctx


class _TLSAdapter(requests.adapters.HTTPAdapter):
    """HTTPAdapter that pins a custom ssl.SSLContext (used for --min-tls)."""

    def __init__(self, ssl_context: ssl.SSLContext, **kwargs: Any) -> None:
        self._ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        kwargs['ssl_context'] = self._ssl_context
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args: Any, **kwargs: Any) -> Any:
        kwargs['ssl_context'] = self._ssl_context
        return super().proxy_manager_for(*args, **kwargs)


class BigIp:
    """Thin iControl REST client: one authenticated, reused session per BIG-IP."""

    def __init__(self, host: str, username: str, password: str,
                 verify: bool | str, timeout: float = 30,
                 min_tls: str | None = None) -> None:
        self.host = host
        self.base_uri = 'https://' + host + '/mgmt/tm'
        self.verify = verify
        self.timeout = timeout
        if verify is False:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.session = requests.session()
        self.session.headers.update({'Content-type': 'application/json'})
        self.session.auth = (username, password)
        if min_tls is not None:
            self.session.mount('https://', _TLSAdapter(build_tls_context(min_tls, verify)))
        LOG.debug('BigIp client for %s (verify=%s, timeout=%ss, min_tls=%s)',
                  host, verify, timeout, min_tls or 'default')

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        """Issue a request relative to the BIG-IP /mgmt/tm base; abort on any error."""
        LOG.debug('%s %s', method, self.base_uri + path)
        try:
            response = self.session.request(method, self.base_uri + path, verify=self.verify,
                                            timeout=self.timeout, **kwargs)
            response.raise_for_status()
            LOG.debug('-> HTTP %s (%d bytes, %.0f ms)', response.status_code,
                      len(response.content), response.elapsed.total_seconds() * 1000)
        except requests.exceptions.SSLError as e:
            abort_script(str(e) + '\nThe TLS handshake to the management interface failed. '
                         'This usually means either (1) this address is a data-plane virtual '
                         'server, not the management interface -- re-target the BIG-IP management '
                         'IP; or (2) a legacy device (e.g. TMOS 13.x) whose httpd predates TLS 1.2 '
                         '-- retry with --min-tls 1.0. Diagnose with: '
                         'openssl s_client -connect ' + self.host + ':443')
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
            LOG.debug('expanding ciphers for %s SSL profile %s via tmm %s', label, name, tmm_flag)
            api_payload = {"command": "run",
                           "utilCmdArgs": "-c " + shlex.quote("tmm " + tmm_flag + " " + cipherstring)}
            entry['cipherlist'] = bigip.post_json('/util/bash', api_payload)['commandResult']
        profiles[name] = entry
    LOG.debug('retrieved %d %s SSL profile(s)', len(profiles), label)
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
    LOG.debug('retrieved %d virtual server(s)', len(virtual_servers))
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


# A tmm cipher row looks like:  " 0: 49199  ECDHE-RSA-AES128-GCM-SHA256  128  TLS1.2  ..."
# i.e. <index>:  <id>  <SUITE>  <BITS>  <PROT>  ...  We capture SUITE and PROT.
_CIPHER_ROW = re.compile(r'^\s*\d+:\s+\d+\s+(\S+)\s+\d+\s+(\S+)')


def parse_cipher_suites(rawlist: str) -> str:
    """Reduce raw `tmm --clientciphers`/`--serverciphers` output to 'SUITE (PROT)' entries.

    The index/ID/BITS/MAC/KEYX columns are dropped because they are noise for
    cross-version comparison and their positions shift between TMOS releases.
    PROT is kept because protocol coverage is exactly what tends to change on an
    upgrade. If nothing parses (unexpected tmm format), the raw text is returned
    so data is never silently lost.

    Entries are joined with '; ' (never a newline) so the whole list stays on a
    single line within one CSV cell — embedded newlines would otherwise spread a
    single profile's ciphers across many visual rows in spreadsheets.
    """
    suites = [m.group(1) + ' (' + m.group(2) + ')'
              for line in rawlist.splitlines()
              if (m := _CIPHER_ROW.match(line))]
    if suites:
        return '; '.join(suites)
    # Fallback: unexpected tmm format — keep the raw text but collapse newlines
    # (and any whitespace runs they create) so it remains a single-line cell.
    return ' '.join(rawlist.split())


def cipher_csv_path(csvfile: str) -> str:
    """Derive the companion cipher-list CSV path (report.csv -> report_ciphers.csv)."""
    root, ext = os.path.splitext(csvfile)
    return root + '_ciphers' + (ext or '.csv')


def create_cipher_csv(csvfile: str, CLIENT_CIPHER_DICT: dict[str, dict[str, str]],
                      SERVER_CIPHER_DICT: dict[str, dict[str, str]]) -> str:
    """Write one row per SSL profile with its expanded cipher list, for version diffing.

    Keyed by profile (not virtual server) so a profile shared by many virtuals is
    written exactly once, keeping a TMOS-version-to-version diff small and readable.
    Returns the path written.
    """
    path = cipher_csv_path(csvfile)
    try:
        outputcsv = open(path, mode="w", newline='')
    except OSError as e:
        abort_script(str(e))
    with outputcsv:
        report_writer = csv.writer(outputcsv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        report_writer.writerow(['SSL PROFILE', 'CONTEXT', 'PARENT PROFILE',
                                'CIPHER STRING', 'CIPHER LIST'])
        for context, cipher_dict in (('Client', CLIENT_CIPHER_DICT), ('Server', SERVER_CIPHER_DICT)):
            for name, entry in cipher_dict.items():
                report_writer.writerow([name, context, entry['parent'], entry['cipherstring'],
                                        parse_cipher_suites(entry.get('cipherlist', ''))])
    return path


def warn_if_python_eol() -> None:
    """Warn on stderr if the running interpreter's security support has ended."""
    if PYTHON_EOL_DATE is not None and datetime.date.today() > datetime.date.fromisoformat(PYTHON_EOL_DATE):
        print('WARNING: Python ' + str(sys.version_info.major) + '.' + str(sys.version_info.minor)
              + ' reached end-of-life on ' + PYTHON_EOL_DATE + ' and no longer receives security '
              'updates; upgrade to a supported release.', file=sys.stderr)


def main() -> None:
    """Entry point: gather profiles and virtuals, then print the report and optional CSV."""
    warn_if_python_eol()
    cfg = get_args()
    configure_logging(cfg.debug)
    LOG.debug('f5_ssl_scan %s starting against %s as %s', __version__, cfg.host, cfg.username)
    bigip = BigIp(cfg.host, cfg.username, cfg.password, cfg.verify, cfg.timeout, cfg.min_tls)
    client_ssl_profiles = retrieve_ssl_profiles(
        bigip, 'client-ssl', 'Client', '--clientciphers', cfg.fullciphers, cfg.verbose)
    server_ssl_profiles = retrieve_ssl_profiles(
        bigip, 'server-ssl', 'Server', '--serverciphers', cfg.fullciphers, cfg.verbose)
    virtual_server_list = retrieve_virtual_servers(bigip, cfg.verbose)
    create_ssl_report(cfg.fullciphers, client_ssl_profiles, server_ssl_profiles,
                      virtual_server_list, cfg.verbose)
    if cfg.csv:
        create_ssl_csv(cfg.csv, client_ssl_profiles, server_ssl_profiles, virtual_server_list)
        if cfg.fullciphers:
            cipher_csv = create_cipher_csv(cfg.csv, client_ssl_profiles, server_ssl_profiles)
            print('Wrote per-profile cipher list to ' + cipher_csv)
    LOG.debug('done')
    print('\nReport complete.')


if __name__ == "__main__":
    main()
