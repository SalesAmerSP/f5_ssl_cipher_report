#!/usr/bin/env python3

import requests
import json
import urllib3
import argparse
import sys
import csv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_args():
    cmdargs = argparse.ArgumentParser()
    cmdargs.add_argument('--host', action='store', required=True, type=str,
                         help='ip of BIG-IP REST interface, typically the mgmt ip')
    cmdargs.add_argument('--username', action='store', required=True, type=str, help='username for REST authentication')
    cmdargs.add_argument('--password', action='store', required=True, type=str, help='password for REST authentication')
    cmdargs.add_argument('--csv', action='store', required=False, type=str, help='CSV filename for report (optional)')
    cmdargs.add_argument('--fullciphers', action='store_true', required=False, help='flag for displaying list of all ciphers in profile')
    cmdargs.add_argument('--verbose', action='store_true', required=False, help='prints additional information during execution')
    parsed_args = cmdargs.parse_args()
    BIG_IP = {'host': parsed_args.host, 'username': parsed_args.username, 'password': parsed_args.password,
              'fullciphers': parsed_args.fullciphers, 'verbose': parsed_args.verbose, 'csv': parsed_args.csv}
    return BIG_IP

def abort_script(reason):
    print('*** Aborting script execution! ***')
    if len(str(reason)) > 0:
        print('ERROR: ' + str(reason))
    sys.exit(2)

def icontrol_get(host, username, password, path):
    apiCall = requests.session()
    apiCall.headers.update({'Content-type': 'application/json'})
    apiCall.auth = (username, password)
    apiUri = 'https://' + host + '/mgmt/tm' + path
    try:
        apiResponse = apiCall.get(apiUri, verify=False)
    except requests.exceptions.RequestException as e:
        abort_script(str(e))
        return
    return apiResponse.text

def retrieve_clientssl_profiles(host, username, password, fullciphers, verbose):
    api_response = icontrol_get(host, username, password, '/ltm/profile/client-ssl')
    api_response_dict = json.loads(api_response)
    clientssl_profile_list = api_response_dict['items']
    CLIENTSSL_PROFILE_CIPHERS = {}
    for current_clientssl_profile in clientssl_profile_list:
        current_clientssl_profile_name = str(current_clientssl_profile['name'])
        current_clientssl_profile_cipherstring = str(current_clientssl_profile['ciphers'])
        if 'defaultsFrom' in current_clientssl_profile.keys():
            current_clientssl_profile_parent = str(current_clientssl_profile['defaultsFrom'])
        else:
            current_clientssl_profile_parent = 'none'
        if verbose:
            print('Found Client SSL profile: ' + current_clientssl_profile_name)
            print(' -> Ciphers: ' + current_clientssl_profile_cipherstring)
        CLIENTSSL_PROFILE_CIPHERS[current_clientssl_profile_name] = {}
        CLIENTSSL_PROFILE_CIPHERS[current_clientssl_profile_name]['name'] = current_clientssl_profile_name
        CLIENTSSL_PROFILE_CIPHERS[current_clientssl_profile_name]['cipherstring'] = current_clientssl_profile_cipherstring
        CLIENTSSL_PROFILE_CIPHERS[current_clientssl_profile_name]['parent'] = current_clientssl_profile_parent
        if fullciphers:
            if verbose:
                print(' -> Retreiving complete cipher list')
            api_payload = {"command": "run", "utilCmdArgs": "-c 'tmm --serverciphers " + current_clientssl_profile_cipherstring + "'"}
            api_response = icontrol_post(host, username, password, '/util/bash', api_payload)
            api_response_dict = json.loads(api_response)
            current_clientssl_profile_cipherlist = api_response_dict['commandResult']
            CLIENTSSL_PROFILE_CIPHERS[current_clientssl_profile_name]['cipherlist'] = current_clientssl_profile_cipherlist
    return CLIENTSSL_PROFILE_CIPHERS

def retrieve_serverssl_profiles(host, username, password, fullciphers, verbose):
    api_response = icontrol_get(host, username, password, '/ltm/profile/server-ssl')
    api_response_dict = json.loads(api_response)
    serverssl_profile_list = api_response_dict['items']
    SERVERSSL_PROFILE_CIPHERS = {}
    for current_serverssl_profile in serverssl_profile_list:
        current_serverssl_profile_name = str(current_serverssl_profile['name'])
        current_serverssl_profile_cipherstring = str(current_serverssl_profile['ciphers'])
        if 'defaultsFrom' in current_serverssl_profile.keys():
            current_serverssl_profile_parent = str(current_serverssl_profile['defaultsFrom'])
        else:
            current_serverssl_profile_parent = 'none'
        if verbose:
            print('Found Server SSL profile: ' + current_serverssl_profile_name)
            print(' -> Ciphers: ' + current_serverssl_profile_cipherstring)
        SERVERSSL_PROFILE_CIPHERS[current_serverssl_profile_name] = {}
        SERVERSSL_PROFILE_CIPHERS[current_serverssl_profile_name]['name'] = current_serverssl_profile_name
        SERVERSSL_PROFILE_CIPHERS[current_serverssl_profile_name]['cipherstring'] = current_serverssl_profile_cipherstring
        SERVERSSL_PROFILE_CIPHERS[current_serverssl_profile_name]['parent'] = current_serverssl_profile_parent
        if fullciphers:
            if verbose:
                print(' -> Retreiving complete cipher list')
            api_payload = {"command": "run", "utilCmdArgs": "-c 'tmm --serverciphers " + current_serverssl_profile_cipherstring + "'"}
            api_response = icontrol_post(host, username, password, '/util/bash', api_payload)
            api_response_dict = json.loads(api_response)
            current_serverssl_profile_cipherlist = api_response_dict['commandResult']
            SERVERSSL_PROFILE_CIPHERS[current_serverssl_profile_name]['cipherlist'] = current_serverssl_profile_cipherlist
    return SERVERSSL_PROFILE_CIPHERS

def retrieve_virtual_servers(host, username, password, verbose):
    api_response = icontrol_get(host, username, password, '/ltm/virtual')
    api_response_dict = json.loads(api_response)
    LTM_VIRTUAL_LIST = api_response_dict['items']
    if verbose:
        for current_virtual_server in LTM_VIRTUAL_LIST:
            print("Found virtual server " + current_virtual_server['name'])
    return LTM_VIRTUAL_LIST

def create_ssl_report(host, username, password, fullcipherflag, CLIENT_CIPHER_DICT, SERVER_CIPHER_DICT, LTM_VIRTUAL_LIST, verbose):
    for current_virtual in LTM_VIRTUAL_LIST:
        print('*********************\nVirtual server: ' + current_virtual['fullPath'] + ' (' + current_virtual['destination'] + ')')
        if 'subPath' in current_virtual.keys():
            api_response = icontrol_get(host, username, password, '/ltm/virtual/~' + current_virtual['partition'] + '~' + current_virtual['subPath'] + '~' + current_virtual['name'] + '/profiles')
        else:
            api_response = icontrol_get(host, username, password, '/ltm/virtual/~' + current_virtual['partition'] + '~' + current_virtual['name'] + '/profiles')
        api_response_dict = json.loads(api_response)
        current_virtual_profiles = api_response_dict['items']
        for current_virtual_profile in current_virtual_profiles:
            if current_virtual_profile['context'] == 'clientside' and current_virtual_profile['name'] in CLIENT_CIPHER_DICT:
                print(' -> Profile found: ' + current_virtual_profile['name'] + ' (Context: ' + current_virtual_profile['context'] + ')')
                print('   -> Cipher string: ' + CLIENT_CIPHER_DICT[current_virtual_profile['name']]['cipherstring'])
                print('   -> Parent profile: ' + CLIENT_CIPHER_DICT[current_virtual_profile['name']]['parent'])
                if fullcipherflag:
                    print('   -> Complete cipher list: \n' + CLIENT_CIPHER_DICT[current_virtual_profile['name']]['cipherlist'])
            elif current_virtual_profile['context'] == 'serverside' and current_virtual_profile['name'] in SERVER_CIPHER_DICT:
                print(' -> Profile found: ' + current_virtual_profile['name'] + ' (Context: ' + current_virtual_profile['context'] + ')')
                print('   -> Cipher string: ' + SERVER_CIPHER_DICT[current_virtual_profile['name']]['cipherstring'])
                print('   -> Parent profile: ' + SERVER_CIPHER_DICT[current_virtual_profile['name']]['parent'])
                if fullcipherflag:
                    print('   -> Complete cipher list: \n' + SERVER_CIPHER_DICT[current_virtual_profile['name']]['cipherlist'])
            else:
                if verbose:
                    print('   -> Non-SSL Profile')

def create_ssl_csv(host, username, password, csvfile, CLIENT_CIPHER_DICT, SERVER_CIPHER_DICT, LTM_VIRTUAL_LIST):
    with open(csvfile, mode="w", newline='') as outputcsv:
        report_writer = csv.writer(outputcsv, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        report_writer.writerow(['Virtual Server Path','Virtual Server Destination', 'CLIENT SSL PROFILE','PARENT CLIENT SSL PROFILE', 'SERVER SSL PROFILE','PARENT SERVER SSL PROFILE'])
        for current_virtual in LTM_VIRTUAL_LIST:
            current_client_profile = 'none'
            current_client_parent_profile = 'none'
            current_server_profile = 'none'
            current_server_parent_profile = 'none'
            if 'subPath' in current_virtual.keys():
                api_response = icontrol_get(host, username, password, '/ltm/virtual/~' + current_virtual['partition'] + '~' + current_virtual['subPath'] + '~' + current_virtual['name'] + '/profiles')
            else:
                api_response = icontrol_get(host, username, password, '/ltm/virtual/~' + current_virtual['partition'] + '~' + current_virtual['name'] + '/profiles')
            api_response_dict = json.loads(api_response)
            current_virtual_profiles = api_response_dict['items']
            for current_virtual_profile in current_virtual_profiles:
                if current_virtual_profile['context'] == 'clientside' and current_virtual_profile['name'] in CLIENT_CIPHER_DICT:
                    current_client_profile = current_virtual_profile['name']
                    current_client_parent_profile = CLIENT_CIPHER_DICT[current_virtual_profile['name']]['parent']
                elif current_virtual_profile['context'] == 'serverside' and current_virtual_profile['name'] in SERVER_CIPHER_DICT:
                    current_server_profile = current_virtual_profile['name']
                    current_server_parent_profile = SERVER_CIPHER_DICT[current_virtual_profile['name']]['parent']
            report_writer.writerow([current_virtual['fullPath'],current_virtual['destination'],current_client_profile,current_client_parent_profile,current_server_profile,current_server_parent_profile])

if __name__ == "__main__":
    BIG_IP = get_args()
    client_ssl_profile_list = retrieve_clientssl_profiles(BIG_IP['host'], BIG_IP['username'], BIG_IP['password'], BIG_IP['fullciphers'], BIG_IP['verbose'])
    server_ssl_profile_list = retrieve_serverssl_profiles(BIG_IP['host'], BIG_IP['username'], BIG_IP['password'], BIG_IP['fullciphers'], BIG_IP['verbose'])
    virtual_server_list = retrieve_virtual_servers(BIG_IP['host'], BIG_IP['username'], BIG_IP['password'], BIG_IP['verbose'])
    create_ssl_report(BIG_IP['host'], BIG_IP['username'], BIG_IP['password'], BIG_IP['fullciphers'], client_ssl_profile_list,server_ssl_profile_list,virtual_server_list, BIG_IP['verbose'])
    if BIG_IP['csv']:
        create_ssl_csv(BIG_IP['host'], BIG_IP['username'], BIG_IP['password'], BIG_IP['csv'], client_ssl_profile_list, server_ssl_profile_list, virtual_server_list)
    print('\nReport complete.')
