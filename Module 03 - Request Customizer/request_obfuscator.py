#!/usr/bin/python3

from argparse import ArgumentParser, BooleanOptionalAction, RawTextHelpFormatter
import subprocess
import os
from pathlib import Path
import random
from time import strftime
import json

import requests
from fake_useragent import UserAgent
from rich import print


def parseArguments():
    
    parser = ArgumentParser(
        description='request_obfuscator.py attempts to obfuscate a web request to a specified URL or URL list.\n\
\nthe script will:\n\
    * connect a VPN using the specified configuration,\n\
    * execute the web request using a modified header,\n\
    * exit the VPN session.\n',
        formatter_class=RawTextHelpFormatter,
        epilog='Reference source at https://github.com/jcole-sec/CSC-842/tree/main/Module%2003%20-%20Request%20Customizer\n ',
    )

    url_input = parser.add_mutually_exclusive_group(required=True)

    url_input.add_argument(
        '-u', '--url',
        help='specify a URL to request.\n\
[ note: either --url or --file is required] \n\
    ', 
        type=str
    )

    url_input.add_argument(
        '-f', '--file',
        help='specify a file containing a list of URLs.\n\
the file should contain a URL per line.\n\
[ note: either --url or --file is required ]\n\
    ', 
        type=str
    )

    parser.add_argument(
        '-c', '--config',  
        help='specify an OpenVPN configuration file.\n\
if option is not provided, will default to --directory option and default\n\
    ', 
        type=str
    )

    parser.add_argument(
        '--d', '--directory', 
        help='the directory path to check for OpenVPN configuration files.\n\
default value: [./openvpn]\n\
    ', 
        type=str, 
        default='./openvpn'
    )

    parser.add_argument(
        '--debug', 
        help='Enable debugging output to the console.\n', 
        action=BooleanOptionalAction, 
        default=False
    )    
    #parser.set_defaults(text=False)

    return parser.parse_args()


def header_randomizer():
    """ Returns random useragent from fake_useragent library """
    headers = {}
    headers['User-Agent'] = UserAgent().random 
    return headers


def openvpn_connection(openvpn_conf):
    """ Returns an OpenVPN process handle using the input configuration """
    PIPE = subprocess.PIPE
    args = [
        'sudo',
        '-b',
        '/usr/sbin/openvpn',
        '--auth-nocache',
        '--config',
        openvpn_conf
    ]
    try:
        return subprocess.Popen(args, stdout=PIPE, stderr=PIPE)
    except Exception as e:
        print(e)


def get_random_configuration(dir):
    """ Generates a list from conf files within a directory and returns a random conf """
    config_list = []
    for r,d,f in os.walk(dir):
        for filename in f:
            if filename.endswith('ovpn'):
                config_list.append(os.path.abspath(os.path.join(r, filename)))
    return random.choice(config_list)


def get_network_detail():
    """ Returns IP and Country detail from myip.com """
    r = requests.get('https://api.myip.com').json()
    ip = r['ip']
    country = r['country']
    return ip, country

def process_request(url, debug):
    """ Executes a request for a given url using a randomized user-agent and prints the details """
    
    request_log = {}
    print('[dim cyan][+] Request Detail:[/dim cyan]')    

    print(f'[-] Request URL: {url}')
    request_log['url'] = url

    header = header_randomizer()
    print(f'[-] User-Agent: {header["User-Agent"]}')
    request_log['user_agent'] = header["User-Agent"]

    try:
        r = requests.get(url, headers = header)
        print(f'[-] Request Status: {r.status_code}')
        request_log['status_code'] = r.status_code

        if r.status_code == 200:
            
            request_log['response_header'] = {}
            #request_log['response_header'] = str(r.headers)
            for k,v in r.headers.items():
             request_log['response_header'][k] = v

            if debug:
                print('[-] Request Response Header:')
                print(r.headers)
            
            try:
                if r.json():
                    print('[-] Request Response: json')
                    request_log['body'] = r.json()
                    if debug:
                        print(r.json())
                    print('')
            except:
                print('[-] Request Response: content')
                request_log['body'] = r.content.decode()
                if debug:
                    print(r.content.decode()+'\n')
                print('')
    except:
        print('[x] URL processing error encountered')
    return request_log


def write_to_log(request_log):
    """ Writes input dictionary to log file """
    datetime = strftime('%Y%m%d_%H%M%S')
    log_name = f'request-obfuscator_log-{datetime}.json'
    with open(log_name, 'a') as logfile:
        logfile.write(json.dumps(request_log))


def call_logger(request_log, ip, country, debug):
    """ Combines log dictionary and provides exception handling for logger """
    try:
        request_log['vpn'] = {}
        request_log['vpn']['ip'] = ip
        request_log['vpn']['country'] = country
        write_to_log(request_log)

    except Exception as e:
        print('[x] Request logging failed')
        if debug:
            print(e)


def __main__():

    options = parseArguments()

    debug = options.debug

    if options.config:
        openvpn_conf = Path(options.config)
    else:
        conf_dir = Path(options.d).resolve()
        print(f'[*] VPN configuration directory: {conf_dir}')
        openvpn_conf = get_random_configuration(conf_dir)
    
    print(f'[*] OpenVPN config file: {openvpn_conf}')
    openvpn_handle = openvpn_connection(openvpn_conf)
    
    while True:
        output = openvpn_handle.stdout.readline()
        if output:
            if debug:
                print (output.strip().decode())
            if "Initialization Sequence Completed" in str(output):
                print('\n[dim pale_turquoise4][*] ----- VPN session connected ----- [/dim pale_turquoise4]\n') # ref rich colors: https://rich.readthedocs.io/en/latest/appendix/colors.html?highlight=colors#standard-colors
        
                print('[dim pale_turquoise4][+] Connection Detail:[/dim pale_turquoise4]')    
                ip, country = get_network_detail()
                print(f'[dim pale_turquoise4][-] VPN IP: {ip}[/dim pale_turquoise4]')
                print(f'[dim pale_turquoise4][-] VPN Country: {country}[/dim pale_turquoise4]\n')

                if options.url:
                    url = options.url
                    request_log = process_request(url, debug)
                    call_logger(request_log, ip, country, debug)
                    print('')
                                
                elif options.file:
                    url_list = Path(options.file).resolve() # get full path
                    print(f'[*] Loading URLs from supplied list: {url_list}\n')
                    with open(str(url_list)) as urls:
                        urls = urls.read().splitlines()
                        for url in urls:
                            request_log = process_request(url, debug)
                            call_logger(request_log, ip, country, debug)
                            print('')


                try:
                    #openvpn_handle.kill()         #  --> sends SIGKILL, doesn't kill openvpn connection
                    #openvpn_handle.terminate()    # s--> ends SIGTERM; note: it will not work with shell=True; doesn't kill openvpn connection
                    #os.killpg(os.getpgid(openvpn_handle.pid), signal.SIGTERM) \
                    # found here, not successful: https://stackoverflow.com/questions/4789837/how-to-terminate-a-python-subprocess-launched-with-shell-true/4791612#4791612
                   
                    os.system('sudo killall openvpn')
                    print('[dim pale_turquoise4][*] ----- VPN session closed ----- [/dim pale_turquoise4]\n')
                    break
                except Exception as e:
                    print(e)
                    break


__main__()