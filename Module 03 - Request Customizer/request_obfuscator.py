from argparse import ArgumentParser, RawTextHelpFormatter
import subprocess
#from subprocess import Popen, PIPE
import os
import requests
from fake_useragent import UserAgent


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
        type=str, 
        default=os.getcwd()
    )

    url_input.add_argument(
        '-f', '--file',
        help='specify a file containing a list of URLs.\n\
the file should contain a URL per line.\n\
[ note: either --url or --file is required ]\n\
    ', 
        type=str, 
        default=os.getcwd()
    )

    parser.add_argument(
        '-c', '--config',  
        help='specify an OpenVPN configuration file.\n\
if option is not provided, will default to --directory option and default\n\
    ', 
        type=str, 
        default=os.getcwd()
    )

    parser.add_argument(
        '--d', '--directory', 
        help='the directory path to check for OpenVPN configuration files.\n\
default value: [./openvpn]', 
        type=str, 
        default=os.path.join(os.getcwd(), './openvpn')
    )
    
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


def get_network_detail():
    """ Returns IP and Country detail from myip.com """
    r = requests.get('https://api.myip.com').json()
    ip = r['ip']
    country = r['country']
    return ip, country


# vars
url = 'https://api.myip.com'
openvpn_conf = '/home/user/code/CSC-842/Module 03 - Request Customizer/openvpn/node-is-02.protonvpn.net.udp.ovpn'


def __main__():

    args = parseArguments()

    openvpn_handle = openvpn_connection(openvpn_conf)
    
    while True:
        output = openvpn_handle.stdout.readline()
        if output:
            #print (output.strip().decode())
            if "Initialization Sequence Completed" in str(output):
                print('[+] VPN session connected')
    
                header = header_randomizer()
                print(f'[*] Header used: {header}')
                
                ip, country = get_network_detail()
                print(f'[*] Current IP: {ip}')
                print(f'[*] Current Country: {country}')
    
                #url = 'https://explore.whatismybrowser.com/useragents/parse/?analyse-my-user-agent=yes'
                #r = requests.get(url, headers = header)
                #print(r.json())
                #print(r.content.decode())
                
                try:
                    #openvpn_handle.kill()         # sends SIGKILL, doesn't kill openvpn connection
                    #openvpn_handle.terminate()    # sends SIGTERM; note: it will not work with shell=True; doesn't kill openvpn connection
                    #os.killpg(os.getpgid(openvpn_handle.pid), signal.SIGTERM) # found here: https://stackoverflow.com/questions/4789837/how-to-terminate-a-python-subprocess-launched-with-shell-true/4791612#4791612
                    os.system('sudo killall openvpn')
                    print('[+] VPN session closed')
                    break
                except Exception as e:
                    print(e)
                    break


__main__()