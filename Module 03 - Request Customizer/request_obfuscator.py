import subprocess
#from subprocess import Popen, PIPE
import os
import requests
from fake_useragent import UserAgent


def parseArguments():
    
    parser = argparse.ArgumentParser(
        description='pcap_analyzer.py is a script that will:\n\
    * recurse through a provided directory to identify pcaps,\n\
    * extract unique public IPs,\n\
    * and provide security intelligence via a user-friendly graph output.',
        formatter_class=RawTextHelpFormatter,
        epilog='Thanks for trying pcap_analyzer!\n ',
    )

    parser.add_argument(
        '-d', '--directory', 
        help='The directory path to scan for pcap files.\nDefault value: [current directory]', 
        type=str, 
        default=os.getcwd()
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