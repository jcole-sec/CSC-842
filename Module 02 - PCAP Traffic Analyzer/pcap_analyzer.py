import requests
import json
from scapy.all import *
from IPy import *       # https://github.com/autocracy/python-ipy/
#import rich
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich import print as rprint


def get_pcaps(srcdir):
    """ Returns list of pcap files recursively identified from supplied directory """
    pcap_list = []
    for r, d, f in os.walk(srcdir):
        for each in f:
            if each.endswith('pcap'):
                srcfile = os.path.join(r, each)
                pcap_list.append(srcfile)
    return pcap_list


def get_ips_from_pcap(pcap):
    """ Returns a list of unique IPs from pcap packets """
    packets = rdpcap(pcap)
    ip_list = set([])
    for packet in packets:
        dst_ip = packet.sprintf("%IP.dst%")
        ip_list.add(dst_ip)
        src_ip = packet.sprintf("%IP.src%")
        ip_list.add(src_ip)
    return ip_list

def get_public_ips(ip_list):
    """ Returns a list of public ips (e.g., non-RFC1918, loopback, linklocal, ...) from a supplied ip list """
    public_ips = []
    for ip in ip_list:
        try:
            ip_type = IP(ip).iptype()
            if ip_type == 'PUBLIC':
                public_ips.append(ip)
        except:
            pass
    return public_ips


def threatfox_lookup(ip):
    """ Performs ThreatFox IP Lookup for a supplied IP address """
    url = 'https://threatfox-api.abuse.ch/api/v1/'
    data = {}
    data["query"] = "search_ioc"
    data["search_term"] = ip
    r = requests.post(url, data=json.dumps(data))
    if r.status_code == 200:
        return r.json()
    else:
        print(f'[*] Request Error: {r.status_code}')


def ripe_lookup(ip):
    """ Performs a RIPE Stat API lookup against a supplied IP and returns a response dictionary """
    url = f'https://stat.ripe.net/data/whois/data.json?resource={ip}'
    r = requests.get(url)
    ip_data = {}
    ip_data['ip'] = ip
    for record in r.json()['data']['records']:
        for item in record:
            ip_data[item['key']] = item['value']
    if r.status_code == 200:
        return ip_data
    else:
        print(f'[*] Request Error: {r.status_code}')


def greynoise_lookup(ip):
    url = f'https://api.greynoise.io/v3/community/{ip}' # https://docs.greynoise.io/reference/get_v3-community-ip
    headers = {}
    headers['accept'] = 'application/json'
    headers['key'] = gn_key
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        return r
    elif r.status_code == 404:
        return  r
    else:
        print(f'[*] Request Error: {r.status_code}')


def __main__():

    pcaps = get_pcaps('samples')

    rprint(pcaps)

    for pcap in pcaps:
        print(f'\n[*] Processing PCAP: {pcap}\n')
    
        ip_list = get_ips_from_pcap(pcap)
        public_ips = get_public_ips(ip_list)
    
        table = Table(title=f'Public IPs from pcap: {pcap}')
        table.add_column("IP", style="cyan", no_wrap=True)
        table.add_column("Net Range", style="dim cyan")
        table.add_column("Net Name", style="dim cyan")
        table.add_column("Country", style="dim cyan")
        table.add_column("Mal Score", style="red")
        table.add_column("Mal Type", style="red")
        table.add_column("Mal Alias", style="red")
        #table.add_column("Status", justify="right", style="green")
        for ip in track(public_ips):
            ripe_data = ripe_lookup(ip)
            
            ip_addr = ripe_data['ip']
            
            # CIDR enum
            try:
                cidr = ripe_data['CIDR']
            except KeyError:
                cidr = ripe_data['inetnum']
            except:
                cidr = '-'
            
            # Network Name enum
            try:
                name = ripe_data['netname']
            except KeyError:
                name = ripe_data['NetName']
            except:
                name = '-'
            
            # Country enum
            try:
                country = ripe_data['country']
            except KeyError:
                country = ripe_data['Country']
            except:
                country = '-'
            
            tf_data = threatfox_lookup(ip)
            tf_data = tf_data['data'][0]
            
            try:
                mal_score = tf_data['confidence_level']
            except:
                mal_score = '-'
            
            try:
                mal_type = tf_data['threat_type']
            except:
                mal_type = '-'
            
            try:
                mal_alias = tf_data['malware_alias']
            except:
                mal_alias = '-'
        
            
            
            table.add_row(ip_addr, cidr, name, country, str(mal_score), mal_type, mal_alias)
        console = Console()
    
        #console.print("Danger, Will Robinson!", style="blink bold red underline on white")
    
        print('')
        console.print(table)
        print('')


__main__()