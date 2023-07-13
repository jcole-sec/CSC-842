import requests
from IPy import IP
import json
from rich.progress import track
from rich import print

def threatfox_ip_lookup(ip :str):
    """ Performs ThreatFox Lookup for a supplied IP address """
    url = 'https://threatfox-api.abuse.ch/api/v1/'
    data = {}
    data["query"] = "search_ioc"
    data["search_term"] = ip
    r = requests.post(url, data=json.dumps(data))
    if r.status_code == 200:
        return r.json()
    else:
        print(f'[*] Request Error: {r.status_code}')
        return '-'


def threatfox_hash_lookup(phash :str):
    """ Performs ThreatFox Lookup for a supplied Hash (MD5 or SHA256) """
    url = 'https://threatfox-api.abuse.ch/api/v1/'
    data = {}
    data["query"] = "search_hash"
    data["hash"] = phash
    r = requests.post(url, data=json.dumps(data))
    if r.status_code == 200:
        return r.json()
    else:
        print(f'[*] Request Error: {r.status_code}')
        return '-'


def ripe_lookup(ip :str):
    """ Performs a RIPE Stat API lookup against a supplied IP and returns a response dictionary """
    url = f'https://stat.ripe.net/data/whois/data.json?resource={ip}'
    r = requests.get(url)
    
    ip_data = {}
    #ip_data['ip'] = ip

    if r.status_code == 200:
        for record in r.json()['data']['records']:
            for item in record:
                ip_data[item['key']] = item['value']
        return ip_data
    else:
        print(f'[*] Request Error: {r.status_code}')


def run_cti_lookups(process_list :list):
    cti_enriched_list = []

    print('[*] Cyber Threat Intelligence enumeration initiated')
    for pdata in track(process_list):
        
        # SHA256 Hash Processing
        if len(pdata['phash']) > 1:
            tfox_hash_data = threatfox_hash_lookup(pdata['phash'])

            # set hash confidence score
            try:
                pdata['hash_cti_confidence'] =  tfox_hash_data['data'][0]['confidence_level']
            except:
                pdata['hash_cti_confidence'] = '-'
            
            # set hash threat type
            try:
                pdata['hash_cti_threat_type'] = tfox_hash_data['data'][0]['threat_type']
            except:
                pdata['hash_cti_threat_type'] = '-'
            
            # set hash malware name
            try:
                pdata['hash_cti_malware'] = tfox_hash_data['data'][0]['malware_printable']
            except:
                pdata['hash_cti_malware'] = '-'
        else:
            pdata['hash_cti_confidence'] = '-'
            pdata['hash_cti_threat_type'] = '-'
            pdata['hash_cti_malware'] = '-'
        
        # Remote IP Processing

        # Check if remote IP address exists and is public
        if pdata['rip'] != '-' and IP(pdata['rip']).iptype() == 'PUBLIC':

            # RIPE data lookup for Remote IP
            ripe_data = ripe_lookup(pdata['rip'])

            # RIPE CIDR enumeration
            try:
                pdata['rip_cidr'] = ripe_data['CIDR']
            except KeyError:
                pdata['rip_cidr'] = ripe_data['inetnum']
            except:
                pdata['rip_cidr'] = '-'
            
            # RIPE Network Name enumeration
            try:
                pdata['rip_netname'] = ripe_data['netname']
            except KeyError:
                pdata['rip_netname'] = ripe_data['NetName']
            except:
                pdata['rip_netname'] = '-'
            
            # RIPE Country enumeration
            try:
                pdata['rip_country'] = ripe_data['country']
            except KeyError:
                pdata['rip_country'] = ripe_data['Country']
            except:
                pdata['rip_country'] = '-'

            tfox_ip_data = threatfox_ip_lookup(pdata['rip'])

            # set remote IP confidence score
            try:
                pdata['rip_cti_confidence'] =  tfox_ip_data['data'][0]['confidence_level']
            except:
                pdata['rip_cti_confidence'] = '-'
            
            # set remote IP threat type
            try:
                pdata['rip_cti_threat_type'] = tfox_ip_data['data'][0]['threat_type']
            except:
                pdata['rip_cti_threat_type'] = '-'
            
            # set remote IP malware name
            try:
                malware_name = tfox_ip_data['data'][0]['malware_printable']
                pdata['rip_cti_malware'] = malware_name
                if len(malware_name) > 1:
                    print(f'[bold red][!] WARNING: Process {pdata["pname"]} hash was detected as malware: {malware_name}[/bold red]')

            except:
                pdata['rip_cti_malware'] = '-'
        
        else:
            pdata['rip_cidr'] = '-'
            pdata['rip_netname'] = '-'
            pdata['rip_country'] = '-'
            pdata['rip_cti_confidence'] = '-'
            pdata['rip_cti_threat_type'] = '-'
            pdata['rip_cti_malware'] = '-'
        
        cti_enriched_list.append(pdata)
    
    print('[*] Cyber Threat Intelligence enumeration complete\n')

    return cti_enriched_list

                
