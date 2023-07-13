import hashlib
from pathlib import Path
import json
import csv
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import psutil
from rich.progress import track
from IPy import IP


# vars
blank = '-'
AF_INET6 = getattr(socket, 'AF_INET6', object())

# Protocol Name translation
proto_map = {
    (AF_INET, SOCK_STREAM): 'tcp',
    (AF_INET6, SOCK_STREAM): 'tcp6',
    (AF_INET, SOCK_DGRAM): 'udp',
    (AF_INET6, SOCK_DGRAM): 'udp6',
}


def get_process_list(debug, test):

    process_list = []

    for connected_process in track(psutil.net_connections(kind='inet')): # track iteration progress (rich library visualization)
        process_list.append(get_process_attributes(connected_process, debug))
    
    if test:    
        # Add bad traffic patterns for detection logic validation
        bad_system = {"pid": "4", "proto": "udp", "lip": "192.168.132.1", "lport": "137", "lip_type": "PRIVATE", "lhost": "nlt-dlxps9-01", "rip": "-", "rport": "-", "rip_type": "-", "rhost": "-", "status": "NONE", "pname": "System", "ppid": "47", "ppid_name": "malsploit.exe", "puser": "NT AUTHORITY\\SYSTEM", "ppath": "c:\\temp\\system.exe", "pp_path": "c:\\temp\\malsploit.exe", "cmdline": "", "phash": "b325c92fa540edeb89b95dbfd4400c1cb33599c66859a87aead820e568a2ebe7"}
        process_list.append(bad_system)

        bad_rip =  {"pid": "27", "proto": "tcp", "lip": "192.168.132.1", "lport": "43568", "lip_type": "PRIVATE", "lhost": "nlt-dlxps9-01", "rip": "181.215.47.82", "rport": "80", "rip_type": "PUBLIC", "rhost": "deal-host.biz", "status": "ESTABLISHED", "pname": "dropper.exe", "ppid": 4, "ppid_name": "dropper.exe", "puser": "NT AUTHORITY\\SYSTEM", "ppath": "c:\\dropper.exe", "pp_path": "c:\\temp\\system.exe", "cmdline": "dropper.exe -c xfsdvjgr", "phash": "42923eb8f5d77854f41d7bbf846be937ab715d1bb227f4fdc8742fbd949607d6"}
        process_list.append(bad_rip)

        bad_user =  {"pid": "1427", "proto": "tcp", "lip": "::", "lport": "49674", "lip_type": "UNSPECIFIED", "lhost": "nlt-dlxps9-01", "rip": "-", "rport": "-", "rip_type": "-", "rhost": "-", "status": "-", "pname": "services.exe", "ppid": "1404", "ppid_name": "dropper.exe", "puser": "dropper.exe", "ppath": "C:\Windows\System32\services.exe", "pp_path": "C:\Windows\System32\wininit.exe", "cmdline": "C:\Windows\system32\services.exe", "phash": "c68ac230566c1e7e775bea31a232d0912542c8506391e691795bece67504aa03"}
        process_list.append(bad_user)

    return process_list


def get_process_attributes(c :psutil._common.sconn, debug :bool):
    """ Returns a dictionary containing relevant data attributes for a network-connected process """
    
    pdata = {}
    
    # Process Id (Int)
    pdata['pid'] = str(c.pid)
    
    if debug:
        print(f'[-] enumerating network process: { pdata["pid"] }')
    
    # Protocol
    pdata['proto'] = str(proto_map[(c.family, c.type)])
    
    # Local Address
    pdata['lip'] = str(c.laddr.ip)
    pdata['lport'] = str(c.laddr.port)

    # Local IP Type
    try:
        pdata['lip_type'] = IP(c.laddr.ip).iptype()
    except:
        pdata['lip_type'] = blank
    
    # Local Host Name
    try:                   
        pdata['lhost'] = socket.gethostbyaddr(c.laddr.ip)[0]
    except:
        pdata['lhost'] = blank
    
    # Remote Address
    if c.raddr:
        #raddr = "%s:%s" % (c.raddr)
        pdata['rip'] = str(c.raddr.ip)
        pdata['rport'] = str(c.raddr.port)
    else:
        pdata['rip'] = blank
        pdata['rport'] = blank
             
    # Remote IP Type
    try:
        pdata['rip_type'] = IP(c.raddr.ip).iptype()
    except:
        pdata['rip_type'] = blank

    # Remote Host
    try:
        pdata['rhost'] =  socket.gethostbyaddr(c.raddr[0])[0]
    except:
        pdata['rhost'] = blank
    
    # Status
    pdata['status'] = c.status
    
    # Process Name
    try:
        pdata['pname'] = psutil.Process(c.pid).name()
    except:
        pdata['pname'] = blank
    
    # Parent Process Id (Int)
    try:
        pdata['ppid'] = psutil.Process(c.pid).ppid()
    except:
        pdata['ppid'] = blank
    
    # Parent Process Id Name
    try:
        pdata['ppid_name'] = psutil.Process(pdata['ppid']).name()
    except:
        pdata['ppid_name'] = blank
    
    # Process User
    try:
        pdata['puser'] = psutil.Process(c.pid).username()
    except:
        pdata['puser'] = blank
    
    # Process Path
    try:
        pdata['ppath'] = psutil.Process(c.pid).exe()
    except:
        pdata['ppath'] = blank

    # Parent Process Path
    try:
        pdata['pp_path'] = psutil.Process(pdata['ppid']).exe()
    except:
        pdata['pp_path'] = blank

    # Process Command Line Parameters
    try:
        pdata['cmdline'] = ' '.join(str(each) for each in psutil.Process(c.pid).cmdline())
    except:
        pdata['cmdline'] = blank
    
    # Process SHA-256 hash
    try:
        pdata['phash'] = get_sha256(psutil.Process(c.pid).exe())
    except:
        pdata['phash'] = blank   

    # Parent Process SHA-256 hash
    try:
        pdata['phash'] = get_sha256(pdata['pp_path'])
    except:
        pdata['phash'] = blank   


    return pdata

def get_sha256(filename):
    """ Calculate the SHA-256 hash for specified file """
    
    h = hashlib.sha256()

    with open(filename,'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)
    return h.hexdigest()


def get_public_ips(ip_list :list):
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


def public_address_filter(pdata_list :list):
    """ Filters an input dictionary for inclusion of either public local or remote IP addresses """

    # list comprehension is a bit faster.. (test ~4 min)
    public_pdata_list = [pdata for pdata in pdata_list if (pdata['lip_type'] == 'PUBLIC') or (pdata['rip_type'] == 'PUBLIC')]

    return public_pdata_list


def write_json(outfile_prefix :str, pdata_list :list):
    """ Writes a process data list to a newline-delimited (ND) JSON file """

    outfilename = outfile_prefix + '.json'

    with open(outfilename, 'at') as outfile:
        for pdata in pdata_list:
            outfile.write(json.dumps(pdata) + '\n')
        
    print(f'[*] Output written to file: {str(Path(outfilename))}')


def write_tsv(outfile_prefix :str, pdata_list :list):
    """ Writes a process data list to a tab-separated values (TSV) file """

    outfilename = outfile_prefix + '.tsv'

    with open(outfilename, 'wt', newline='') as output_file:
        dw = csv.DictWriter(output_file, sorted(pdata_list[0].keys()), delimiter='\t')
        dw.writeheader()
        dw.writerows(pdata_list)
        
    print(f'[*] Output written to file: {str(Path(outfilename))}')