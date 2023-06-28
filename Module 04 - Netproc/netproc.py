 
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import time
from pathlib import Path
import hashlib
from argparse import ArgumentParser, BooleanOptionalAction, RawTextHelpFormatter

# non-standard libs
import json
import psutil
from rich import print
from rich.progress import track
from rich.console import Console
from rich.table import Table
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

def parseArguments():
    
    parser = ArgumentParser(
        description='netproc is a tool that will:\n\
    * Retrieve a list of all currently running processes\n\
    * Display and/or log process details such as status, user, path, and parent process\n\
    * Display and/or log network connection details related to each process\n\
    ',
        formatter_class=RawTextHelpFormatter,
        epilog='For support, contact https://github.com/jcole-sec.\n ',
    )


    parser.add_argument(
        '-t', '--tsv', 
        help='Enable output logging to tab-separate value (TSV) file.\nFile will be written to netproc_hostname_YYYYmmDD.HHMM.tsv\n\
    ', 
        action=BooleanOptionalAction,
        default=True
    )

    parser.add_argument(
        '-j', '--json', 
        help='Enable output logging to a new-line delimited JSON file.\nFile will be written to netproc_hostname_YYYYmmDD.HHMM.json\n\
    ', 
        action=BooleanOptionalAction,
        default=False
    )

    parser.add_argument(
        '-d', '--display', 
        help='Enable table display for process details.\n\
    ', 
        action=BooleanOptionalAction,
        default=False
    )

    parser.add_argument(
        '-p', '--public', 
        help='Filter for processes with connections to or from public IPs.\n\
    ', 
        action=BooleanOptionalAction,
        default=False
    )

    parser.add_argument(
        '--debug', 
        help='Enable additional console output for debugging purposes.\n\
    ', 
        action=BooleanOptionalAction,
        default=False
    )
    return parser.parse_args()


def get_sha256(filename):
    
    """ Calculate the SHA-256 hash for specified file """
    
    h = hashlib.sha256()

    with open(filename,'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(1024)
            h.update(chunk)
    return h.hexdigest()


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

    return pdata

def public_address_filter(pdata_list :list):
    """ Filters process data list to return processes containing public IPs """
    
    """
    # this is slow... (mean test ~10 min)
    
    public_pdata_list = []

    for pdata in pdata_list:
        if (pdata['lip_type'] == 'PUBLIC') or (pdata['rip_type'] == 'PUBLIC'):
            public_pdata_list.append(pdata)
            
    """

    # list comprehension is a bit faster.. (test ~4 min)
    public_pdata_list = [pdata for pdata in pdata_list if (pdata['lip_type'] == 'PUBLIC') or (pdata['rip_type'] == 'PUBLIC')]

    return public_pdata_list


def write_tsv(outfile_prefix :str, pdata_list :list):

    """ Writes a process data list to a tab-separated value (TSV) file """

    outfilename = outfile_prefix + '.tsv'
    with open(outfilename, 'at') as outfile:

        headers = ['Proto', 'Local IP', 'Local Host', 'Local Port', 'Remote address','Remote host', 'Remote Port','Status','PID','Process name','PPID','PPID Name','User','Path','SHA-256','Command Line']
        outfile.write('\t'.join(map(str,headers)) + '\n')

        for pdata in pdata_list:
            try:
                outfile.write(f"{pdata['proto']}\t{pdata['lip']}\t{pdata['lhost']}\t{pdata['lport']}\t{pdata['rip']}\t{pdata['rhost']}\t\
                              {pdata['rport']}\t{pdata['status']}\t{pdata['pid']}\t{pdata['pname']}\t{str(pdata['ppid'])}\t{pdata['ppid_name']}\t\
                                {pdata['puser']}\t{pdata['ppath']}\t{pdata['phash']}\t{pdata['cmdline']}\n")        
            except:
                outfile.write(f"{pdata['proto']}\t{pdata['lip']}\t{pdata['lhost']}\t{pdata['lport']}\t{pdata['rip']}\t{pdata['rhost']}\t\
                              {pdata['rport']}\t{pdata['status']}\t{pdata['pid']}\t-\t-\t-\t-\t-\t-\n")
    
    print(f'[*] Output written to file: {str(Path(outfilename))}')


def write_json(outfile_prefix :str, pdata_list :list):

    """ Writes a process data list to a newline-delimited (ND) JSON file """

    outfilename = outfile_prefix + '.json'

    with open(outfilename, 'at') as outfile:
        for pdata in pdata_list:
            outfile.write(json.dumps(pdata) + '\n')
        
    print(f'[*] Output written to file: {str(Path(outfilename))}')


def create_display_table(hostname :str, pdata_list :list):

    """ Create a table containing process data for visualization """
    
    # Sort the list based on process name key
    pdata_list.sort(key=lambda x: x['pname'])

    # Rich table configution settings   
    table = Table(title=f'Process Data for: {hostname}')
    table.add_column("Process Name", style="cyan")
    table.add_column("PID", style="dim cyan", no_wrap=True)
    table.add_column("Parent Proc", style="cyan", no_wrap=True)
    table.add_column("Loc Port", style="dim cyan", no_wrap=True)
    table.add_column("Rem Host", style="cyan", no_wrap=True)
    table.add_column("Rem IP", style="dim cyan", no_wrap=True)
    table.add_column("Rem Port", style="dim cyan", no_wrap=True)
    table.add_column("Command", style="dim cyan")
    for pdata in pdata_list:
        table.add_row(pdata['pname'], pdata['pid'],pdata['ppid_name'],pdata['lport'],pdata['rhost'],pdata['rip'],pdata['rport'],pdata['cmdline'])

    return table


def main():

    options = parseArguments()
    debug = options.debug
    
    # set output file name details
    datetime = time.strftime('%Y%m%d.%H%M')
    hostname = socket.gethostname()
    outfile_prefix = f'netproc_{hostname}_{datetime}'
       

    print('[*] Networked process enumeration initiated')

    process_list = []

    for connected_process in track(psutil.net_connections(kind='inet')): # track iteration progress (rich library visualization)
        process_list.append(get_process_attributes(connected_process, debug))

    if options.public:
        process_list = public_address_filter(process_list)

    if options.tsv:
        write_tsv(outfile_prefix, process_list)

    if options.json:
        write_json(outfile_prefix, process_list)
   
    if options.display:
        
        display_table = create_display_table(hostname, process_list)

        console = Console()
        print('')
        console.print(display_table)
        print('')

    print('[*] Networked process enumeration complete')
 
 
if __name__ == '__main__':
    main()