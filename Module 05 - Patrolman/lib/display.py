from rich import print
from rich.console import Console
from rich.table import Table

def create_display_table(hostname :str, pdata_list :list):
    """ Create a table containing process data for visualization """
    
    # Sort the list based on process name key
    pdata_list.sort(key=lambda x: x['pname'])

    # Rich table configution settings   
    table = Table(title=f'Process Data for: {hostname}')
    table.add_column("Process Name", style="cyan")
    table.add_column("PID", style="dim cyan", no_wrap=True)
    table.add_column("Parent", style="cyan", no_wrap=True)
    table.add_column("L.Port", style="dim cyan", no_wrap=True)
    table.add_column("Remote IP", style="dim cyan", no_wrap=True)
    table.add_column("R.Port", style="dim cyan", no_wrap=True)
    table.add_column("Hunt Flags", style="bold red")
    table.add_column("CTI Matches", style="dim red")

    for pdata in pdata_list:
        if len(pdata['hunt_flags']) > 1 or len(pdata['hash_cti_malware']) > 1 or  len(pdata['rip_cti_malware']) > 1:
            if len(pdata['hash_cti_malware']) > 1:
                pdata['cti_matches'] = pdata['hash_cti_malware']
            else:
                pdata['cti_matches'] = pdata['rip_cti_malware']
            table.add_row(pdata['pname'], pdata['pid'],pdata['ppid_name'],pdata['lport'],pdata['rip'],pdata['rport'],pdata['hunt_flags'],pdata['cti_matches'])
    return table


def print_display_table(hostname, process_list):
        display_table = create_display_table(hostname, process_list)
        console = Console()
        print('')
        console.print(display_table)
        print('')