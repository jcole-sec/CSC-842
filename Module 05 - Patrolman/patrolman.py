import time
from rich import print

# locals
from lib.args import *
from lib.huntevil import *
from lib.cti_enrichment import *
from lib.utils import *
from lib.display import *


def main():

    # Get arguments
    options = parse_arguments()
    debug = options.debug
    test = options.test

    # Run Process Enumeration
    print('[*] Networked process enumeration initiated')

    process_list = get_process_list(debug, test)

    # Optionally Filter for public IP entries
    if options.public:
        print('[*] Filtering for public IPs')
        process_list = public_address_filter(process_list)

    print('[*] Networked process enumeration complete\n')

    # Run "Hunt Evil" (Process Anomaly) Checks
    process_list = run_huntevil_checks(process_list)

    # Run CTI Enrichment
    process_list = run_cti_lookups(process_list)

    # Set Outputs
    datetime = time.strftime('%Y%m%d.%H%M')
    hostname = socket.gethostname()
    outfile_prefix = f'patrolman_{hostname}_{datetime}'

    if options.json:
        write_json(outfile_prefix, process_list)

    if options.tsv:
        write_tsv(outfile_prefix, process_list)
   
    if options.display:
        print_display_table(hostname, process_list)

 
if __name__ == '__main__':
    main()