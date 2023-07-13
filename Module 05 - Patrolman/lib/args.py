from argparse import ArgumentParser, BooleanOptionalAction, RawTextHelpFormatter


def parse_arguments():

    parser = ArgumentParser(
        description='about:\n\
    Patrolman enumerates running processes and identifies associated data attributes, including execution path and arguments, binary hash, and network connection details.\n\
    Patrolman then attempts to identify malicious indicators by analyzing behavioral abnormalities and checking observable indicators for Cyber Threat Intelligence (CTI) pattern matches.\n\
    ',
        formatter_class=RawTextHelpFormatter,
        epilog='For support, contact https://github.com/jcole-sec.\n ',
    )

    parser.add_argument(
        '-j', '--json', 
        help='Enable output logging to a new-line delimited JSON file.\nFile will be written to patrolman_hostname_YYYYmmDD.HHMM.json\n\
    ', 
        action=BooleanOptionalAction,
        default=True
    )

    parser.add_argument(
        '-t', '--tsv', 
        help='Enable output logging to a tab-separated value (TSV) file.\nFile will be written to patrolman_hostname_YYYYmmDD.HHMM.tsv\n\
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

    parser.add_argument(
        '--test', 
        help='Inject simulated malicious process indicators for testing and validation purposes.\n\
    ', 
        action=BooleanOptionalAction,
        default=False
    )
    
    return parser.parse_args()
