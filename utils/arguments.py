import argparse
from argparse import Namespace

def parse_command_arguments() -> Namespace:
    # Setup the main parser
    parser = argparse.ArgumentParser(description="Katarina v0.0.0-beta, Your malware analysis and CTF toolkit!")
    parser.add_argument('file', help='Path to your executable')

    # Subparsers
    subparsers = parser.add_subparsers(dest='mode', help='Available modes')

    # pe parser
    pe_parser = subparsers.add_parser('pe', help='Extract data on the executable PE headers')
    pe_parser.add_argument('--dump-info', dest='dump_info', action='store_true', default=False, help='Dump PE headers information from the executable')
    pe_parser.add_argument('--extract-pdb-path', dest='extract_pdb_path', action='store_true', default=False, help='Extract the pdb path from the executable')
    pe_parser.add_argument('--extract-imports', dest='extract_imports', action='store_true', default=False, help='Extract dll imports from the executable')
    pe_parser.add_argument('--entry-address', dest='entry_address', action='store_true', default=False, help="Get the entry address of the executable")
    pe_parser.add_argument('--basic-analysis', dest='basic_analysis', action='store_true', default=False, help='Get basic information about the PE headers')

    # strings parser
    strings_parser = subparsers.add_parser('strings', help="Extract and filter strings located inside the executable")
    strings_parser.add_argument('--min-length', dest='min_length', default=4, help="Minimal length for strings to be grabbed")
    strings_parser.add_argument('--extract-paths', dest='extract_paths', action='store_true', default=False, help="Extract windows paths from the executable strings")
    strings_parser.add_argument('--extract-ctf-flags', dest='extract_ctf_flags', action='store_true', default=False, help="Extract possible CTF flags in executable strings")
    strings_parser.add_argument('--search', dest='search', required=False, help="Search for a specific string inside of the executable")
    strings_parser.add_argument('--regex-search', dest='regex_search', required=False, help="Search for a specific string inside of the executable using regex")

    # asm parser
    asm_parser = subparsers.add_parser('asm', help="Decompile and extract information from the executable")
    asm_parser.add_argument('--decompile', dest='decompile', action='store_true', default=False, help='Decompile the executable PE headers into assembly')
    asm_parser.add_argument('--address', dest='section_address', default=False, help="Get the assembly code for a certain address")
    asm_parser.add_argument('--before', dest='before_address', default=0, help="How many instructions to show before the selected address")
    asm_parser.add_argument('--after', dest='after_address', default=0, help="How many instructions to show after the selected address")


    # get args
    args = parser.parse_args()

    return args