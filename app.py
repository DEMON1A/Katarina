import os, sys
from loguru import logger

from utils.analyzer import PEAnalyzer
from utils.strings import Strings
from utils.decompiler import Decompiler
from utils.arguments import parse_command_arguments

logger.remove(0)
logger.add(sys.stdout, level="TRACE")

def main() -> None:
    args = parse_command_arguments()

    if args.mode == "pe":
        analyzer = PEAnalyzer(file_path=args.file)
        if args.dump_info:
            analyzer.dump_pe_info()
            return
        elif args.extract_pdb_path:
            analyzer.extract_pdb_path()
            return
        elif args.basic_analysis:
            analyzer.basic_pe_file_analysis()
            return
        elif args.extract_imports:
            analyzer.extract_dll_imports()
            return
        elif args.entry_address:
            analyzer.get_entry_point()
        else:
            logger.error("No specified action")
            logger.info(f"python {os.path.basename(__file__)} {args.file} {args.mode} -h, for more details")
    elif args.mode == "strings":
        strings = Strings(file_path=args.file)

        min_length = args.min_length if args.min_length is not None else 4
        if args.extract_paths:
            strings.extract_windows_paths(min_length=min_length)
        elif args.extract_ctf_flags:
            strings.extract_ctf_flags(min_length=min_length)
        elif args.search:
            strings.search_for_string(min_length=min_length, search_string=args.search)
        elif args.regex_search:
            strings.search_with_regex(min_length=min_length, regex=args.regex_search)
        else:
            strings.print_strings(min_length=min_length)
    elif args.mode == "asm":
        decompiler = Decompiler(file_path=args.file)

        if args.decompile:
            decompiler.disassemble_exe()
        elif args.section_address:
            decompiler.disassemble_exe_for_address(address=args.section_address, before=int(args.before_address), after=int(args.after_address))
        else:
            logger.error("No specified action")
            logger.info(f"python {os.path.basename(__file__)} {args.file} {args.mode} -h, for more details")

if __name__ == "__main__":
    main()