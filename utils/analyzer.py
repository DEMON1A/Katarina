import pefile
import json
import re
from loguru import logger

class PEAnalyzer:
    def __init__(self, file_path) -> None:
        self.file_path = file_path
        self.pe = pefile.PE(self.file_path)

    def get_entry_point(self) -> None:
        logger.info(f"Entry address: {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")

    def basic_pe_file_analysis(self) -> None:
        try:
            logger.info(f"Number of sections: {len(self.pe.sections)}")
            logger.info(f"Entry point: {hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
            logger.info(f"Sections: {', '.join([i.Name.decode('utf-8').strip('\x00') if i.Name.decode('utf-8').strip('\x00') != '' else 'Unknown' for i in self.pe.sections])}")

            # Iterate through the sections
            logger.info("PE sections details: ")
            for section in self.pe.sections:
                section_info = {
                    "Name": section.Name.decode().strip('\x00'),
                    "VirtualSize": section.Misc_VirtualSize,
                    "VirtualAddress": section.VirtualAddress,
                    "SizeOfRawData": section.SizeOfRawData,
                    "PointerToRawData": section.PointerToRawData,
                    "Characteristics": section.Characteristics
                }

                section_output = json.dumps(section_info, sort_keys=True, indent=4)
                logger.info(f"\n{section_output}")
        except Exception as e:
            print("Error:", e)

    def dump_pe_info(self) -> None:
        try:
            print(self.pe.dump_info())
        except Exception as e:
            print("Error:", e)

    def extract_pdb_path(self) -> None:
        # PDB file path detection
        if hasattr(self.pe, 'DIRECTORY_ENTRY_DEBUG'):
            for debug_entry in self.pe.DIRECTORY_ENTRY_DEBUG:
                if debug_entry.struct.Type == pefile.DEBUG_TYPE['IMAGE_DEBUG_TYPE_CODEVIEW']:
                    # Check if it's a CodeView entry (which typically contains PDB information)
                    cv_info = debug_entry.entry
                    if cv_info.CvSignature == b"RSDS":  # Check if it's a PDB70 format
                        pdb_filename = cv_info.PdbFileName.decode('utf-8').rstrip('\x00')
                        logger.info(f"Found a PDP path {pdb_filename}")

                        windows_user = str(pdb_filename).split('\\')[2]
                        logger.success(f'Found a windows user: {windows_user}, Detection method: PDB file path')
                        return

        logger.error("Couldn't find a pdb path inside this executable")

    def extract_dll_imports(self) -> None:
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = {}
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8')
                imports[dll_name] = []

                for imp in entry.imports:
                    if imp.name:
                        imports[dll_name].append(imp.name.decode("utf-8"))
                    else:
                        imports[dll_name].append(imp.import_by_ordinal)

            logger.info(f"DLLs imported: {', '.join([name for name, _ in imports.items()])}")
            logger.info("Functons usied in each DLL: ")

            for dll_name, imports_list in imports.items():
                functions_output = json.dumps({dll_name: imports_list}, sort_keys=True, indent=4)
                logger.info(f"\n{functions_output}")
        else:
            logger.error("This executable doesn't have any imports listed in the PE headers.")