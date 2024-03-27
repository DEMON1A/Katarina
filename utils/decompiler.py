import lief
from capstone import *
from loguru import logger

class Decompiler:
    def __init__(self, file_path) -> None:
        self.file_path = file_path

    def disassemble_exe(self):
        # Load the executable file
        binary = lief.parse(self.file_path)

        # Check if it's a PE (Portable Executable) format
        if not isinstance(binary, lief.PE.Binary):
            logger.error("You didn't provide a valid windows executable")
            return

        # Initialize Capstone disassembler
        md = Cs(CS_ARCH_X86, CS_MODE_32 if binary.header.machine == lief.PE.Header.MACHINE_TYPES.I386 else CS_MODE_64)

        # Iterate through each section of the executable
        for section in binary.sections:
            print(f"\nDisassembly of section {section.name}:")
            raw_bytes = bytes(section.content)
            for instruction in md.disasm(raw_bytes, section.virtual_address):
                print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")

    def disassemble_exe_for_address(self, address="", before=0, after=0):
        # Load the executable file
        binary = lief.parse(self.file_path)

        # Check if it's a PE (Portable Executable) format
        if not isinstance(binary, lief.PE.Binary):
            logger.error("You didn't provide a valid windows executable")
            return

        # Initialize Capstone disassembler
        md = Cs(CS_ARCH_X86, CS_MODE_32 if binary.header.machine == lief.PE.Header.MACHINE_TYPES.I386 else CS_MODE_64)

        # Iterate through each section of the executable
        sections_data = {}
        for section in binary.sections:
            instructions = []
            address_index: int = None
            instructions_counter: int = 0
            raw_bytes: bytes = bytes(section.content)

            for instruction in md.disasm(raw_bytes, section.virtual_address):
                # if hex(instruction.address) == address:
                #     print(f"\nDisassembly of section {section.name}:")
                #     print(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
                #     return
                instructions_counter += 1
                instructions.append(f"0x{instruction.address:x}:\t{instruction.mnemonic}\t{instruction.op_str}")
                if hex(instruction.address) == address:
                    address_index = instructions_counter

            # Add the section data
            sections_data[section.name] = {
                "instructions": instructions,
                "address_index": address_index
            }

            # Reset the counter and empty the instructions
            instructions = []
            address_index: int = None
            instructions_counter: int = 0

        for section_name, data in sections_data.items():
            instructions = data['instructions']
            address_index = data['address_index']
            
            if address_index is not None:
                for list_index, _ in enumerate(instructions):
                    if list_index == address_index:
                        if address_index is not None:
                            # Calculate the start index for slicing
                            start_index = max(0, address_index - before)
                            # Calculate the end index for slicing
                            end_index = min(len(instructions), address_index + after + 1)
                            
                            # Grab items using slicing
                            items_to_print = instructions[start_index:end_index]
                            
                            # Print the items
                            print(f"\nDisassembly of section {section_name}:")

                            for item in items_to_print:
                                print(item)
                            
                            return

        logger.error("Couldn't find this address in the executable PE headers")
