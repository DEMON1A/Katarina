import re
from loguru import logger

class Strings:
    def __init__(self, file_path) -> None:
        self.file_path: str = file_path
        self.strings: list[str] = []

    def extract_strings(self, min_length=4) -> None:
        with open(self.file_path, 'rb') as f:
            file_data = f.read()

        current_string = b''

        for byte in file_data:
            if 32 <= byte <= 126:
                current_string += bytes([byte])
            else:
                if len(current_string) >= min_length:
                    self.strings.append(current_string.decode('utf-8', errors='ignore'))
                
                current_string = b''

    def print_strings(self, min_length) -> None:
        self.extract_strings(min_length=min_length)
        for string in self.strings:
            print(string)

    def extract_windows_paths(self, min_length) -> None:
        self.extract_strings(min_length=min_length)
        for string in self.strings:
            if re.search(r"[a-zA-Z]\:[\\\/].*", string):
                logger.success(f"Found a windows path: {string}")

    def extract_ctf_flags(self, min_length) -> None:
        self.extract_strings(min_length=min_length)
        for string in self.strings:
            if re.search(r"[A-Za-z]{3,}\{.*\}", string):
                logger.success(f"Found a possible CTF flag: {string}")

    def search_for_string(self, min_length, search_string) -> None:
        self.extract_strings(min_length=min_length)
        for string in self.strings:
            if search_string.lower() in string.lower():
                logger.success(f"Found a match: {string}")

    def search_with_regex(self, min_length, regex) -> None:
        self.extract_strings(min_length=min_length)
        pattern = re.compile(regex)
        for string in self.strings:
            if pattern.search(string):
                logger.success(f"Found a match: {string}")