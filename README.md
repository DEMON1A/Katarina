## Katarina 
CTF and malware analysis toolkit that helps analyzing, decompiling and searching through executables

## How to install
You can easily install katarina and install required pip packages using the following commands 
```bash
git clone https://github.com/DEMON1A/Katarina
cd Katarina
pip install -r requirements.txt
```

## Usage
```css
E:\Projects\Python\katarina>python app.py samples\test.exe -h
usage: app.py [-h] file {pe,strings,asm} ...

Katarina v0.0.0-beta, Your malware analysis and CTF toolkit!

positional arguments:
  file              Path to your executable
  {pe,strings,asm}  Available modes
    pe              Extract data on the executable PE headers
    strings         Extract and filter strings located inside the executable
    asm             Decompile and extract information from the executable

options:
  -h, --help        show this help message and exit
```

### PE
```css
E:\Projects\Python\katarina>python app.py samples\test.exe pe -h
usage: app.py file pe [-h] [--dump-info] [--extract-pdb-path] [--extract-imports] [--entry-address] [--basic-analysis]

options:
  -h, --help          show this help message and exit
  --dump-info         Dump PE headers information from the executable
  --extract-pdb-path  Extract the pdb path from the executable
  --extract-imports   Extract dll imports from the executable
  --entry-address     Get the entry address of the executable
  --basic-analysis    Get basic information about the PE headers
```

#### Example usage
```css
E:\Projects\Python\katarina>python app.py samples\test.exe pe --extract-pdb-path
2024-03-27 07:07:44.908 | INFO     | utils.analyzer:extract_pdb_path:52 - Found a PDP path C:\Users\tmcguff\source\repos\HelloWorld\HelloWorld\obj\x64\Release\HelloWorld.pdb
2024-03-27 07:07:44.909 | SUCCESS  | utils.analyzer:extract_pdb_path:55 - Found a windows user: tmcguff, Detection method: PDB file path
```

```css
E:\Projects\Python\katarina>python app.py samples\test.exe pe --entry-address
2024-03-27 07:08:20.102 | INFO     | utils.analyzer:get_entry_point:12 - Entry address: 0x0
```

### STRINGS
```css
E:\Projects\Python\katarina>python app.py samples\test.exe strings -h
usage: app.py file strings [-h] [--min-length MIN_LENGTH] [--extract-paths] [--extract-ctf-flags] [--search SEARCH]
                           [--regex-search REGEX_SEARCH]

options:
  -h, --help            show this help message and exit
  --min-length MIN_LENGTH
                        Minimal length for strings to be grabbed
  --extract-paths       Extract windows paths from the executable strings
  --extract-ctf-flags   Extract possible CTF flags in executable strings
  --search SEARCH       Search for a specific string inside of the executable
  --regex-search REGEX_SEARCH
                        Search for a specific string inside of the executable using regex
```

#### Example usage
```css
E:\Projects\Python\katarina>python app.py samples\test.exe strings --regex-search .*\.exe
2024-03-27 07:05:35.792 | SUCCESS  | utils.strings:search_with_regex:52 - Found a match: HelloWorld.exe
```

```css
E:\Projects\Python\katarina>python app.py samples\test.exe strings --search hello
2024-03-27 07:06:27.422 | SUCCESS  | utils.strings:search_for_string:45 - Found a match: HelloWorld
2024-03-27 07:06:27.423 | SUCCESS  | utils.strings:search_for_string:45 - Found a match: HelloWorld.exe
2024-03-27 07:06:27.423 | SUCCESS  | utils.strings:search_for_string:45 - Found a match: HelloWorld
2024-03-27 07:06:27.424 | SUCCESS  | utils.strings:search_for_string:45 - Found a match: C:\Users\tmcguff\source\repos\HelloWorld\HelloWorld\obj\x64\Release\HelloWorld.pdb
```

```css
E:\Projects\Python\katarina>python app.py samples\test.exe strings --extract-paths
2024-03-27 07:07:06.329 | SUCCESS  | utils.strings:extract_windows_paths:33 - Found a windows path: C:\Users\tmcguff\source\repos\HelloWorld\HelloWorld\obj\x64\Release\HelloWorld.pdb
```

### ASM
```css
E:\Projects\Python\katarina>python app.py samples\test.exe asm -h
usage: app.py file asm [-h] [--decompile] [--address SECTION_ADDRESS] [--before BEFORE_ADDRESS] [--after AFTER_ADDRESS]

options:
  -h, --help            show this help message and exit
  --decompile           Decompile the executable PE headers into assembly
  --address SECTION_ADDRESS
                        Get the assembly code for a certain address
  --before BEFORE_ADDRESS
                        How many instructions to show before the selected address
  --after AFTER_ADDRESS
                        How many instructions to show after the selected address
```

#### Example usage
```css
E:\Projects\Python\katarina>python app.py samples\test.exe asm --address 0x40bd --before 2 --after 4

Disassembly of section .rsrc:
0x40b7: add     byte ptr [rbp + 0xfeef04], bh
0x40bd: add     byte ptr [rcx], al
0x40bf: add     byte ptr [rax], al
0x40c1: add     byte ptr [rcx], al
0x40c3: add     byte ptr [rax], al
0x40c5: add     byte ptr [rax], al
0x40c7: add     byte ptr [rax], al
```
