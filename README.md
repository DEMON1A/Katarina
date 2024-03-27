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

