# fido
Teaching an old shellcode new tricks

Give it x86 (32 bit) windows shellcode and it will strip off Stephen Fewer's hash API call and replace it 
with something that bypasses EMET Caller and EAF+ checks but keeps the actual API calls in use.

WARNING: If the 2nd stage payload uses the hash api from metasploit that loads Win APIs from EATs and jmp's into them,
EMET will catch it.

## Usage

Can take input from stdout and output to stdout:
```
msfvenom -p windows/exec CMD=calc EXITFUNC=thread | ~/github/fido/testharness.py -m -b Tcpview.exe -p ExternGPA -t win10  > test.bin
```

Can take input from cmdline (via -s).



