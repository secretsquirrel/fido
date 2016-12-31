#!/usr/bin/env python3

from __future__ import print_function
from keystone import *
from capstone import *
from capstone.x86 import *
import struct
import sys
import re
import binascii
from collections import OrderedDict


class build_code:

    def __init__(self, shellcode={}):
        # block is a list
        # LOADLIBA in EBX
        # GETPROCADDR in ECX
        self.block = None
        self.last_called_api = None
        self.last_called_dll = None
        self.arch = CS_ARCH_X86
        self.mode = CS_MODE_32
        # the way this flow will work
        # track what is pushed on the stack for calling
        # Call loadlibA/Getprocaddress to call the winAPI
        # keep track of lla/gpa and whether the api is needed for 
        # further use
        self.args = []
        self.returnValue = 0
        # Important Handles for tracking
        
        self.Handle = ''
        #self.arch = CS_ARCH_X86
        #self.mode = CS_MODE_32
        # set regs
        self.shellcode = OrderedDict(shellcode)
        print("Init shellcode:", self.shellcode)
        self.safe_mnemonics = ['test', 'cmp']
        if self.shellcode !={}:
            #print(next(iter(self.shellcode.keys())))
            self.initShellLen = self.shelllen()

        #self.shell_len_init = self.shellcode.


        #APIs structure: API, Call_Response_Type(returnValue/True/False/None/Handle), Needed_in_future/checked(T/F)
        # it would be more powerfull to determine if eax was used in the next call or moved to another register 
        # so that I am not api dependent.
        self.Handles = {
            'LLAHandle' : 'ebx',
            'GPAHandle' : 'ebp',
            'APIHandle' : '',  
            'DLLHandle' : '',
        }
       
        
        self.registers = {
                        'eax' : 0,
                        'ecx' : 0,
                        'edx' : 0,
                        'ebx' : 0,
                        'esp' : 0,
                        'ebp' : 0,
                        'esi' : 0,
                        'edi' : 0,
                    }

        self.apis = [  ( 0x006B8029, "ws2_32.dll!WSAStartup", self.returnValue, False),
                       ( 0xE0DF0FEA, "ws2_32.dll!WSASocketA", self.Handle, True ),
                       ( 0x33BEAC94, 'ws2_32.dll!WSAaccept', self.returnValue, True),  # inc eax jz condition
                       ( 0x6737DBC2, "ws2_32.dll!bind", self.returnValue, False ),
                       ( 0xFF38E9B7, "ws2_32.dll!listen", self.returnValue, False ),  # 0 on success
                       ( 0xE13BEC74, "ws2_32.dll!accept", self.returnValue, False),
                       ( 0x614D6E75, "ws2_32.dll!closesocket", self.returnValue, False ),
                       ( 0x6174A599, "ws2_32.dll!connect",  self.returnValue, True), # check if Zero (success)
                       ( 0x5FC8D902, "ws2_32.dll!recv", self.returnValue, True),  # check if Zero (failure)
                       ( 0x5F38EBC2, "ws2_32.dll!send", self.returnValue, False),
                       ( 0x5BAE572D, "kernel32.dll!WriteFile", self.returnValue, False),
                       ( 0x4FDAF6DA, "kernel32.dll!CreateFileA", self.Handle, True),
                       ( 0x13DD2ED7, "kernel32.dll!DeleteFileA", self.returnValue, False),
                       ( 0xE449F330, "kernel32.dll!GetTempPathA", self.returnValue, True ),
                       ( 0x528796C6, "kernel32.dll!CloseHandle", self.returnValue, False),
                       ( 0x863FCC79, "kernel32.dll!CreateProcessA", self.returnValue, False),
                       ( 0xE553A458, "kernel32.dll!VirtualAlloc", self.returnValue, False),
                       ( 0x300F2F0B, "kernel32.dll!VirtualFree", self.returnValue, ),
                       ( 0x0726774C, "kernel32.dll!LoadLibraryA", self.Handle, True), # handle
                       ( 0x7802F749, "kernel32.dll!GetProcAddress", self.Handles['APIHandle'], True), # handle
                       ( 0x601D8708, "kernel32.dll!WaitForSingleObject", self.returnValue, False ),
                       ( 0x876F8B31, "kernel32.dll!WinExec", self.returnValue, False),
                       ( 0x9DBD95A6, "kernel32.dll!GetVersion", self.returnValue, True ),
                       ( 0xEA320EFE, "kernel32.dll!SetUnhandledExceptionFilter", self.returnValue, False ),
                       ( 0x56A2B5F0, "kernel32.dll!ExitProcess", None, False ),
                       ( 0x0A2A1DE0, "kernel32.dll!ExitThread", None, False ),
                       ( 0x6F721347, "ntdll.dll!RtlExitUserThread", None, False ),
                       ( 0x23E38427, "advapi32.dll!RevertToSelf", self.returnValue,  False),
                       ( 0xa779563a, "wininet.dll!InternetOpenA", self.Handle, True),  # handle
                       ( 0xc69f8957, "wininet.dll!InternetConnectA", self.Handle, True), # handle
                       ( 0x3B2E55EB, "wininet.dll!HttpOpenRequestA", self.Handle, True), # handle
                       ( 0x869E4675, "wininet.dll!InternetSetOptionA", self.returnValue, False),
                       ( 0x7B18062D, "wininet.dll!HttpSendRequestA", self.returnValue, False),  # just check for success
                       ( 0xE2899612, "wininet.dll!InternetReadFile", self.returnValue, False), # just check for success
              ]

    def get_api(self, anumber):
        #print('anumber', type(anumber), anumber)
        for ahash in self.apis:
            if hex(ahash[0]) == anumber:
                print("\tCalling: {0}".format(ahash[1]))
                return True
        return None   

    def assemble_code(self, mnemonics):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        encoding, count = ks.asm(mnemonics)
        tmp = b''
        for i in encoding:
            # hack hack hack
            tmp += struct.pack("<B", i)
        return tmp     

    def disa_code(self, byte_string):
        md = Cs(self.arch, self.mode)
        md.detail = True
        #only handle one instruction set at a time
        for insn in md.disasm(byte_string, self.shelllen()):
            return insn.mnemonic, insn.op_str

    def add2shellcode(self, byte_string, mnemonic=None, op_str=None, 
                      controlFlowTag=None, blocktag=None, direction=None):
        
        if not mnemonic and not op_str:
            mnemonic, op_str = self.disa_code(byte_string)
            #print (mnemonic, op_str)
        #print("len before", self.shelllen())
        self.shellcode[self.shelllen() + len(byte_string)] = { 'bytes': byte_string,
                              'mnemonic': mnemonic,
                              'op_str': op_str,
                              'controlFlowTag': controlFlowTag,
                              'blocktag': blocktag,
                              'direction': direction,
                            }
        #print("len after:", self.shelllen())
    
    def shelllen(self):
        # Because stopiteration
        final_len = 0
        for key, value in self.shellcode.items():
            final_len = key
        return final_len
        #return next(reversed(self.shellcode))

    def lla_stub(self, api_offset):
        # LLA MUST BE IN EBX
        #self.lla_xchg_handler(self.Handles['LLAHandle'])
        self.add2shellcode(b'\xe8\x00\x00\x00\x00', blocktag=self.blocktag)           # GET Next add
        self.add2shellcode(b'\x59', blocktag=self.blocktag)                    # POP EXC
        tmp = b"\x8D\x89"                 # LEA EXC, ...
        #print('len check meh', self.shelllen() - api_offset - 2)
        tmp += struct.pack("<I", 0xFFFFFFFF-(self.shelllen() - api_offset)+2) #... DWORD PTR DS: [API ADDR]
        self.add2shellcode(tmp, blocktag=self.blocktag)
        self.add2shellcode(b'\x51', blocktag=self.blocktag)                    # Push ECX
        self.add2shellcode(b'\xFF\x13', blocktag=self.blocktag)                # Call [EBX]
        self.Handles['DLLHandle'] = 'eax'

    def gpa_stub(self, api_offset):
        # GPA Must be in EBP
        # DLLHandle MUST be in EAX
        self.gpa_xchg_handler(self.Handles['GPAHandle'])
        self.dll_xchg_handler(self.Handles['DLLHandle'])
        self.add2shellcode(b'\xe8\x00\x00\x00\x00', blocktag=self.blocktag)          # GET Next add
        self.add2shellcode(b'\x59', blocktag=self.blocktag)                          # POP EXC
        tmp = b'\x8D\x89'                  # LEA EXC, ...
        #print('Len check:', len(self.return_shellcode()) - api_offset)
        tmp += struct.pack("<I", 0xFFFFFFFF-(self.shelllen() - api_offset)+2) #... DWORD PTR DS: [API ADDR]
        self.add2shellcode(tmp, blocktag=self.blocktag)
        self.add2shellcode(b'\x51', blocktag=self.blocktag)                     # PUSH ECX
        self.add2shellcode(b'\x50', blocktag=self.blocktag)                     # PUSH EAX
        self.add2shellcode(b'\xFF\x55\x00', blocktag=self.blocktag)                 # Call [EBP]
        self.Handles['APIHandle'] = 'eax'

    def lla_gpa_stub(self, api_offset1, api_offset2):
        self.add2shellcode(b'\x60', blocktag=self.blocktag)                     # PUSHAD
        
        self.lla_stub(api_offset1)   
        self.gpa_stub(api_offset2)
        
        self.add2shellcode(b'\x61', blocktag=self.blocktag)                   # POPAD restore registers
        # API HANDLE in EAX
        # TODO: This below needs to work on the fly for what
        #   register is required.
        self.add2shellcode(b'\x8B\x4C\x24\xB8', blocktag=self.blocktag)        # MOV EBP, DWORD PTR SS:[ESP-24]
        self.add2shellcode(b'\x8B\x7C\x24\xD8', blocktag=self.blocktag)         # MOV EDI, [EDI] ; put the dll handle in EDI for future use (maybe)
        self.Handles['DLLHandle'] = 'edi'
        self.Handles['APIHandle'] = 'ecx'

    def return_shellcode(self):
        tmp_code = b''
        for key, value in self.shellcode.items():
            if 'bytes' in value:
                tmp_code += value['bytes']

        return tmp_code

    def find_location_string(self, astring):
        
        p = re.compile(bytes(astring, 'iso-8859-1'))
        tmp_code = b''
        
        for m in p.finditer(self.return_shellcode()):
            #print("regex check:", hex(self.return_shellcode()[m.start()]))
            return m.start()
    
    def dll_xchg_handler(self, Handle):
        # For xchg DLLHandle to EAX
        print("\t[!] xchg DLLHandle to EAX:", type(Handle))
        if Handle != 'eax' and Handle != '':
            self.add2shellcode(self.assemble_code('xchg eax, ' + Handle),
                               blocktag=self.blocktag)
        
            self.Handles['DLLHandle'] = 'eax'

    def gpa_xchg_handler(self, Handle):
        # For xchg GPA to ESI
        print("\t[!] xchg GPA to ESI", Handle)
        if Handle != 'ebp':
            self.add2shellcode(self.assemble_code('xchg ebp, ' + Handle),
                               blocktag=self.blocktag)
        
            self.Handles['GPAHandle'] = 'ebp'

    def lla_xchg_handler(self, Handle):
        # for xchg LLA EBX
        print("\t[!] xchg LLA to EBX")
        if Handle != 'ebx':
            self.add2shellcode(self.assemble_code('xchg ebx, ' + Handle),
                               blocktag=self.blocktag)

            self.Handles['LLAHandle'] = 'ebx'

    def push_handler(self, Handle):
        self.add2shellcode(self.assemble_code('push ' + Handle),
                               blocktag=self.blocktag)

    def call_handler(self, Handle):
        self.add2shellcode(self.assemble_code('call ' + Handle),
                               blocktag=self.blocktag)
        
    def walk_check(self, value):
        # ECX, EDX EAX, NOT SAFE
        # overwite DLL Handle 
        self.add2shellcode(self.assemble_code('mov edi, ' + value),
                               blocktag=self.blocktag)
        #elif 'edx' not in self.Handles.values():
        #    new_value = 'edi'
        #    self.shellcode += self.assemble_code('mov edx, ' + value)
        
        for a_handle, regvalue in self.Handles.items():    
            if value == regvalue:
        #        # Time to use keystone
        #        # new value = 'mov ' + value
                self.Handles[a_handle] = 'edi'
        
        self.last_called_dll = None           
        #for reg, _ in self.registers.items():


    def inspect_block(self, block, called_api):
        self.block = block
        self.called_api = called_api
        self.dll_location = 0
        self.api_location = 0
        self.blocktag = self.block[next(reversed(self.block))]['blocktag']
        print("BLOCKTAG:", self.blocktag)
        #print("len shellcode", len(self.shellcode))
        # check for saving eax
        #if last_called_api != called_api:

        if self.called_api:
            print("Called API:", self.called_api.split("!"))
            dll2Call, api2Call = self.called_api.split("!")
            dll2Call = dll2Call.strip('.dll')
        
        #if dll2Call == 'Not Found':
        #    return None
        
            print("Check", self.last_called_dll, dll2Call)
        
            if self.last_called_dll != dll2Call:
                print("DLL to lla: {0}, API to GPA: {1}".format(dll2Call, api2Call))
                #self.find_location_string(dll2Call)
                self.lla_gpa_stub(self.find_location_string(dll2Call), self.find_location_string(api2Call))
                #self.shellcode += self.lla_gpa_stub()
                #print (binascii.hexlify(self.shellcode))
                self.last_called_dll = dll2Call

            else:
                # The DLLHandle is being reused
                print("Yup")
                # Set DLLHandle for GPA
                self.add2shellcode(b"\x60", blocktag=self.blocktag)                    # PUSHAD
                self.gpa_stub(self.find_location_string(api2Call))
                # recover DLLHandle (just in case)
                self.add2shellcode(b"\x61", blocktag=self.blocktag)                       # POPAD
                self.add2shellcode(b"\x8B\x4C\x24\xB8", blocktag=self.blocktag)          # MOV ECX, DWORD PTR SS:[ESP-24]
                self.Handles['APIHandle'] = 'ecx'
                self.Handles['DLLHandle'] = 'edi'
#DO an exchange after push eax to save DLL handle
        #Now call the function 
        print("BLOCK:", self.block)
        for key, value in self.block.items():
            value['direction'] = None
            print('[*] Value:', value)
            #print(type(self.Handles['APIHandle']), self.Handles['APIHandle'])
            if any(value['mnemonic'] in x for x in self.safe_mnemonics):
                print (value['mnemonic'], "WOOT")
            
            for handle in self.Handles:
                #print("$$$$", handle)
                if len(value['op_str'].split(',')) >=2:

                    if self.Handles[handle] in value['op_str'].split(',')[1] and len(value['op_str'].split(',')) >=2 and value['mnemonic'] not in self.safe_mnemonics:
                        pass
                        #print("YEAHDOG", value['mnemonic']+ " "+ value['op_str'])
                        # if it a DLL handle I'm ok with letting it get clobbered
                        # if it is a LLA/GPA, not so much
            
            print("APIHandle", self.Handles['APIHandle'])
            print("DLLHandle", self.Handles['DLLHandle'])
            print("LLAHandle", self.Handles['LLAHandle'])
            print("GPAHandle", self.Handles['GPAHandle'])
                
            if len(value['op_str'].split(',')) >= 2 and self.Handles['DLLHandle'] != '':
                # it is getting clobbered
                print("Right HERE")
                if self.Handles['DLLHandle'] in value['op_str'].split(',')[1] and len(value['op_str'].split(',')) >=2 and value['mnemonic'] not in self.safe_mnemonics:
                    print("OH NOES", value['mnemonic']+ " "+ value['op_str'])
                    # I'm ok with the DLL Handle getting clobbered
                    self.Handles['DLLHandle'] = ''
                    self.last_called_dll = None
            
            if 'save eax' in value:
                print('saving eax (Not implemented)')
                continue
            
            elif 'mov ' + self.Handles['APIHandle'] in value['mnemonic'] + ' ' + value['op_str'] and self.Handles['APIHandle'] != '':
                # get handle to another register
                print('TODO: Should Exchange APIHandle')
                #self.shellcode += "\x95"                          # xchg eax, ebp 
                #self.Handles['APIHandle'] = 'eax'
                #self.eax = 0
                #print('mov eax', values)
                # Check if if it is a numberical value

                #if len(values[0]) > 2:
                    # not an operade mov 

            elif 'mov ' + self.Handles['GPAHandle'] in value['mnemonic'] + ' ' + value['op_str'] and self.Handles['GPAHandle'] != '':
                print("\t[!] GPA Overwrite at", self.Handles['GPAHandle'])
                # find empty register
                self.walk_check(self.Handles['GPAHandle'])
                print("[%%%] New GPAHandle:", self.Handles['GPAHandle'])

            elif 'mov ' + self.Handles['LLAHandle'] in value['mnemonic'] + ' ' + value['op_str'] and self.Handles['LLAHandle'] != '':
                print("\t[!] LLA Overwrite at", self.Handles['LLAHandle'])
                # find empty register
                self.walk_check(self.Handles['LLAHandle'])
                print("[~~~] New LLAHandle", self.Handles['LLAHandle'])

            elif 'mov ' + self.Handles['DLLHandle'] in value['mnemonic'] + ' ' + value['op_str'] and self.Handles['DLLHandle'] != '':
                print("\t[!] DLL Overwrite at", self.Handles['DLLHandle'])
                self.walk_check(self.Handles['DLLHandle'])
                print("[XXX] New DLLHandle", self.Handles['DLLHandle'])
                      
            elif 'push' == value['mnemonic'] and len(value['bytes']) > 2:
                # check if known hash

                if self.get_api(value['op_str']) is True:
                    print("Found API Push, Continuing")
                    # push the handle Need a handle tracker
                    #self.push_handler(self.Handles['APIHandle'])
                    continue

            elif 'call ebp' == value['mnemonic'] + ' ' + value['op_str']:
                 print("Calling Handler")
                 print('API Handler in:', self.Handles['APIHandle'])
                 self.call_handler(self.Handles['APIHandle'])   
                 #print(binascii.hexlify(self.return_shellcode()))
                 break
            
            elif 'mov' == value['mnemonic'] and len(value['bytes']) > 2:
                print('fdsajfklad')
                if self.get_api(value['op_str']) is True:
                    print("Found API MOV, Continuing")
                    continue
            
            elif 'push ebx' == value['mnemonic'] + ' ' + value['op_str']:
                # check for mov ebx, api_hash in this block
                print('found push ebx')
                found_mov = False
                for sub_key, sub_value in self.block.items():
                    print('FUCK', sub_key, sub_value)
                    if 'mov' == sub_value['mnemonic'] and len(sub_value['bytes']) > 2:
                        if self.get_api(sub_value['op_str'].split(", ")[1]) is True:
                            print("Found API MOV, Continuing")
                            found_mov = True
                            
                if found_mov is True:
                    print('SO TRUE')
                    continue

            #Add direction flag

            if value['controlFlowTag'] and ('call'in value['mnemonic'] or 'j' in value['mnemonic']):
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
                # change op_str to 0 for later fix up
                #value['bytes'] = self.assemble_code(value['mnemonic'] + ' 0x0')
                #print('+++++', test)
                #print("[++++] New block:", value)
            
            self.add2shellcode(value['bytes'], value['mnemonic'], value['op_str'], 
                               value['controlFlowTag'], value['blocktag'], value['direction'])
            
            #TODO: ADD API After action here?
        print (binascii.hexlify(self.return_shellcode()))

            #print(asm)
            #insn = self.dissa(asm, count)
            #print(insn.mnemonic + " " + insn.op_str)

        #print(self.block)
