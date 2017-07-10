import sys
from keystone import *
import array
from capstone import *
from capstone.x86 import *

def lla_gpa_parser_stub_x64():
    parser_stub = 'LLAGPA'
    importname = 'main_module'

    shellcode =   (
               

                # x86 calling convention
                # eax, ecx, edx are caller saved everything pushed on the stack in reverse order
                # 
                # vs
                # x64 calling convention
                # It uses registers RCX, RDX, R8, R9 for the first four integer or pointer arguments (in that order), 
                #  and XMM0, XMM1, XMM2, XMM3 are used for floating point arguments. 
                #  Additional arguments are pushed onto the stack (right to left).
                # Stack: "shadow space" on the stack right before calling the function (regardless of the actual number of parameters used), and to pop the stack after the call. The shadow space is used to spill RCX, RDX, R8, and R9,[14] but must be made available to all functions, even those with fewer than four parameters.  
                # RAX, RCX, RDX, R8, R9, R10, R11 are considered volatile (caller-saved).[15]   
                # RBX, RBP, RDI, RSI, RSP, R12, R13, R14, and R15 are considered nonvolatile (callee-saved).[15]    
                b'int3;'               
                b'cld;'
                b'sub rsp,0x20;'
                b'push r9;'                              # Save registers
                b'push r8;'
                b'push rdx;'
                b'push rcx;'
                b'push rsi;'
                b'xor rdx, rdx;'
                b'mov rdx, qword ptr gs:[rdx + 0x60];'   #; PEB
                b'mov rdx, qword ptr [rdx + 0x10];'      #; PEB.imagebase
                b'mov rbx, rdx;'                         #; Set rbx to imagebase  
                b'mov eax, dword ptr [rdx + 0x3c];'      #; Splitting 4 byte memory "PE"
                b'add rdx, rax;'                         #; "PE"
                
                b'mov edi, dword ptr [rdx + 0x90];'      #; Import Table RVA
                b'add rdi, rbx;'                         #; Import table in memory offset   
                
                b'findImport:;'
                b'mov edx, dword ptr [rdi + 0xc];'       # Offset for Import Directory Table Name RVA  NEED TO TEST
                b'add rdx, rbx;'                         # Offset in memory
                b'cmp dword ptr [rdx], 0x4e52454b;'      # cmp kern
                b'jne incImport;'                             # jmp short to increment 14
                b'cmp dword ptr ds:[rdx+4],0x32334C45;'  # el32   
                b'je saveBase;'                              # je to saveBase
                
                b'incImport:;'
                b'add rdi, 0x14;'                        # inc to next import
                b'jmp findImport;'                             # jmp to findImport
                # mov ; Offset for import Directory Table Name
                # ; Offset in memory    
                
                b'saveBase:;'
                b'push rdi;'
                b'jmp loadAPIs;' # jump LoadAPIs
                
                b'setBounds:;'
                b'mov edx, dword ptr [rdi + 0x10];'       # ;Point to API name
                b'add rdx, rbx;'                          # ;Adjust to in memory offset
                b'mov esi, dword ptr [rdi];'              # ;Set ESI to the Named Import base
                b'add rsi, rbx;'                          # ;Adjust to in memory offset
                b'mov rcx, rdx;'                          # ;Mov in memory offset to ecx
                b'add rcx, 0xff0000;'                     # ;Set an upper bounds for reading
                b'xor rbp, rbp;'                          # ;Zero ebp for thunk offset
                
                b'findAPI:;'
                b'mov eax, dword ptr [rsi];'              #;Mov pointer to Named Imports
                b'add rax, rbx;'                          #;Find in memory offset
                b'add rax, 2;'                            #;Adjust to ASCII name start
                b'cmp rcx, rax;'                          #;Check if over bounds
                b'jb increment;'                             #;If not over, don't jump to increment
                b'cmp rax, rdx;'                          #;Check if under Named import
                b'jb increment;'                             #;If not over, don't jump to increment
                b'mov edi, dword ptr ds:[rsp + 8];'       #;Move API name to edi
                b'cmp dword ptr [rax], edi;'              #;Check first 4 chars
                b'jne increment;'                            #;If not a match, jump to increment
                b'mov edi, dword ptr ds:[rsp + 16];'       #;Move API 2nd named part to edi
                b'cmp dword ptr [rax + 8], edi;'          #;Check next 4 chars
                b'jne increment;'                            #;If not a match, jump to increment
                b'ret;'                                   #;If a match, ret                
                
                b'increment:;'
                b'add ebp, 4;'                            # ;inc offset
                b'add rsi, 4;'                            # ;inc to next name
                b'jmp findAPI;'                              # ;jmp findAPI
                
                b'loadAPIs:;'
                b'push 0x41797261;'                      # ;aryA (notice the 4 char jump between beginni
                b'push 0x64616f4c;'                      # ;Load
                b'call setBounds;'                            # ;call setBounds
                b'add rdx, rbp;'                         # ;In memory offset of API thunk
                b'add rsp, 0x10;'                           # ;Move stack to import base addr
                b'pop rdi;'                              # ;restore import base addr for parsing;'
                #add rest here
                b'push rdx;'                             # ;save LoadLibraryA thunk address on stack
                b'push 0x65726464;'                      # ;ddre
                b'push 0x50746547;'                      # ;Getp
                b'call setBounds;'                            # ;call setBounds
                b'add rdx, rbp;'                         # ;
                b'pop rbp;'                              # ;
                b'pop rbp;'                              # ;
                b'pop rbx;'                              # ;Pop LoadlibraryA thunk addr into rbx
                b'mov rbp, rdx;'                         # ;Move GetProcaddress thunk addr into rbx
                )#
                ######
                # LLA in RBX
                # GPA RBP
    return shellcode

def gpa_parser_stub_x64():

    shellcode = (
                                # x86 calling convention
                # eax, ecx, edx are caller saved everything pushed on the stack in reverse order
                # 
                # vs
                # x64 calling convention
                # It uses registers RCX, RDX, R8, R9 for the first four integer or pointer arguments (in that order), 
                #  and XMM0, XMM1, XMM2, XMM3 are used for floating point arguments. 
                #  Additional arguments are pushed onto the stack (right to left).
                # Stack: "shadow space" on the stack right before calling the function (regardless of the actual number of parameters used), and to pop the stack after the call. The shadow space is used to spill RCX, RDX, R8, and R9,[14] but must be made available to all functions, even those with fewer than four parameters.  
                # RAX, RCX, RDX, R8, R9, R10, R11 are considered volatile (caller-saved).[15]   
                # RBX, RBP, RDI, RSI, RSP, R12, R13, R14, and R15 are considered nonvolatile (callee-saved).[15]    
                b'int3;'               
                b'cld;'
                b'sub rsp,0x20;'
                b'push r9;'                              # Save registers
                b'push r8;'
                b'push rdx;'
                b'push rcx;'
                b'push rsi;'
                b'xor rdx, rdx;'
                b'mov rdx, qword ptr gs:[rdx + 0x60];'   #; PEB
                b'mov rdx, qword ptr [rdx + 0x10];'      #; PEB.imagebase
                b'mov rbx, rdx;'                         #; Set rbx to imagebase  
                b'mov eax, dword ptr [rdx + 0x3c];'      #; Splitting 4 byte memory "PE"
                b'add rdx, rax;'                         #; "PE"
                
                b'mov edi, dword ptr [rdx + 0x90];'      #; Import Table RVA
                b'add rdi, rbx;'                         #; Import table in memory offset   
                
                b'findImport:;'
                b'mov edx, dword ptr [rdi + 0xc];'       # Offset for Import Directory Table Name RVA  NEED TO TEST
                b'add rdx, rbx;'                         # Offset in memory
                b'cmp dword ptr [rdx], 0x4e52454b;'      # cmp kern
                b'jne incImport;'                             # jmp short to increment 14
                b'cmp dword ptr ds:[rdx+4],0x32334C45;'  # el32   
                b'je saveBase;'                              # je to saveBase
                
                b'incImport:;'
                b'add rdi, 0x14;'                        # inc to next import
                b'jmp findImport;'                             # jmp to findImport
                # mov ; Offset for import Directory Table Name
                # ; Offset in memory    
                
                b'saveBase:;'
                b'push rdi;'
                b'jmp loadAPIs;' # jump LoadAPIs
                
                b'setBounds:;'
                b'mov edx, dword ptr [rdi + 0x10];'       # ;Point to API name
                b'add rdx, rbx;'                          # ;Adjust to in memory offset
                b'mov esi, dword ptr [rdi];'              # ;Set ESI to the Named Import base
                b'add rsi, rbx;'                          # ;Adjust to in memory offset
                b'mov rcx, rdx;'                          # ;Mov in memory offset to ecx
                b'add rcx, 0xff0000;'                     # ;Set an upper bounds for reading
                b'xor rbp, rbp;'                          # ;Zero ebp for thunk offset
                
                b'findAPI:;'
                b'mov eax, dword ptr [rsi];'              #;Mov pointer to Named Imports
                b'add rax, rbx;'                          #;Find in memory offset
                b'add rax, 2;'                            #;Adjust to ASCII name start
                b'cmp rcx, rax;'                          #;Check if over bounds
                b'jb increment;'                             #;If not over, don't jump to increment
                b'cmp rax, rdx;'                          #;Check if under Named import
                b'jb increment;'                             #;If not over, don't jump to increment
                b'mov edi, dword ptr ds:[rsp + 8];'       #;Move API name to edi
                b'cmp dword ptr [rax], edi;'              #;Check first 4 chars
                b'jne increment;'                            #;If not a match, jump to increment
                b'mov edi, dword ptr ds:[rsp + 16];'       #;Move API 2nd named part to edi
                b'cmp dword ptr [rax + 8], edi;'          #;Check next 4 chars
                b'jne increment;'                            #;If not a match, jump to increment
                b'ret;'                                   #;If a match, ret                
                
                b'increment:;'
                b'add ebp, 4;'                            # ;inc offset
                b'add rsi, 4;'                            # ;inc to next name
                b'jmp findAPI;'                              # ;jmp findAPI
                
                b'loadAPIs:;'
                # Find GPA
                b'push rdx;'                             # ;save LoadLibraryA thunk address on stack
                b'push 0x65726464;'                      # ;ddre
                b'push 0x50746547;'                      # ;Getp
                b'call setBounds;'                            # ;call setBounds
                b'add rdx, rbp;'                         # ;
                b'pop rbp;'                              # ;
                b'pop rbp;'                              # ;
                b'mov rbp, rdx;'                         # ;Move GetProcaddress thunk addr into rbx
                # GPA in RBP
                #
                b'xor rdx, rdx;'                         # ; Prep rdx
                b'mov rdx, qword ptr gs:[rdx + 0x60];'   # ; PEB
                b'mov rdx, qword ptr [rdx + 0x18];'
                b'mov rdx, qword ptr [rdx + 0x20];'
                
                b'outerloop:;'
                b'mov rsi, qword ptr [rdx + 0x50];'
                b'push 0x18;'
                b'pop rcx;'
                b'xor r9, r9;'

                b'innerloop:;'
                b'xor rax, rax;'
                b'lodsb al, byte ptr [rsi];'
                b'cmp al, 0x61;'
                b'jl uppercase;'
                b'sub al, 0x20;'
                
                b'uppercase:;'
                b'ror r9d, 0xd;'
                b'add r9d, eax;'
                b'loop innerloop;'
                b'cmp r9,0x6a4abc5b;'
                b'mov rbx, qword ptr [rdx + 0x20];'
                b'mov rdx, QWORD PTR [rdx];'
                b'jne outerloop;'
                #kernel32 handle in rbx
                b'push 0;'
                b'push 0;'
                b'mov dword ptr [rsp+0x8], 0x41797261;'
                b'mov dword PTR [rsp+0x4], 0x7262694c;'
                b'mov dword ptr [rsp], 0x64616f4c;'
                
                b'mov rdx,rsp;'                         #; mov lla string ptr to rdx
                b'mov rcx, rbx;'                        #; mov kernel32 handle to rcx
                b'sub rsp,0x20;'                        #; prep stack
                b'call qword ptr [rbp];'                #; Call GPA
                b'push rax;'                            #; push lla handle to stack
                b'mov rbx, rsp;'                        #; mov lla handle ptr to rbx
                b'add rsp, 0x40;'                       #; align the stack
                
                # LLA in RBX
                # GPA RBP
                )

    return shellcode

def loaded_lla_gpa_parser_stub_x64():
    shellcode = (
                b'int3;'               
                b'cld;'
                b'sub rsp,0x20;'
                b'push r9;'                              # Save registers
                b'push r8;'
                b'push rdx;'
                b'push rcx;'
                b'push rsi;'
                
                b'xor rdx, rdx;'                         # ; Prep rdx
                b'mov rdx, qword ptr gs:[rdx + 0x60];'   # ; PEB
                b'mov rdx, qword ptr [rdx + 0x18];'
                b'mov rdx, qword ptr [rdx + 0x20];'
                
                b'outerloop:;'
                b'mov rsi, qword ptr [rdx + 0x50];'
                b'push 0x18;'
                b'pop rcx;'
                b'xor r9, r9;'

                b'innerloop:;'
                b'xor rax, rax;'
                b'lodsb al, byte ptr [rsi];'
                b'cmp al, 0x61;'
                b'jl uppercase;'
                b'sub al, 0x20;'
                
                b'uppercase:;'
                b'ror r9d, 0xd;'
                b'add r9d, eax;'
                b'loop innerloop;'
                b'cmp r9d, 0xc78a43f4;' # change for testing
                b'mov rbx, qword ptr [rdx + 0x20];'
                b'mov rdx, QWORD PTR [rdx];'
                b'jne outerloop;'
                #dll handle in rbx
                
                #IAT Parser
                b'mov rdx, rbx;'                         #; DLL imagebase
                b'mov eax, dword ptr [rdx + 0x3c];'      #; Splitting 4 byte memory "PE"
                b'add rdx, rax;'                         #; "PE"
                
                b'mov edi, dword ptr [rdx + 0x90];'      #; Import Table RVA
                b'add rdi, rbx;'                         #; Import table in memory offset   
                
                b'findImport:;'
                b'mov edx, dword ptr [rdi + 0xc];'       # Offset for Import Directory Table Name RVA  NEED TO TEST
                b'add rdx, rbx;'                         # Offset in memory
                b'cmp dword ptr [rdx], 0x4e52454b;'      # cmp kern
                b'jne incImport;'                             # jmp short to increment 14
                b'cmp dword ptr ds:[rdx+4],0x32334C45;'  # el32   
                b'je saveBase;'                              # je to saveBase
                
                b'incImport:;'
                b'add rdi, 0x14;'                        # inc to next import
                b'jmp findImport;'                             # jmp to findImport
                # mov ; Offset for import Directory Table Name
                # ; Offset in memory    
                
                b'saveBase:;'
                b'push rdi;'
                b'jmp loadAPIs;' # jump LoadAPIs
                
                b'setBounds:;'
                b'mov edx, dword ptr [rdi + 0x10];'       # ;Point to API name
                b'add rdx, rbx;'                          # ;Adjust to in memory offset
                b'mov esi, dword ptr [rdi];'              # ;Set ESI to the Named Import base
                b'add rsi, rbx;'                          # ;Adjust to in memory offset
                b'mov rcx, rdx;'                          # ;Mov in memory offset to ecx
                b'add rcx, 0xff0000;'                     # ;Set an upper bounds for reading
                b'xor rbp, rbp;'                          # ;Zero ebp for thunk offset
                
                b'findAPI:;'
                b'mov eax, dword ptr [rsi];'              #;Mov pointer to Named Imports
                b'add rax, rbx;'                          #;Find in memory offset
                b'add rax, 2;'                            #;Adjust to ASCII name start
                b'cmp rcx, rax;'                          #;Check if over bounds
                b'jb increment;'                             #;If not over, don't jump to increment
                b'cmp rax, rdx;'                          #;Check if under Named import
                b'jb increment;'                             #;If not over, don't jump to increment
                b'mov edi, dword ptr ds:[rsp + 8];'       #;Move API name to edi
                b'cmp dword ptr [rax], edi;'              #;Check first 4 chars
                b'jne increment;'                            #;If not a match, jump to increment
                b'mov edi, dword ptr ds:[rsp + 16];'       #;Move API 2nd named part to edi
                b'cmp dword ptr [rax + 8], edi;'          #;Check next 4 chars
                b'jne increment;'                            #;If not a match, jump to increment
                b'ret;'                                   #;If a match, ret                
                
                b'increment:;'
                b'add ebp, 4;'                            # ;inc offset
                b'add rsi, 4;'                            # ;inc to next name
                b'jmp findAPI;'                              # ;jmp findAPI
                
                b'loadAPIs:;'
                b'push 0x41797261;'                      # ;aryA (notice the 4 char jump between beginni
                b'push 0x64616f4c;'                      # ;Load
                b'call setBounds;'                            # ;call setBounds
                b'add rdx, rbp;'                         # ;In memory offset of API thunk
                b'add rsp, 0x10;'                           # ;Move stack to import base addr
                b'pop rdi;'                              # ;restore import base addr for parsing;'
                #add rest here
                b'push rdx;'                             # ;save LoadLibraryA thunk address on stack
                b'push 0x65726464;'                      # ;ddre
                b'push 0x50746547;'                      # ;Getp
                b'call setBounds;'                            # ;call setBounds
                b'add rdx, rbp;'                         # ;
                b'pop rbp;'                              # ;
                b'pop rbp;'                              # ;
                b'pop rbx;'                              # ;Pop LoadlibraryA thunk addr into rbx
                b'mov rbp, rdx;'                         # ;Move GetProcaddress thunk addr into rbx
                # LLA in RBX
                # GPA RBP
                       
        )

    return shellcode 

def loaded_gpa_iat_parser_stub():
    shellcode = (
                b'int3;'               
                b'cld;'
                b'sub rsp,0x20;'
                b'push r9;'                              # Save registers
                b'push r8;'
                b'push rdx;'
                b'push rcx;'
                b'push rsi;'
                
                b'xor rdx, rdx;'                         # ; Prep rdx
                b'mov rdx, qword ptr gs:[rdx + 0x60];'   # ; PEB
                b'mov rdx, qword ptr [rdx + 0x18];'
                b'mov rdx, qword ptr [rdx + 0x20];'
                
                b'upperloop:;'
                b'mov rsi, qword ptr [rdx + 0x50];'
                b'push 0x18;'
                b'pop rcx;'
                b'xor r9, r9;'

                b'innerupperloop:;'
                b'xor rax, rax;'
                b'lodsb al, byte ptr [rsi];'
                b'cmp al, 0x61;'
                b'jl uppercase;'
                b'sub al, 0x20;'
                
                b'uppercase:;'
                b'ror r9d, 0xd;'
                b'add r9d, eax;'
                b'loop innerupperloop;'
                b'cmp r9d, 0xc78a43f4;' # change for testing
                b'mov rbx, qword ptr [rdx + 0x20];'
                b'mov rdx, QWORD PTR [rdx];'
                b'jne upperloop;'
                #dll handle in rbx
                #IAT Parser
                b'mov rdx, rbx;'                         #; DLL imagebase
                b'mov eax, dword ptr [rdx + 0x3c];'      #; Splitting 4 byte memory "PE"
                b'add rdx, rax;'                         #; "PE"
                
                b'mov edi, dword ptr [rdx + 0x90];'      #; Import Table RVA
                b'add rdi, rbx;'                         #; Import table in memory offset   
                
                b'findImport:;'
                b'mov edx, dword ptr [rdi + 0xc];'       # Offset for Import Directory Table Name RVA  NEED TO TEST
                b'add rdx, rbx;'                         # Offset in memory
                b'cmp dword ptr [rdx], 0x4e52454b;'      # cmp kern
                b'jne incImport;'                             # jmp short to increment 14
                b'cmp dword ptr ds:[rdx+4],0x32334C45;'  # el32   
                b'je saveBase;'                              # je to saveBase
                
                b'incImport:;'
                b'add rdi, 0x14;'                        # inc to next import
                b'jmp findImport;'                             # jmp to findImport
                # mov ; Offset for import Directory Table Name
                # ; Offset in memory    
                
                b'saveBase:;'
                b'push rdi;'
                b'jmp loadAPIs;' # jump LoadAPIs
                
                b'setBounds:;'
                b'mov edx, dword ptr [rdi + 0x10];'       # ;Point to API name
                b'add rdx, rbx;'                          # ;Adjust to in memory offset
                b'mov esi, dword ptr [rdi];'              # ;Set ESI to the Named Import base
                b'add rsi, rbx;'                          # ;Adjust to in memory offset
                b'mov rcx, rdx;'                          # ;Mov in memory offset to ecx
                b'add rcx, 0xff0000;'                     # ;Set an upper bounds for reading
                b'xor rbp, rbp;'                          # ;Zero ebp for thunk offset
                
                b'findAPI:;'
                b'mov eax, dword ptr [rsi];'              #;Mov pointer to Named Imports
                b'add rax, rbx;'                          #;Find in memory offset
                b'add rax, 2;'                            #;Adjust to ASCII name start
                b'cmp rcx, rax;'                          #;Check if over bounds
                b'jb increment;'                             #;If not over, don't jump to increment
                b'cmp rax, rdx;'                          #;Check if under Named import
                b'jb increment;'                             #;If not over, don't jump to increment
                b'mov edi, dword ptr ds:[rsp + 8];'       #;Move API name to edi
                b'cmp dword ptr [rax], edi;'              #;Check first 4 chars
                b'jne increment;'                            #;If not a match, jump to increment
                b'mov edi, dword ptr ds:[rsp + 16];'       #;Move API 2nd named part to edi
                b'cmp dword ptr [rax + 8], edi;'          #;Check next 4 chars
                b'jne increment;'                            #;If not a match, jump to increment
                b'ret;'                                   #;If a match, ret                
                
                b'increment:;'
                b'add ebp, 4;'                            # ;inc offset
                b'add rsi, 4;'                            # ;inc to next name
                b'jmp findAPI;'                              # ;jmp findAPI
                
                b'loadAPIs:;'
                b'push rdx;'                             # ;save LoadLibraryA thunk address on stack
                b'push 0x65726464;'                      # ;ddre
                b'push 0x50746547;'                      # ;Getp
                b'call setBounds;'                            # ;call setBounds
                b'add rdx, rbp;'                         # ;
                b'pop rbp;'                              # ;
                b'pop rbp;'                              # ;
                b'mov rbp, rdx;'                         # ;Move GetProcaddress thunk addr into rbx
                # GPA in RBP
                #
                b'xor rdx, rdx;'                         # ; Prep rdx
                b'mov rdx, qword ptr gs:[rdx + 0x60];'   # ; PEB
                b'mov rdx, qword ptr [rdx + 0x18];'
                b'mov rdx, qword ptr [rdx + 0x20];'
                
                b'outerloop:;'
                b'mov rsi, qword ptr [rdx + 0x50];'
                b'push 0x18;'
                b'pop rcx;'
                b'xor r9, r9;'

                b'innerloop:;'
                b'xor rax, rax;'
                b'lodsb al, byte ptr [rsi];'
                b'cmp al, 0x61;'
                b'jl uppercase2;'
                b'sub al, 0x20;'
                
                b'uppercase2:;'
                b'ror r9d, 0xd;'
                b'add r9d, eax;'
                b'loop innerloop;'
                b'cmp r9,0x6a4abc5b;'
                b'mov rbx, qword ptr [rdx + 0x20];'
                b'mov rdx, QWORD PTR [rdx];'
                b'jne outerloop;'
                #kernel32 handle in rbx
                b'push 0;'
                b'push 0;'
                b'mov dword ptr [rsp+0x8], 0x41797261;'
                b'mov dword PTR [rsp+0x4], 0x7262694c;'
                b'mov dword ptr [rsp], 0x64616f4c;'
                
                b'mov rdx,rsp;'                         #; mov lla string ptr to rdx
                b'mov rcx, rbx;'                        #; mov kernel32 handle to rcx
                b'sub rsp,0x20;'                        #; prep stack
                b'call qword ptr [rbp];'                #; Call GPA
                b'push rax;'                            #; push lla handle to stack
                b'mov rbx, rsp;'                        #; mov lla handle ptr to rbx
                b'add rsp, 0x70;'                       #; align the stack

                # LLA in RBX
                # GPA RBP
                       
        )

    return shellcode 


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage:", sys.argv[0], 'fileout.bin', 'MODE (x86 or x64)'
        sys.exit(-1)

    if sys.argv[2] == 'x86':
        KSMODE = KS_MODE_32
        CSMODE = CS_MODE_32
    elif sys.argv[2] == 'x64':
        KSMODE = KS_MODE_64
        CSMODE = CS_MODE_64
    else:
        print("Must have a mode (x86 or x64)")
        sys.exit(-1)
    
    shellcode = gpa_parser_stub_x64()
    try:
        ks = Ks(KS_ARCH_X86, KSMODE)
        encoding, count = ks.asm(shellcode)
        #print("%s = %s (number of statements: %u)" %(shellcode, encoding, count))
        #print(type(encoding))
        #for i in encoding:
        #     print("%02x" % i)
    except KsError as e:
        print("ERROR: %s" % e)
    somecode = array.array('B', encoding).tostring()
    open(sys.argv[1], 'wb').write(somecode)
    
    md = Cs(CS_ARCH_X86, CSMODE)
    for insn in md.disasm(somecode, 0):
        width = 50 - len(''.join('\\x{:02x}'.format(x) for x in insn.bytes))
        print("%s:\t\"%s\" %s %s %s" % (hex(insn.address).strip('L'), ''.join('\\x{:02x}'.format(x) for x in insn.bytes), '#'.rjust(width), insn.mnemonic, insn.op_str))


    
