---
title: IdaPython使用小结
date: 2019-4-11 00:18:51
tags: [Tools, IDA]
categories: Tools
---

## 0x01 介绍    

IdaPython是ida内置的一个强大工具，可以自动化处理繁琐的逆向工程任务。之前一直觉得IdaPython太过小众，一直没有去学习相关的操作，最近才有时间了解了个大概，这边做一个小小的总结。  

IdaPython和IDC同样都是利用Ida的api进行自动化操作的工具，其中IdaPython基于Python，而IDC是基于C的。  

IdaPython在2004年被开发出来，其目的是为了将Python简洁的语法和Ida支持的IDC语言结合起来。  

IdaPython由三个独立的模块组成：    

- idc：这个是兼容idc函数的模块  
- idautils：这是ida中一个高级实用模块  
- idaapi：允许使用者通过类似的形式，访问更多的底层数据  

IdaPython命名采用“驼峰命名法”，函数名称类似”GetFunctionName“这种，一个函数名中每个单词的开头一个字符大写，看起来就像是骆驼的驼峰一样，这就是这个命名的由来。  



## 0x02 功能  

IdaPython可以通过基于capstone反汇编引擎的api实现函对二进制程序进行跟踪，其可以细粒度到指令、寄存器级别，加深我们对程序的理解。  

常见的功能比如：  

> 指令处理

1、获取当前指令地址  

ea=here() 

print hex(ea)

2、获取当前汇编指令

idc.GetDisasm(ea)

3、获取当前处于的段

idc.SegName()



> 函数操作

1、获取所有函数的名称：

```
for func in idautils.Functions():

	print hex(func),idc.GetFunctionName(func)
```

2、计算当前函数指令数：

```
ea=here()
len(list(idautils.FuncItems(ea)))
```



> 指令操作

1、给定地址，打印指令：

`idc.GetDisasm(ea)`

2、	对汇编指令进行拆解：

`idc.GetMnem：获取指令操作数`



> 交叉引用

1、指令From/To：

`idautils.CodeRefsTo(here(),0)：指令来自`

`idautils.CodeRefsFrom(here(),0)：指令目的`

2、数据From/To：

`idautils.DataRefsTo(here(),0) ：数据来自`

`idautils.DataRefsFrom(here(),0) ：数据目的`





## 0x03 动动手  

### 3.1 快捷键使用  

- 运行Ida脚本文件：(Alt+F7)

- 查看现有的Ida脚本文件：(Alt+F9)  

- 使用Ida内置的脚本命令行：(Shift+F2)  

  

### 3.2 代码测试  

现在的IdaPython常被用于程序危险函数查找，这边贴一下实例脚本  

```
#coding:utf-8
from idaapi import *

# 设置颜色
def judgeAduit(addr):
    '''
    not safe function handler
    '''
    MakeComm(addr,"### AUDIT HERE ###")
    SetColor(addr,CIC_ITEM,0x0000ff)  #set backgroud to red
    pass

# 函数标识  
def flagCalls(danger_funcs):
    count = 0
    for func in danger_funcs:      
        faddr = LocByName( func )     
        if faddr != BADADDR: 
            # Grab the cross-references to this address         
            cross_refs = CodeRefsTo( faddr, 0 )                       
            for addr in cross_refs:
                count += 1 
                Message("%s[%d] calls 0x%08x\n"%(func,count,addr))  
                judgeAduit(addr)
                    
if __name__ == '__main__':
    '''
    handle all not safe functions
    '''
    print "-------------------------------"
    # 列表存储需要识别的函数
    danger_funcs = ["free","strcpy","sprintf","strncpy"] 
    flagCalls(danger_funcs)
    print "-------------------------------"
```



###  

### 3.3 其它  

这边贴一下IdaPython的一些学习站点，包括文档等

[官方文档](https://www.hex-rays.com/products/ida/support/idapython_docs/ )

[常用IdaPython指令](https://www.cnblogs.com/0xHack/p/9399321.html)

[Using IDAPython to Make Your Life Easier](https://unit42.paloaltonetworks.com/using-idapython-to-make-your-life-easier-part-1/)

etc



## 0x04 待续





