---
title: LLVM初探
data:
tags: [编译器, 总结, 虚拟机]
categories: 虚拟机
---
## 0x01 LLVM简介  
>The LLVM Project is a collection of modular and reusable compiler and toolchain technologies.  

LLVM是模块化、可重用的编译器以及工具链的集合，有些人把LLVM当成是一个低层的虚拟机(low level virtual machine)，但官方给出的解释是这样的:  
>The name "LLVM" itself is not an acronym; it is the full name of the project.  

也就是说LLVM并不是一个缩写，而是整个项目的全名。  
LLVM和传统的编译器(GCC)是有差别的  
### 传统的编译器架构
![image](./传统编译器架构.jpg)  

传统的编译器架构主要分为三个部分  
- Frontend:前端  
包括词法分析、语法分析、语义分析、中间代码生成
- Optimizer:优化器  
主要是对编译前端对生成的中间代码的优化  
- Backend:后端  
翻译中间代码为native机器码

### LLVM编译器架构
![image](./LLVM编译器架构.jpg)  

LLVM编译器套件与传统编译器架构的不同之处主要在于  
- LLVM编译器的前端其它层(优化器、后端)是分离的，LLVM专门有一个Clang子项目用来对源码进行编译，生成IR(intermediate representation)中间字节码;而传统编译器的代表(GCC)由于编译前后端耦合度太高，增加一个前端语言支持或者一个后端平台支持将会变得异常复杂。相比之下LLVM由于是分离式架构，其组件复用性就很高，增加语言/平台支持也相对容易，增加一个新的编程语言，就增加一个新的前端组件，增加一个新的平台支持，就增加一个新的后端组件。  
- LLVM编译器不同的前端统一使用相同的中间码，不像GCC有各种风格(intel&ATT)  
- LLVM经常被用于一些解释型语言的动态编译(优化)。类似的JAVA虚拟机(JVM)的JIT(好像现在就有厂在做基于LLVM的JAVA JIT编译器，负责将高层字节码(java-bytecode)解析成相对底层的IR中间码，之后编译成相应平台的机器码执行。  
- LLVM也经常被用于一些语言的静态编译，类似的Objective-c就是使用Clang进行编译(之前其实也是使用GCC的,但现在连Xcode的内置编译器都换成Clang了)，据说编译时间是GCC的1/3，语法树占用内存是GCC的1/5，而且诊断信息可读性强，不像GCC是一大坨不容易识别的那种。  

## 0x02 狭义的LLVM和广义的LLVM  

![image](./LLVM架构.png)  

广义的LLVM通常指LLVM编译器的整体架构，而狭义的LLVM通常指不包含前端，只实现中间代码优化和native码生成的部分。IR中间码需要多个pass进行一系列优化后再进行翻译。  


## 0x03 字节码抽象层次  
比较典型的就是java bytecode与LLVM IR之间的抽象层次比较，java bytecode与LLVM IR都是用于描述代码运算的模型，但两者的抽象层次是不同的。之前想过一个问题，就是为什么编译器/虚拟机需要引入中间码/字节码，现在大概可以理解，源码通过编译前端语法分析后生成抽象语法树(AST),问题出现了，只是抽象语法树的话，编译器并不理解编码者的代码用意，也就不好直接通过语法树翻译可执行代码，所以才引入了一个虚拟层，对语法树进行归纳，用一种更低层级的代码(字节码)来表示，这样编译器后端就能更轻松的去解析代码，最终生成可执行代码。为什么说java的bytecode层级要高一点呢，因为java的字节码的语义和java语言的语法结构有非常直接的对应关系，包含大量的(类java的)面向对象语言的高层操作，例如虚函数，接口方法调用。说直白点，光看java字节码你就能看出这是java写的；而LLVM的IR相对来说更底层，没有暴露具体平台/语言的相关特征，所以可以理解成一种中层IR，层级比java的bytecode是要低的。  


## 0x04 OLLVM  
LLVM前端是Clang，当对源代码进行编译生成IR中间码以后，优化器会对IR进行优化，然后后端生成执行代码。试想一下如果IR进行优化的过程可控，那么LLVM编译后端生成的代码也会是可控的，基于这个原理，OLLVM应运而生，做法就是基于LLVM开发一些pass来对IR进行优化(修改)，然后控制生成的机器码。OLLVM本身只支持源码&中间码加固，它的保护是基于代码级别的；如果想要做基于二进制的OLLVM加固，需要首先通过反汇编引擎(类似的有capstone)把二进制程序指令抽出，并转为自己的虚拟指令，VMP代码虚拟化保护就是做的类似的工作，这种保护模式需要对指令进行抽取分析转换再植入，难度较大，对于代码混淆来说，基于LLVM对IR进行处理就行了。  
下面是一些用于混淆的成熟开源项目，打算之后来一波源码分析。  

[OLLVM](https://github.com/obfuscator-llvm/obfuscator)  
[Hikari](https://github.com/HikariObfuscator/Hikari)  
[Armariris(孤挺花)](https://github.com/GoSSIP-SJTU/Armariris)  

### 1、编译  
OLLVM项目中集成了LLVM，所以不需要单独安装LLVM环境，这边参照官网的说明进行编译安装。一开始用的是最新版的LLVM(version--4)，发现编译报错，果断换了一个低一点的版本，发现编译可以继续了。      
![image](./编译.png)  

这边有个坑，编译的时候说xxx已经存在，看dalao博客找到的编译选项，可以正常编译  
>cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_INCLUDE_TESTS=OFF ../obfuscator/  

然后就是缓慢的编译过程。。。。。。  

![image](./等待.png)  

orz.........焦灼  
编译到百分之三十多的时候，突然进度条就卡住了，然后编译过程崩溃，查了一下好像是内存分配的太少了，导致进程卡死，于是给虚拟机加了两个G，继续编译，发现报错:  
>g++: internal compiler error: Killed (program cc1plus)

查了下资料发现还是内存不足。。。。(我都给了四个G了) 解决方法是加一个临时的交换分区  
```
sudo dd if=/dev/zero of=/swapfile bs=64M count=16  
sudo mkswap /swapfile  
sudo swapon /swapfile  
After compiling, you may wish toCode:  
sudo swapoff /swapfile  
sudo rm /swapfile

```

最后不容易终于编译成功了，build/bin目录下生成了编译前端  

![image](./编译成功.png)  

### 2、混淆参数  
OLLVM有一些混淆参数，类似的有字符串加密、控制流扁平化、指令替换、控制流伪造等等  

1、控制流扁平化  
>clang -mllvm -fla test.c -o test1  

2、指令替换  
>clang -mllvm -sub test.c -o test2  

3、控制流伪造    
>clang -mllvm -bcf test.c -o test3  

对比一下混淆编译之后的可执行文件大小  

![image](./比较.png)  

在文件比较小的情况下好像差别并不明显2333333，OLLVM牛逼(滑稽)。  

### 3、混淆效果  
先贴一下test.c的源码    
![image](./源码.png)  

在ida里面看一下混淆以后的效果  
  
![image](./test1对比test.png)  

右边是开启控制流扁平化以后的程序的ida视图，左边是未添加编译保护的程序的控制流图  

![image](./常量替换.png)  

可以看到程序逻辑至少复杂了一个量级，而且一些常量被替换了，导致分析起来也觉得难以理解。OLLVM牛逼！！！  

## 0x05 总结  
这篇文章只是记录了一下学习LLVM&OLLVM的过程，其实说实话并没有进行比较详细的分析，还有一些拓展面也没有想好怎么写，等下次再填坑吧。  
