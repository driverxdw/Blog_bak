---
title: AFL-Fuzz技术初探
data:
tags: [Fuzz, 总结]
categories: Fuzz
---
## 0x01 AFL-Fuzz介绍
模糊测试(Fuzzing)技术作为漏洞挖掘最有效的手段之一，近年来一直是众多安全研究员发现漏洞的首选技术。AFL-Fuzz、LibFuzzer、honggFuzz等操作简单友好的工具相继出现，大大降低了漏洞挖掘的门槛。AFL(American Fuzzy Lop)是由安全研究员Michał Zalewski（@lcamtuf）开发的一款基于覆盖引导(Coverage-guided)的模糊测试工具，它通过记录输入样本的代码覆盖率，从而调整输入样本以提高覆盖率，增加发现漏洞的概率。AFL-Fuzz通过在相关代码处进行插桩，来对程序内部的执行路径进行探索，挖掘可能存在的漏洞如栈溢出、堆溢出、UAF、DOUBLEFREE等等，由于要对程序进行插桩，所以AFL-Fuzz主要用于对开源软件进行测试，当然配合QEMU等工具也可以对闭源代码进行Fuzzing，不过执行效率会受影响。  
组成：
- 编译器wrapper，该部分用于编译目标代码(afl-gcc、afl-clang等)
- Fuzzer：afl-fuzz，fuzzing的主要工具
- afl-cmin、afl-tmin等

工作流程：
- 从源码编译程序时进行插桩，以记录代码覆盖率(Code Coverage)
- 选择测试文件作为初始测试集加入队列
- 对队列中的样本文件进行变化，生成大量样本
- 如果变异文件更新了覆盖范围，将其留在队列中，否则舍弃
- 上述过程会一直循环，直到程序出现Crash，Crash的文件会被记录下来  

![image](./工作流程.jpg)  

## 0x02 安装
直接去官网上下载源码编译安装
>make  
>sudo make install  

输入afl能补全的话就是安装完成了  
![iamge](./安装完成.png)

## 0x03 语料库的选择
AFL需要一些初始输入数据(种子文件)，作为fuzzing的起点，afl可以根据自己的算法生成相应的文件格式，就算输入数据毫无意义，lcamtuf就在其官网上给出例子：对djpeg进行fuzzing的时候，仅输入一个hello字符串，而fuzzer自动生成了大量的jpeg样本。虽然fuzzer本身的生成算法很强大，但是为了提高afl的fuzz速度，探索更多的有效路径，选择一个高质量的语料库是有必要的。  
[AFL-Fuzz官网下的测试集](http://lcamtuf.coredump.cx/afl/demo/)  
其它一些开源的语料库：  
[Fuzzer-test-suite](https://github.com/google/fuzzer-test-suite)  
[Samples-libav](https://samples.libav.org/)  
[Samples-ffmpeg](http://samples.ffmpeg.org/)  
[FuzzData](https://github.com/MozillaSecurity/fuzzdata)  
[MoonLight](https://gitlab.anu.edu.au/lunar/moonlight)  

语料库中通常包含有大量文件，这时需要对其进行精简，专业术语叫做"语料蒸馏"。Afl-Fuzz提供了两个工具  

(1)移除执行相同代码的输入文件----afl-cmin  
afl-cmin目的是尝试找到语料库全集在此程序执行不同路径的最小子集。一个大的语料库对测试程序来说很可能存在多个不同文件执行了相同代码，探索了相同的路径，afl-cmin就是对此进行精简，舍弃相同执行路径的测试集。  

(2)减小单个输入文件的大小----alf-tmin  
整体大小得到改善以后，需要对单个文件进行更细化的处理，舍弃单个文件中的部分数据，提高afl-fuzz的执行速度。  

## 0x04 源码插桩编译  
由于需要对源码进行插桩，所以这里需要更换程序编译器为AFL-Fuzz自带的afl-gcc/afl-g++
> $ ./configure CC="afl-gcc" CXX="afl-g++"  

或者修改MakeFile也是可以的。  

Afl-Fuzz还有一个llvm模式，可以通过优化代码提高Fuzz速度。  

## 0x05 开始Fuzzing  
这边选用了一个libtiff的历史版本来进行测试，首先编译，发现生成了一些可执行程序  
![image](./lib2tiff编译.png)  

建立输入输出文件夹，将AFL官网语料库中的bmp文件库集合放到input文件夹下作为输入，然后输入命令进行fuzz  
![image](./fuzz命令.png)  

如果fuzz的程序是从标准输入获取的，那么这边不需要@@，如果是从文件进行读取的，这边需要用@@进行一个替换。  

这边报错了  
![image](./报错.png)  
设置一下core转储路径  
>sudo su  
>echo core >/proc/sys/kernel/core_pattern  

这边又报错了  
![iamge](./报错2.png)  
看了下好像bmp2tiff用到了so库，由于没有对so库进行插桩，所以这边出现了错误。解决方法有两个：  
- 静态构建  
./configure后面跟--disable-shared参数
- 指定插桩过的so库  
通过设置LD_LIBRARY_PATH让程序加载插桩过的so库  

这边直接静态构建，之后Fuzz发现能跑起来了。  

## 0x06 AFL窗口状态  
![image](./界面.png)  
这边对窗口内容进行一下介绍：  
- process timing  
Fuzzer运行时长、距离最近发现的路径、上一个崩溃和挂起经历了多长世间。这边要注意如果输入参数有错误的话，执行路径是一直不会变而且会提醒你syntax error的  
![image](./参数错误.png)  

- overall results  
从上至下依次是程序执行的总周期数、总路径数、崩溃次数和超时次数  

- cycle progress  
已经处理的输入队列中的文件数  

- map coverage  
插桩代码记录下的覆盖率  

- stage progress  
Fuzzer正在执行的文件变异策略、总的执行文件大小、执行速度  

- findings in depth
有关我们找到的执行路径、总崩溃数等  

这边[官网](http://lcamtuf.coredump.cx/afl/status_screen.txt)有详述。 

## 0x07 Crash  
可以看到AFL在output文件夹下生成了crash和hangs的样本  
![image](./崩溃.png)  
拿到样本以后可以动态调试走一波，找到崩溃点，看能否进行利用。  
这边有个相关的内存检测框架Valgrind，它能根据提供的样本进行异常检测，并将漏洞类型和产生漏洞的地址进行输出，测试者可以直接定位。  

## 0x08 黑盒  
AFL也支持无源码插桩，这边利用了qemu进行动态二进制插桩，看dalao博客的解释有点类似JIT，贴一下回去慢慢理解  

```
这是因为QEMU使用basic blocks作为翻译单元，利用QEMU做instrumentation，启动很慢的QEMU mode同样使用了一个fork server，和编译期一样，通过把一个已经初始化好的进程镜像，直接拷贝到新的进程中。
所以相当于第一次翻译一个新的basic block，这肯定会有必要的延迟，为了解决这个问题AFL forkserver在emulator和父进程之间提供了一个信息管道。
这个信息管道用来通知父进程新添加的blocks的地址，之后把这些blocks放到一个缓存中，以便直接复制到将来的子进程中。
但这样处理之后，QEMU模式对目标程序造成2-5倍的减速。
```

无源码状态下二进制程序的Fuzz首先需要安装QEMU虚拟机，Fuzz的时候著需要增加-Q选项就能在qemu模式下进行fuzzing了。  
>$ afl-fuzz -Q -i input -o output /path/to/program [params] @@  

## 0x09 总结  
听说跑Fuzz烧硬盘，阔怕，以后得上服务器跑了23333333  

基本就是这样子了，希望能早日挖到属于自己的洞，拿到属于自己的CVE号~  

队友：醒醒，该敲代码了!!!