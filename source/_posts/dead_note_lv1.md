---
title: ISITDTU CTF 2018 Quals
date: 2018-07-31 08:37:40
tags: [CTF, PWN]
categories: ISITDTU_CTF
---
# ISITDTU CTF 2018 Quals

## dead_note_lv1 wp

​	拿到题目扔ida一看发现在check的时候没有考虑考虑全面导致输入的index可以为负数，这样就能够导致数组下标越界，引发一些问题，比如用户可以通过构造的index进行覆写got表执行任意指令.但是比较麻烦的是这里只允许用户输入三个字节，超过三个字节输入程序会报big size，输入的数据将不会被写入内存.
<!--more-->
	然而此时用户已经可以覆写got表了，由于程序是用strlen进行长度判断，那么将strlen函数的got表复写成指定指令，使存储长度的rax寄存器为0就行了，这里可以使用例如xor eax,eax的指令.当复写strlen的got为xor eax,eax后，程序将认为用户输入长度为0，小于三，这个坑就算绕过了.然而程序允许用户输入的长度总共也就8字节，也就是说用户最多一次只能执行8字节的指令.8字节的shellcode我是没有找到,所以这里换一下思路,不直接执行指令,而是通过构造执行buff区的shllcode.接下来我们看到strdup函数,看到这个函数有一个参数保存在rdi中,而这个rdi就是用户输入的内存空间指针.此时我们只要复写strdup为call rdi就能够执行buff区的shllcode了.
	脚本写好后发现无法getshell,而本地又开了pie,想调试又比较烦,emmm,有点僵.先放着等以后再填坑.

扔个链接：https://ctftime.org/task/6341