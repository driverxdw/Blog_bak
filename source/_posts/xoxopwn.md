---
title: ISITDTU CTF 2018 Quals
date: 2018-07-31 08:37:40
tags: [CTF, PWN]
categories: ISITDTU_CTF
---
# ISITDTU CTF 2018 Quals 

## xoxopwn wp

​	看题目只给了一个服务器ip和端口考虑到是盲打，连上去看一下发现好像是一道python沙盒逃逸。常见的语法都被过滤了，使用常见的python内置函数和类试图去发现指定路径下的文件发现沙盒都是显示代码太长了，于是直接__file__显示当前引用文件的内容，发现dump出的应该就是题目。
题目如下：
<!--more-->
```
import socket

import threading

import SocketServer

host, port = '0.0.0.0', 9999

def o(a):

	secret = "392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09"

	secret = secret.decode("hex")

	key = "pythonwillhelpyouopenthedoor"

	ret = ""

	for i in xrange(len(a)):

		ret += chr(ord(a[i])^ord(key[i%len(a)]))

	if ret == secret:

		print "Open the door"

	else:

		print "Close the door"

def x(a):

	xxx = "finding secret in o()"

	if len(a)>21:

		return "Big size ~"

	#print "[*] ",a

	return eval(a)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):

    allow_reuse_address = True

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):

    def handle(self):

    	self.request.sendall("This is function x()")

        self.request.sendall(">>> ")

        self.data = self.request.recv(1024).strip()

        print "{} wrote: {}".format(self.client_address[0],self.data)

        ret = x(str(self.data))

        self.request.sendall(str(ret))

if name == "main":

	serverthuong123 = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)

	server_thread = threading.Thread(target=serverthuong123.serve_forever)

	server_thread.daemon = True

	server_thread.start()

	print "Server loop running in thread:", server_thread.name

	server_thread.join()

```

​	

​	发现如果输入长度超过21就会显示big size。
一个很简单的单字节异或，解密脚本如下:

```
secret="392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09".decode("hex")

key = "pythonwillhelpyouopenthedoor"

result = ""

for i in xrange(len(secret)):

        result += chr(ord(secret[i]) ^ ord(key[i % len(key)]))

print result

```