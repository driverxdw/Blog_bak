---
title: 基于Python-flask的一次性口令认证系统
data:
tags: [开发, Python]
categories: Python
---

## 0x00  锲子

女友老师布置的作业，写一个一次性口令认证系统，要有图形界面，实现架构不限，最好是用C/S模式，实现语言不限。

看着女友扑闪扑闪的眼睛+委屈巴巴的眼神。。。。。。

只想骂一句：你这该死的甜美~ 

丢~

## 0x01  简介

#### 1.1  固定口令

现在很多网站上的密码都是明文存储的，这种以固定口令进行认证的方式存在很多问题，很容易受到恶意攻击。

![](./1.png)  

常见的有以下几种：

- 网络数据流窃听(Sniffer)：
  - 由于认证信息要通过网络传递，并且很多认证系统的口令是未经加密的明文，攻击者通过窃听网络数据很容易就能分辨出特定系统的认证数据，并且提取出用户名和口令。
- 认证信息截取/重放(Record/Replay):
  - 有的系统会将认证信息进行简单的加密后传输，如果攻击者不能直接窃取到明文用户名和口令，则可以通过重放攻击，发送一个目的主机已经接收过的包来欺骗服务器。  
- Hash破解：
  - 一些系统会获取密码的hash值存储，这种存储方式依旧是不安全的。由于hash加密是单向的，一些网站存储了hash值与其对应的密码；而且目前如MD系列算法已经有人公开说可以破解了。  
- 字典攻击：
  - 弱口令字典爆破
- 社交工程

#### 1.2  一次性口令

为了解决以上的这些问题，安全专家提出了一次性口令（OTP：One Time Password）的密码体制，以保护关键数据。

OTP的主要思路是在登陆过程中加入不确定因素，使得每次登陆过程中传送的信息都不同，以提高登陆过程的安全性。  

例如：登陆密码=MD5（username+password+time），系统接到后做一个简单的验算即可验证用户的合法性。  

这样的话，由于每次登陆的信息都不同，hacker就无法获取到关键信息。  

口令序列(S/KEY) ：  

口令为一个单向的前后相关的序列，系统只用记录第 N个口令。用户用第N－1个口令登录时，系统用单向算法算出第N个口令与自己保存的第N个口令匹配，以判断用户的合法性。由于N是有限的，用户登录N次后必须重新初始化口令序列。  

挑战/回答(CRYPTOCard)：  

用户要求登录时，系统产生一个随机数发送给用户。用户用某种单向算法将自己的秘密口令和随机数混合起来发送给系统，系统用同样的方法做验算即可验证用户身份。  



## 0x02  一次性口令の鉴别流程

1、用户发出注册请求

2、服务器随机生成(R,N)发送

3、用户计算H<sup>N+1</sup>(PW||R)，将H<sup>N+1</sup>(PW||R)以及用户ID发送给服务器

4、服务器将用户ID和H<sup>N+11</sup>(PW||R)存储在服务器中

5、用户发出认证请求(用户ID)

6、根据ID查找(N,R)，将其发送挑战(N,R)

7、客户端计算H<sup>N</sup>(PW||R)应战值发送

8、服务端对应战值再进行一次hash算法得到H(H<sup>N</sup>(PW||R))，和之前存储的H<sup>N+1</sup>(PW||R)进行对比，若相等，则认证成功，服务器将H<sup>N+1</sup>(PW||R)替换成H<sup>N</sup>(PW||R)，即N=N-1，若失败，则不变

9、当客户端再一次认证时，服务端将(N-1,R)发送给客户端，重复`7、8`过程。当N=1时，重置N1并更新R1，发送给客户端，客户端再发送H<sup>N</sup>1(PW||R1)给服务端，服务端更新H<sup>N1+1</sup>(PW||R1)，重复以上过程



![](./2.png)  





## 0x03  编码实现

![](./3.png)  

由于这边并没有刚需，所以只是大概把功能实现了一下。

整个项目按照MVC的架构来编码的，controller放在skt.py里，主要是对一次性口令认证的逻辑实现，全部功能模块化，方便view所在的web.py模块做路由绑定，读写数据库的api放在dao.py里；整个架构可以说是很简单了，这边贴下部分代码 ：

```python
##dao.py
import MySQLdb
def searchUserInfo():
    db=MySQLdb.connect("localhost","root","sliver-xdw","sk",charset="utf8")
    cursor=db.cursor()
    sql='select * from userInfomation;'
    cursor.execute(sql)
    data=cursor.fetchall()
    cursor.close()
    db.close()
    return data

def insertUserInfo(username,password):
    db=MySQLdb.connect("localhost","root","sliver-xdw","sk",charset="utf8")
    cursor=db.cursor()
    li=[(username,password)]
    cursor.executemany('insert into userInfomation(username,password) values(%s,%s);', li)
    db.commit()
    cursor.close()
    db.close()

def updateUserInfo(username,password):
    db=MySQLdb.connect("localhost","root","sliver-xdw","sk",charset="utf8")
    cursor=db.cursor()
    sql='update userInfomation set password = "'+password+'" where username= "'+username+'";'
    cursor.execute(sql)
    db.commit()
    cursor.close()
    db.close()

def searchFilePrivilege(username):
    privilege=[]
    db=MySQLdb.connect("localhost","root","sliver-xdw","sk",charset="utf8")
    cursor=db.cursor()
    sql='select file1,file2,file3,file4,file5 from filePrivileges where user="'+username+'";'
    print(sql)
    cursor.execute(sql)
    privilege=cursor.fetchall()[0]
    cursor.close()
    db.close()
    return privilege

def initFilePrivilege(username):
    db=MySQLdb.connect("localhost","root","sliver-xdw","sk",charset="utf8")
    cursor=db.cursor()
    li=[(username,0,0,0,0,0)]
    cursor.executemany('insert into filePrivileges(user,file1,file2,file3,file4,file5) values(%s,%s,%s,%s,%s,%s);', li)
    db.commit()
    cursor.close()
    db.close()

def modifyFilePrivilege(username,privileges):
    print(privileges)
    db=MySQLdb.connect("localhost","root","sliver-xdw","sk",charset="utf8")
    cursor=db.cursor()
    sql='update filePrivileges set file1='+privileges['file1']+','+'file2='+privileges['file2']+',file3='+privileges['file3']+',file4='+privileges['file4']+',file5='+privileges['file5']+' where user="'+username+'";'
    print(sql);
    cursor.execute(sql)
    db.commit()
    cursor.close()
    db.close()

```



下面是skt.py

![](./4.png)  



最后是视图部分

```python
## web.py
from flask import Flask,render_template,request,redirect,session,url_for
from skt import *
from privilege import *

app=Flask(__name__)


@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='GET':
        return render_template('login.html')
    else:
        user = request.form.get('user')
        pwd = request.form.get('pwd')
        r = log(user, pwd)  # 验证用户名和密码
        #print ('r is %s'%r)
        if r == True:
            # print(session['user_info'])
            if user=='admin':
                return redirect('/chpri')
            else:
                return redirect(url_for('fileRead',user=user))
        else:
            # return render_template('login.html',msg='用户名或者密码有误')
            return render_template('login.html',**{'msg':'用户名或者密码有误'})

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=="GET":
        return render_template('register.html')
    else:
        user=request.form.get('user')
        pwd=request.form.get('pwd')
        is_exist=user_exist(user)
        if is_exist:
            return redirect('/userExist')
        else:
            registerCall(user,pwd)
            initPrivilege(user)
            return redirect('/registerSuccess')
        

@app.route('/index',methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/userExist',methods=['GET'])
def userExist():
    return render_template('userExist.html')

@app.route('/registerSuccess',methods=['GET'])
def registerSuccess():
    return render_template('regsuccess.html')

@app.route('/manage',methods=['GET','POST'])
def manage():
    return render_template('manage.html')

@app.route('/fileRead?user=<user>',methods=['GET','POST'])
def fileRead(user):
    privilege=searchPrivilege(user) 
    #print(privilege)
    return render_template('fileRead.html',user=user,privilege=privilege)

@app.route('/chpri',methods=['GET','POST'])
def chpri():
    privileges={'file1':'','file2':'','file3':'','file4':'','file5':''}
    if request.method=='GET':
        return render_template('chpri.html')

    else:
        #print(request.form.get('value'))
        username = request.values.get("filename")
        if len(username)==0:
            return render_template('chpri.html',**{'msg':'用户名不能为空'})
        for idx in privileges:
            #print(request.values.get(idx))
            privileges[idx]=request.values.get(idx)
            #privileges.append(request.values.get(idx))
        print(privileges)
        changePrivileges(username,privileges)
        #print(privileges)
        return redirect('/login')
if __name__ == '__main__':
   app.run(host='0.0.0.0',debug=True)
```



![](./5.png)

## 0x04  坑

- 脑海中关于flask的记忆已经很少了，连夜翻文档，不得不说flask的文档还行，挺通俗易懂的，两年没看，发现有些机制更容易理解了，果然还是成长了吗~
- 模板渲染那块找不到合适的前端，emmmmm，手写html，丢~，趁早去学一波
- 前后端交互的实现是通过在绑定函数中`request.values.get`得到用户Post的参数值，这边也能用js和一些flask处理前后端交互的扩展来做；感叹自己太菜，前端一窍不通，好羡慕那些能做出优美页面的dalao~

## 0x05  总结

- 以前一直是去做研究，去分析如何挖洞，如何利用；其实，换个角度，从防的角度来看，或者说从事物的原理出发，可能对某个东西了解会更透彻一点，攻击思路和手段也会更开阔。
- 前端是硬伤，学一波