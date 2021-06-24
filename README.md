# fu-tomcat-embed-rfc7230
### 让spring-tomcat-embed-tomcat 在url中支持rfc7230字符

#### [网关url特殊字符问题]

网关后端老旧系统用了如:{}等特殊字符. 在新的gateway不接受此类字符,应用URL编码 如: http://a.com/c.do?x={} 编码成 http://a.com/c.do?x=%7B%7D
但是老系统不方便改源码,因此通过修改embed-tomcat源码实现兼容.

## 原理

 修改org.apache.coyote.http11.Http11InputBuffer.java 源码
   484行,注释掉非法字符验证. if (parsingRequestLineQPos != -1 && !httpParser.isQueryRelaxed(chr)) {...

 修改org.apache.coyote.http11.Http11Processor.java 源码
   198 开始, 如果 query字符中有 指定的 字符则用url编码替代.
   通过"tomcat.query.char.convert" 系统变量控制配置.
   用法见源码


## 用法 A

编译成功后,把对应的 *.class 文件覆盖到 tomcat-embed-core-9.0.41.jar 中去.
发布时要手动引用修改后的tomcat-embed-core-9.0.41.jar文件

## 用法 B
releases目录下有修改后tomcat-embed-core-9.0.41.jar文件，可以下载后手动替换你的tomcat-embed-core-9.0.41.jar文件

## 用法 C
1.在你的maven中排除tomcat-embed-core-9.0.41
```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-tomcat</artifactId>
	<exclusions>
		<exclusion>
			<artifactId>tomcat-embed-core</artifactId>
			<groupId>org.apache.tomcat.embed</groupId>
		</exclusion>
	</exclusions>
</dependency>
```
2.引用修改后的tomcat-embed-core-9.0.41
```xml
<dependency>
	<groupId>org.apache.tomcat.embed</groupId>
	<artifactId>tomcat-embed-core</artifactId>
	<version>9.0.41-rfc7230</version>
</dependency>
```

3. 包不在maven公库网上，要在项目pom.xml文件中加
```xml
<repositories>
  <repository>
    <id>utilsfun</id>
    <name>utilsfun</name>
    <url>https://utilsfun.oss-cn-shenzhen.aliyuncs.com/repository/</url>
  </repository>
</repositories>
```

## 配置

默认值 "*,*,{}[]|,utf-8;"
表示在所有host,所有uri时，把{}[]|字符转成URLEncode utf-8 字符

手动配置方法

系统变量：tomcat.query.char.convert
规则 主机,包含路径,字符,编码;(下一条)
多个规则用;分开

如：
```
 System.setProperty("tomcat.query.char.convert","my.com,/test/,{},gbk;*,*,{}[]|,utf-8;");
```
表示在访问my.com,uri包含/test/时，把{}字符转成URLEncode gbk字符,其它情况下把{}[]|字符转成URLEncode utf-8 字符
