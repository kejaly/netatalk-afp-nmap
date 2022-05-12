# netatalk-afp-nmap
对 nmap 中 afp 协议的一些完善（具体在 afp.lua ），以及新添一些脚本。

另外，由于 nmap 对非 548 端口的 afp 协议识别不了，所以如果需要对非 548 端口的 afp 服务运行脚本，需要自行修改脚本中的 `portrule`，比如：

```lua
portrule = shortport.portnumber({548, 32884})
```



## 脚本使用

afp-read: 

```sh
# flag 为 0 读取文件本身内容， flag 为 1 读取 resource fork 
nmap 127.0.0.1 -p 32884 --script=afp-read --script-args "rpath=test/exp,flag=1"

nmap 127.0.0.1 -p 32884 --script=afp-read --script-args "rpath=test/flag,flag=0"
```

afp-write:

```sh
# localfile 本地文件路径，rpath 远程共享文件路径

nmap 127.0.0.1 -p 32884 --script=afp-write --script-args "localfile=d:\\work\\._exp,rpath=test/exp"
```

afp-getextattr:

```sh
# rpath 远程共享文件路径, attr_name 额外属性名

nmap 127.0.0.1 -p 32884 --script=afp-getextattr --script-args "rpath=test/readexp,attr_name=org.netatalk.Metadata"

```

afp-remove-extattr:

```sh
# rpath 远程共享文件路径, attr_name 额外属性名

nmap 127.0.0.1 -p 32884 --script=afp-remove-extattr --script-args "rpath=test/readexp,attr_name=org.netatalk.Metadata"
```

