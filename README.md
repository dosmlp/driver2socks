# driver2socks
在驱动层拦截指定应用的流量转发到socks5服务器实现socks5代理的效果

### 使用的第三方项目

1. [WinDivert](https://reqrypt.org/windivert.html)，魔改了源码，以实现在驱动层根据应用程序名称拦截ip数据包；
2. [LWIP](https://savannah.nongnu.org/projects/lwip/)，魔改了源码，以实现接收任意ip数据包并建立虚拟tcpip协议堆栈，将流量转发到socks5客户端；
3. [Melon](https://github.com/Water-Melon/Melon) ，修改了其中的mln_rbtree，在Windows内核空间实现红黑树，用来过滤需要拦截的IP包信息；





![](https://raw.githubusercontent.com/dosmlp/driver2socks/main/d2s.png)

### 待开发。。。

- [ ] 拦截系统DNS查询，转为dot安全dns
- [ ] 增加配置选项
- [x] 支持ipv6