## 微信CRM
> 这个项目是为了让微信使用者方便管理多个微信账号去做批量维护微信用户

> 接口层: controllers

实现了一些对外的接口，用于操作微信，如登录，好友，群，朋友圈

> 服务层: services

处理接口层的功能

> 管理层: manager

用来管理微信账号的一些操作和数据库交互和具体的功能交互

> 功能层: wechat_sdk

微信协议



## 不需要认证的接口 
```
CmdId: 
1,
2,
32,
33,
48,
179,
232,CmdIdGetLoginQrCode
233,CmdIdCheckLoginQrCode
247,



CgiUrl:
/cgi-bin/micromsg-bin/manualauth
/cgi-bin/micromsg-bin/autoauth
/cgi-bin/micromsg-bin/reportkvcommrsa
/cgi-bin/micromsg-bin/reportidkeyrsa
/cgi-bin/micromsg-bin/newreportkvcommrsa
/cgi-bin/micromsg-bin/getkvidkeystrategyrsa
/cgi-bin/micromsg-bin/getcdndns
```

```
 <cgi reqid="27" respid="1000000027" nettype="3" netstrategy="0" netproto="2" netchannel="1">newinit</cgi>

 
```