SamWaf网站防火墙
[![Release](https://img.shields.io/github/release/samwafgo/SamWaf.svg)](https://github.com/samwafgo/SamWaf/releases)

# 介绍
SamWaf网站防火墙是一款适用于小公司、工作室和个人网站的免费轻量级网站防火墙，代码开源，完全私有化部署，数据加密且仅保存本地，一键启动，支持Linux，Windows 64位

## 架构

![SamWaf架构](/docs/images/tecDesign.png)

## 界面
![SamWaf网站防火墙概览](/docs/images/overview.png)

<table>
    <tr>
        <td align="center">添加主机</td>
        <td align="center">攻击日志</td>
    </tr>
    <tr>
        <td><img src="./docs/images/add_host.png" alt="添加主机"/></td>
        <td><img src="./docs/images/attacklog.png" alt="攻击日志"/></td>
    </tr>
    <tr>
        <td align="center">CC</td>
        <td align="center">IP黑名单</td>
    </tr>
    <tr>
        <td><img src="./docs/images/cc.png" alt="CC"/></td>
        <td><img src="./docs/images/ipblack.png" alt="IP黑名单"/></td>
    </tr>
    <tr>
        <td align="center">IP白名单</td>
        <td align="center">LDP</td>
    </tr>
    <tr>
        <td><img src="./docs/images/ipwhite.png" alt="IP白名单"/></td>
        <td><img src="./docs/images/ldp.png" alt="LDP"/></td>
    </tr>
    <tr>
        <td align="center">添加规则脚本日志</td>
        <td align="center">选择日志</td>
    </tr>
    <tr>
        <td><img src="./docs/images/log_add_rule_script.png" alt="添加规则脚本日志"/></td>
        <td><img src="./docs/images/log_select.png" alt="选择日志"/></td>
    </tr>
    <tr>
        <td align="center">日志详情</td>
        <td align="center">手动规则</td>
    </tr>
    <tr>
        <td><img src="./docs/images/logdetail.png" alt="日志详情"/></td>
        <td><img src="./docs/images/manual_rule.png" alt="手动规则"/></td>
    </tr>
    <tr>
        <td align="center">URL黑名单</td>
        <td align="center">URL白名单</td>
    </tr>
    <tr>
        <td><img src="./docs/images/urlblack.png" alt="URL黑名单"/></td>
        <td><img src="./docs/images/urlwhite.png" alt="URL白名单"/></td>
    </tr>
</table>


## 主要功能：
- 代码完全开源
- 支持私有化部署
- 轻量化不依赖三方服务
- 完全独立引擎，防护功能不依赖IIS,Nginx
- 自定义防护规则，支持脚本和界面编辑
- 支持白名单访问
- 支持IP黑名单
- 支持URL白名单
- 支持限制URL访问
- 支持指定界面数据隐私输出
- 支持CC频率访问
- 支持全局一键配置
- 支持分网站单独防护策略
- 日志加密保存
- 通讯日志加密
- 信息脱敏保存



## 下载最新版本
gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

github: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)
 
## 快速启动
### Windows
- 直接启动
```
SamWaf64.exe
```
- 服务形式
```
//安装
SamWaf64.exe install 

//启动
SamWaf64.exe start

//停止
SamWaf64.exe stop

//卸载
SamWaf64.exe uninstall
```

### Linux

- 直接启动
```
./SamWafLinux64
```
- 服务形式
```
//安装
./SamWafLinux64 install 

//启动
./SamWafLinux64 start

//停止
./SamWafLinux64 stop

//卸载
./SamWafLinux64 uninstall
```
 

## 启动访问

http://127.0.0.1:26666

默认帐号：admin  默认密码：admin868 (注意首次进入请把默认密码改掉)


## 编译
How to compile
[编译说明](./docs/compile.md)

## 已测试支持的平台
[已测试支持的平台](./docs/Tested_supported_systems.md)

## 问题反馈
- [github issues访问](https://github.com/samwafgo/SamWaf/issues)
- 邮件反馈 samwafgo@gmail.com

