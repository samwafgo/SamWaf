SamWaf网站防火墙
[![Release](https://img.shields.io/github/release/samwafgo/SamWaf.svg)](https://github.com/samwafgo/SamWaf/releases)

# 介绍
SamWaf网站防火墙是一款适用于小公司、工作室和个人网站的免费轻量级网站防火墙，代码开源，完全私有化部署，数据加密且仅保存本地，一键启动，支持Linux，Windows 64位

## 技术架构

![SamWaf技术架构](/docs/images/tecDesign.png)

## 界面
![SamWaf网站防火墙概览](/docs/images/overview.png)

## 主要功能：
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

## 已测试支持的平台
- Centos 64位
- Ubuntu 64
- Windows 2008r2 64位
- Windows10 64位

## 下载最新版本
gitee:  [https://gitee.com/samwaf/SamWaf/releases](https://gitee.com/samwaf/SamWaf/releases)

github: [https://github.com/samwafgo/SamWaf/releases](https://github.com/samwafgo/SamWaf/releases)


- Windows 

SamWaf64.exe

- Linux

SamWafLinux64

## 快速启动
启动方式分为后台服务形式启动和非后台服务启动
### 服务形式
服务方式可以自动注册重启自动启动

1.安装

如果是windows环境
```shell script
SamWaf64.exe install
```

如果是linux环境
```shell script
SamWafLinux64 install
```
2.启动

如果是windows环境
```shell script
SamWaf64.exe start
```

如果是linux环境
```shell script
SamWafLinux64 start
```

3.停止

如果是windows环境
```shell script
SamWaf64.exe stop
```
如果是linux环境
```shell script
SamWafLinux64 stop
```
### 非服务形式

如果是windows环境 双击启动
```shell script
 SamWaf64.exe
```
如果是linux环境 执行
```shell script
./SamWafLinux64 
```


## 启动访问

http://127.0.0.1:26666

默认帐号：admin  默认密码：admin868 (注意首次进入请把默认密码改掉)


## 编译
代码为go语言开发。建议golang:1.22.3

windows
```
build-releases-win-upx.bat

```
linux
```
./build_docker_release_linux.bat

```

## 问题反馈
- [github issues访问](https://github.com/samwafgo/SamWaf/issues)
- 邮件反馈 samwafgo@gmail.com
