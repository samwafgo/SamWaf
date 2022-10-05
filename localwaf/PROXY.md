# TDesign starter 本地开发联调

## 工具准备

- 浏览器插件：[SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif?hl=zh-CNhttps://chrome.google.com/webstore/detail/proxy-switchyomega/padekgcemlokbadohgkifijomclgjgif?hl=zh-CN)
- 调试代理工具：[whistle](https://wproxy.org/whistle/)

## 代理配置

`npm run dev`开启本地服务后，可以配置代理将线上域名的非后台 api 路径（如`/api`）的静态文件请求代理到本地，这样就可以进行本地联调和前端代码热更新了。

举例子：

```
/tdesign.tencent.com(?!\/api)/ 127.0.0.1:3001
```

其中：

- tdesign.tencent.com：修改你的线上域名
- /api：修改成后台请求路径
- 3001：修改成本地服务端口
