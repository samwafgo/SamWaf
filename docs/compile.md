# Compile 编译说明
## 环境说明
golang:1.21.4

## 代码说明

前台:
```
已经迁移到单独仓        # 本地Web应用防火墙相关文件
```

后台:
```
alert           # 规划用于通知和警报的相关文件
api             # 涉及应用程序编程接口（API）的文件
bat             # 批处理脚本或相关文件
binarydist      # 二进制分发相关的文件
cache           # 缓存数据和文件
conf            # 配置文件和设置
customtype      # 自定义类型相关的文件
data            # 数据文件和数据存储
dbgen           # 数据库生成或相关工具
docs            # 文档和说明文件
enums           # 枚举类型的定义和文件
exedata         # 执行数据相关的文件
firewall        # 防火墙配置和相关文件
global          # 全局配置或文件
globalobj       # 全局对象或相关文件
innerbean       # 内部组件或bean文件
libinjection-go # libinjection库的Go语言版本 
middleware      # 中间件组件和相关文件
model           # 数据模型或相关文件
PDFs            # PDF文档
plugin          # 插件和扩展
release         # 发布版本相关文件
router          # 路由配置和相关文件
service         # 服务相关的文件
setup           # 安装和设置文件
test            # 测试文件和测试用例
upx             # UPX压缩工具或相关文件
utils           # 实用工具和辅助文件
vue             # 前端转go后的代码
wafbot          # Web应用防火墙爬虫的相关文件
wafconfig       # Web应用防火墙配置文件
wafdb           # Web应用防火墙数据库文件
wafdefenserce   # Web应用防火墙防御rce文件
wafenginecore   # Web应用防火墙引擎核心文件
wafmangeweb     # Web应用防火墙管理
wafnotify       # Web应用防火墙通知相关文件
wafonekey       # Web应用防火墙一键操作相关文件
wafproxy        # Web应用防火墙代理相关文件
wafreg          # Web应用防火墙注册文件
wafsafeclear    # Web应用防火墙安全清理文件
wafsec          # Web应用防火墙安全相关文件
wafsnowflake    # Web应用防火墙Snowflake相关文件
waftask         # Web应用防火墙任务相关文件
wafupdate       # Web应用防火墙更新文件
wechat          # 微信相关文件
```


## 编译
 
提前安装好:mingw(https://www.mingw-w64.org/downloads/)

windows
```
build-releases-win-upx.bat

```
linux
```
./build_docker_release_linux.bat

```

ubuntu docker 测试

```
docker build -f UbuntuDockerfile -t samwaflocalcompile .

docker run --rm samwaflocalcompile
docker run --rm -v $(pwd):/workspace samwaflocalcompile
docker run --rm -v %cd%:/workspace samwaflocalcompile

```
## 集成的三方库
前端: 使用TDesign Vue Starter
后端: gorm,excelize(360EntSecGroup-Skylar),godlp(bytedance),gin,gocron,
     grule-rule-engine,ip2region,sqlitedriver,viper,libinjection-go,corazawaf,go-acme/lego
数据：
ipv6(GeoLite2-Country.mmdb) by maxmind 
## TODO List
 
- 完善对应功能test 