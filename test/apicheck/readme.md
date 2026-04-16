# api 可行性测试


```
go test -v -count=1 -run TestAllRoutes ./test/apicheck/ -timeout=30s

```

# 测试结果

```

C:\huawei\goproject\SamWaf>go test -v -count=1 -run TestAllRoutes ./test/apicheck/ -timeout=30s
=== RUN   TestAllRoutes
    api_routes_test.go:341: ──────────────────────────────────────────────────────────────────────────────────────────
    api_routes_test.go:342: 方法     路径                                                 状态     问题               描述
    api_routes_test.go:343: ──────────────────────────────────────────────────────────────────────────────────────────
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/ipwhite/add                        200    -                新增IP白名单
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/ipwhite/detail                     200    -                获取IP白名单详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/ipwhite/list                       200    -                获取IP白名单列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/ipwhite/del                        200    -                删除IP白名单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/ipwhite/edit                       200    -                编辑IP白名单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/urlwhite/add                       200    -                新增URL白名单
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/urlwhite/detail                    200    -                获取URL白名单详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/urlwhite/list                      200    -                获取URL白名单列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/urlwhite/del                       200    -                删除URL白名单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/urlwhite/edit                      200    -                编辑URL白名单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/ipblock/add                        200    -                新增IP黑名单
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/ipblock/detail                     200    -                获取IP黑名单详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/ipblock/list                       200    -                获取IP黑名单列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/ipblock/del                        200    -                删除IP黑名单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/ipblock/edit                       200    -                编辑IP黑名单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/urlblock/add                       200    -                新增URL黑名单
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/urlblock/detail                    200    -                获取URL黑名单详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/urlblock/list                      200    -                获取URL黑名单列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/urlblock/del                       200    -                删除URL黑名单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/urlblock/edit                      200    -                编辑URL黑名单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/anticc/add                         200    -                新增Anti-CC规则
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/anticc/detail                      200    -                获取Anti-CC规则详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/anticc/list                        200    -                获取Anti-CC规则列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/anticc/del                         200    -                删除Anti-CC规则
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/anticc/edit                        200    -                编辑Anti-CC规则
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/ipfailure/config                   200    -                获取IP失败封禁配置
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/ipfailure/config                   200    -                设置IP失败封禁配置
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/ipfailure/baniplist                200    -                获取IP失败封禁列表
    api_routes_test.go:368: ✓ POST   /api/v1/firewall/ipblock/add                       200    -                新增防火墙IP封禁
    api_routes_test.go:368: ✓ POST   /api/v1/firewall/ipblock/list                      200    -                获取防火墙IP封禁列表
    api_routes_test.go:368: ✓ GET    /api/v1/firewall/ipblock/del                       200    -                删除防火墙IP封禁
    api_routes_test.go:368: ✓ POST   /api/v1/firewall/ipblock/edit                      200    -                编辑防火墙IP封禁
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/rule/add                           200    -                新增WAF规则
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/rule/detail                        200    -                获取WAF规则详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/rule/list                          200    -                获取WAF规则列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/rule/del                           200    -                删除WAF规则
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/rule/edit                          200    -                编辑WAF规则
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/rule/rulestatus                    200    -                修改WAF规则状态
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sensitive/add                      200    -                新增敏感词
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/sensitive/detail                   200    -                获取敏感词详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sensitive/list                     200    -                获取敏感词列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/sensitive/del                      200    -                删除敏感词
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sensitive/edit                     200    -                编辑敏感词
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/cacherule/add                      200    -                新增缓存规则
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/cacherule/detail                   200    -                获取缓存规则详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/cacherule/list                     200    -                获取缓存规则列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/cacherule/del                      200    -                删除缓存规则
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/cacherule/edit                     200    -                编辑缓存规则
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/loadbalance/add                    200    -                新增负载均衡
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/loadbalance/detail                 200    -                获取负载均衡详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/loadbalance/list                   200    -                获取负载均衡列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/loadbalance/del                    200    -                删除负载均衡
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/loadbalance/edit                   200    -                编辑负载均衡
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/onekeymod/detail                   200    -                获取一键修改详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/onekeymod/list                     200    -                获取一键修改列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/onekeymod/del                      200    -                删除一键修改
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/onekeymod/doModify                 200    -                执行一键修改
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/onekeymod/restore                  200    -                还原一键修改
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/task/add                           200    -                新增任务
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/task/detail                        200    -                获取任务详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/task/list                          200    -                获取任务列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/task/del                           200    -                删除任务
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/task/edit                          200    -                编辑任务
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/task/manual_exec                   200    -                手动执行任务
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/task/log                           200    -                获取任务日志
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/task/log/clear                     200    -                清空任务日志
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/dataretention/list                 200    -                获取数据保留策略列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/dataretention/detail               200    -                获取数据保留策略详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/dataretention/edit                 200    -                编辑数据保留策略
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/privateinfo/add                    200    -                新增私有信息
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/privateinfo/detail                 200    -                获取私有信息详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/privateinfo/list                   200    -                获取私有信息列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/privateinfo/del                    200    -                删除私有信息
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/privateinfo/edit                   200    -                编辑私有信息
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/privategroup/add                   200    -                新增私有分组
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/privategroup/detail                200    -                获取私有分组详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/privategroup/list                  200    -                获取私有分组列表
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/privategroup/listbybelongcloud     200    -                按云获取私有分组列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/privategroup/del                   200    -                删除私有分组
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/privategroup/edit                  200    -                编辑私有分组
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/host/add                           200    -                新增站点
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/host/detail                        200    -                获取站点详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/host/list                          200    -                获取站点列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/host/del                           200    -                删除站点
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/host/edit                          200    -                编辑站点
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/host/guardstatus                   200    -                修改防护状态
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/host/startstatus                   200    -                修改启动状态
    api_routes_test.go:368: ✓ POST   /api/v1/sslconfig/add                              200    -                新增SSL证书
    api_routes_test.go:368: ✓ GET    /api/v1/sslconfig/detail                           200    -                获取SSL证书详情
    api_routes_test.go:368: ✓ POST   /api/v1/sslconfig/list                             200    -                获取SSL证书列表
    api_routes_test.go:368: ✓ GET    /api/v1/sslconfig/del                              200    -                删除SSL证书
    api_routes_test.go:368: ✓ POST   /api/v1/sslconfig/edit                             200    -                编辑SSL证书
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sslorder/add                       200    -                新增SSL订单
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/sslorder/detail                    200    -                获取SSL订单详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sslorder/list                      200    -                获取SSL订单列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/sslorder/del                       200    -                删除SSL订单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sslorder/edit                      200    -                编辑SSL订单
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sslexpire/add                      200    -                新增SSL到期监控
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/sslexpire/detail                   200    -                获取SSL到期监控详情
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sslexpire/list                     200    -                获取SSL到期监控列表
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/sslexpire/del                      200    -                删除SSL到期监控
    api_routes_test.go:368: ✓ POST   /api/v1/wafhost/sslexpire/edit                     200    -                编辑SSL到期监控
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/sslexpire/nowcheck                 200    -                立即检测SSL到期
    api_routes_test.go:368: ✓ GET    /api/v1/wafhost/sslexpire/sync_host                200    -                从站点同步SSL监控
    api_routes_test.go:368: ✓ POST   /api/v1/tunnel/tunnel/add                          200    -                新增隧道
    api_routes_test.go:368: ✓ GET    /api/v1/tunnel/tunnel/detail                       200    -                获取隧道详情
    api_routes_test.go:368: ✓ POST   /api/v1/tunnel/tunnel/list                         200    -                获取隧道列表
    api_routes_test.go:368: ✓ GET    /api/v1/tunnel/tunnel/del                          200    -                删除隧道
    api_routes_test.go:368: ✓ POST   /api/v1/tunnel/tunnel/edit                         200    -                编辑隧道
    api_routes_test.go:368: ✓ GET    /api/v1/tunnel/tunnel/connections                  200    -                获取隧道连接数
    api_routes_test.go:368: ✓ POST   /api/v1/notify/channel/add                         200    -                新增通知渠道
    api_routes_test.go:368: ✓ GET    /api/v1/notify/channel/detail                      200    -                获取通知渠道详情
    api_routes_test.go:368: ✓ POST   /api/v1/notify/channel/list                        200    -                获取通知渠道列表
    api_routes_test.go:368: ✓ GET    /api/v1/notify/channel/del                         200    -                删除通知渠道
    api_routes_test.go:368: ✓ POST   /api/v1/notify/channel/edit                        200    -                编辑通知渠道
    api_routes_test.go:368: ✓ POST   /api/v1/notify/subscription/add                    200    -                新增通知订阅
    api_routes_test.go:368: ✓ POST   /api/v1/notify/subscription/list                   200    -                获取通知订阅列表
    api_routes_test.go:368: ✓ GET    /api/v1/notify/subscription/del                    200    -                删除通知订阅
    api_routes_test.go:368: ✓ POST   /api/v1/notify/log/list                            200    -                获取通知日志列表
    api_routes_test.go:368: ✓ GET    /api/v1/notify/log/detail                          200    -                获取通知日志详情
    api_routes_test.go:368: ✓ GET    /api/v1/notify/log/del                             200    -                删除通知日志
    api_routes_test.go:368: ✓ POST   /api/v1/vipconfig/updateIpWhitelist                200    -                更新管理IP白名单
    api_routes_test.go:368: ✓ GET    /api/v1/vipconfig/getIpWhitelist                   200    -                获取管理IP白名单
    api_routes_test.go:368: ✓ POST   /api/v1/vipconfig/updateSslEnable                  200    -                更新SSL启用状态
    api_routes_test.go:368: ✓ GET    /api/v1/vipconfig/getSslStatus                     200    -                获取SSL启用状态
    api_routes_test.go:368: ✓ GET    /api/v1/vipconfig/getSecurityEntry                 200    -                获取安全入口
    api_routes_test.go:368: ✓ POST   /api/v1/vipconfig/updateSecurityEntry              200    -                更新安全入口
    api_routes_test.go:368: ✓ GET    /api/v1/vipconfig/getNoticeTitle                   200    -                获取通知标题前缀
    api_routes_test.go:368: ✓ POST   /api/v1/vipconfig/updateNoticeTitle                200    -                更新通知标题前缀
    api_routes_test.go:368: ✓ POST   /api/v1/systemconfig/list                          200    -                获取系统配置列表
    api_routes_test.go:368: ✓ POST   /api/v1/systemconfig/edit                          200    -                更新系统配置
    api_routes_test.go:368: ✓ POST   /api/v1/systemconfig/editByItem                    200    -                通过item更新系统配置
    api_routes_test.go:368: ✓ GET    /api/v1/monitor/system_info                        200    -                获取系统监控信息
    api_routes_test.go:368: ✓ GET    /api/v1/wafstatsumday                              200    -                获取今日访问统计
    api_routes_test.go:368: ✓ GET    /api/v1/wafstatsumdayrange                         200    -                按日期范围统计访问量
    api_routes_test.go:368: ✓ GET    /api/v1/wafstatsumdaytopiprange                    200    -                统计攻击IP排行
    api_routes_test.go:368: ✓ GET    /api/v1/statsysinfo                                200    -                获取首页系统基本信息
    api_routes_test.go:368: ✓ GET    /api/v1/statrumtimesysinfo                         200    -                获取运行时系统基本信息
    api_routes_test.go:368: ✓ GET    /api/v1/wafstatsiteoverview                        200    -                站点综合概览统计
    api_routes_test.go:368: ✓ GET    /api/v1/wafstatsitedetail                          200    -                站点详情趋势查询
    api_routes_test.go:368: ✓ GET    /api/v1/sysinfo/version                            200    -                获取版本信息
    api_routes_test.go:368: ✓ GET    /api/v1/sys_log/list                               200    -                获取系统日志列表
    api_routes_test.go:368: ✓ GET    /api/v1/sys_log/detail                             200    -                获取系统日志详情
    api_routes_test.go:368: ✓ POST   /api/v1/waflog/attack/list                         200    -                获取攻击日志列表
    api_routes_test.go:368: ✓ GET    /api/v1/waflog/attack/detail                       200    -                获取攻击日志详情
    api_routes_test.go:368: ✓ GET    /api/v1/logfilewrite/preview                       200    -                预览日志文件
    api_routes_test.go:368: ✓ GET    /api/v1/logfilewrite/currentfile                   200    -                获取当前日志文件
    api_routes_test.go:368: ✓ GET    /api/v1/logfilewrite/backupfiles                   200    -                获取备份日志文件列表
    api_routes_test.go:368: ✓ POST   /api/v1/logfilewrite/clear                         200    -                清空日志文件
    api_routes_test.go:368: ✓ GET    /api/v1/logfilewrite/variables                     200    -                获取日志变量
    api_routes_test.go:368: ✓ GET    /api/v1/resetWAF                                   200    -                重启WAF引擎
    api_routes_test.go:370: ──────────────────────────────────────────────────────────────────────────────────────────
    api_routes_test.go:371: 合计 151 条，通过 151 条，失败 0 条
--- PASS: TestAllRoutes (1.73s)
PASS
ok      SamWaf/test/apicheck    1.756s
```