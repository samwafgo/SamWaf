# 安全说明

SamWaf 是一款轻量化的网站安全防护产品（Web 应用防火墙）。

为了尽最大可能保障安全，我们做了以下工作：

1. 敏感数据（管理口令、各类凭证、POST 请求体等）本地加密保存
2. 管理端与业务连接加密通讯
3. POST 请求数据落库前进行脱敏处理

## 对外访问列表

- 版本升级检测：https://update.samwaf.com
- 域名反解析：119.29.29.29
- 获取外网 IP：http://myexternalip.com/raw

### 版本检查请求携带的信息

为判断存量版本分布、决定老版本还需兼容多久，版本与清单检查请求会携带：

- 版本号、实例码
- 编译目标系统与架构、运行形态（容器类型或宿主机）

仅此几项程序自身的信息，不含任何站点域名、日志、规则、证书或业务请求数据；
二进制与数据包的下载地址不带任何参数。

其中系统架构与运行形态可在 `conf/config.yml` 将 `update_env_report` 置为 `false` 关闭，
关闭后只携带版本号与实例码。

## 最佳实践

1. 对于管理端口 26666（默认），请在外层安全策略组加入可信 IP 限制访问
2. 修改默认管理密码
3. 启用「安全路径入口」，避免管理端暴露在根路径
4. 为管理端启用 HTTPS 并配置证书

## 安全问题反馈

如果您发现安全问题，请直接联系我们：

邮件主题：`[SecProblem] 简短标题`

邮件内容：安全问题的详细说明

- samwafgo@gmail.com

欢迎各位安全研究员提交，请附带完整的 PoC。我们会在收到后 3 个工作日内确认并同步进展；
出于存量用户升级节奏的考虑，漏洞详情会在修复版本发布后统一披露（不影响 CVE 编号申请）。
若您已有既定的公开时间安排，请在邮件中说明，我们会与您协商一致后再行动。
经您同意，我们会在公告中致谢。

### 不在受理范围

以下类型一般不作为安全问题受理，收到后可能不再单独回复：

- 需要先取得服务器本机管理员权限才能触发的问题
- 社会工程学、物理接触、针对使用者本人的钓鱼
- 纯流量型拒绝服务与压力测试
- 扫描器原始输出、仅凭版本号推断、无法复现的报告

---

## Reporting a Security Issue

If you find a security issue, please contact us directly:

Email subject: `[SecProblem] short title`

Email body: a detailed description of the issue

- samwafgo@gmail.com

Security researchers are welcome - please include a complete PoC. We will acknowledge your
report and share progress within 3 business days. Because self-hosted users upgrade at their
own pace, vulnerability details are disclosed together once the fixed release is out (this does
not affect CVE assignment). If you already have a planned publication date, please say so in
your email and we will agree on the timing with you before acting. With your permission, we
will credit you in the advisory.

### Out of Scope

The following are generally not accepted as security issues, and we may not reply to them
individually:

- Issues that require local administrator access on the server to trigger
- Social engineering, physical access, and phishing aimed at the operator
- Volumetric denial of service and stress testing
- Raw scanner output, version-banner-only inferences, and reports we cannot reproduce
