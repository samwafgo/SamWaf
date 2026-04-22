package wafowasp

// UsageDocMarkdown 返回 OWASP 规则管理的使用讲解（Markdown）。
//
// 这份文档同时也是 SamWafTechDoc 下《OWASP规则在线管理使用指南.md》的主体内容。
// 保持在代码里可以支持单机离线查阅，前端通过 /api/v1/owasp/usage/doc 取回 render。
func UsageDocMarkdown() string {
	return usageDocMD
}

const usageDocMD = `# OWASP 规则在线管理使用指南

本页面介绍如何在 SamWaf 后台管理 OWASP CRS 规则：禁用/改写单条规则、调优全局阈值、在线升级、沙盒验证。

## 一、工作原理速览

- SamWaf 集成了 [Coraza WAF](https://github.com/corazawaf/coraza) + **OWASP ModSecurity Core Rule Set (CRS)**。
- CRS 采用**评分机制**：每条规则命中会按 severity 给 tx.anomaly_score 加分；累计达到阈值就拦截。
- 默认 paranoia-level=1、threshold=7（SamWaf 在官方默认值 5 基础上放宽至 7，降低单条规则直接 block 的概率）。

## 二、目录结构与三层策略

三层策略叠加，加载顺序如下：

    Layer 0 (CRS 上游，在线升级时整体替换)
      data/owasp/coreruleset/rules/*.conf

    Layer 1 (SamWaf 产品默认层，随 SamWaf 版本更新)
      data/owasp/overrides/00-samwaf-base.conf

    Layer 2 (用户自定义层，永不被任何升级覆盖)
      data/owasp/overrides/05-user-vars.conf
      data/owasp/overrides/10-disabled-rules.conf
      data/owasp/overrides/20-custom-rules.conf
      data/owasp/overrides/override_registry.json

| 路径 | 层 | 作用 |
| --- | --- | --- |
| data/owasp/coraza.conf | — | Coraza 基础配置（请勿直接改） |
| data/owasp/coreruleset/ | 0 | 官方规则基线（CRS 在线升级时整体替换） |
| overrides/00-samwaf-base.conf | **1** | SamWaf 产品默认 tx.* 变量（随 SamWaf 二进制更新） |
| overrides/05-user-vars.conf | **2** | 用户覆盖的 tx.* 变量（优先于 Layer 1） |
| overrides/10-disabled-rules.conf | **2** | 按 ID 禁用的规则（SecRuleRemoveById） |
| overrides/20-custom-rules.conf | **2** | 用户改写后的规则 |
| overrides/override_registry.json | **2** | 元数据：记录哪些 ID 被改动 |

加载顺序：coraza.conf → crs-setup.conf → 00-samwaf-base.conf → 05-user-vars.conf → rules/*.conf → 10-disabled-rules.conf → 20-custom-rules.conf

tx.* 变量必须在 rules/*.conf 之前设置：CRS rule 901160 只在变量未设置时才写默认值。

## 三、误报应对阶梯

当线上出现误报，按如下顺序排查：

1. **先用观察模式（DetectionOnly）评估**：在"全局调参"把 rule_engine 改成 DetectionOnly，线上只记录不拦截，跑 24h 看看哪些规则频繁误报。
2. **调高总阈值**：把 inbound_anomaly_score_threshold 从 7 提到 10 甚至更高；但不要低于 3，过低时一次合规请求都可能触发。
3. **禁用单条规则**：在"规则管理"搜到对应 ID，勾上禁用；后台会在 overrides/10-disabled-rules.conf 追加 SecRuleRemoveById，热重载即可生效。
4. **改写单条规则**：对于只想修改动作或部分匹配条件的规则，使用"编辑"功能。保存的是 overrides/20-custom-rules.conf，原文件不动。
5. **实在不行再关闭整个 OWASP**：通过系统配置 enable_owasp=0 或者 rule_engine=Off。

## 四、在线升级

- 升级源：SamWaf 自有服务
- 流程：检查版本 → 下载 zip → 校验 sha256 → 合并（保留用户改动）→ 热重载
- 用户在任意规则上的禁用或改写**升级时不会丢失**，原理是合并阶段会比对 override_registry.json。

## 五、沙盒验证

在"测试沙盒"可以构造请求（method/url/headers/body）实时看命中规则与累计分数。典型用例：

- 正常 GET /：应 0 命中。
- GET /?id=1%27%20OR%201=1：应命中 942xxx 系列 SQLi 规则。
- POST + body 含 <script>alert(1)</script>：应命中 941xxx 系列 XSS 规则。

## 六、性能注意

- 开启 debug 日志会让 SamWaf 额外采集 Coraza 全部变量，RSS 会升高。生产环境建议关闭。
- 大请求体（> 13MB）会被 SecRequestBodyLimit 截断后再检测，不会全量驻留。

## 七、常见问题

1. **沙盒命中但线上没命中？** 多半是 paranoia-level 或阈值差异：确认两边 tuning 一致。
2. **升级后规则变多了？** 正常。CRS 会随版本迭代新增规则。若想锁定版本，创建 data/owasp/lock.txt。
3. **误禁用了重要规则？** 在规则管理里点击"还原"，会从 registry 移除该 ID，热重载后恢复官方行为。
`
