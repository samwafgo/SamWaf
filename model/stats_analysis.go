package model

import "SamWaf/model/baseorm"

// M5 分析层的天级汇总，喂三个视角：行为（谁）/ 目标（打哪）/ 手法（怎么打）。
//
// 为什么去重数不做成列：去重计数没法跨批次累加——同一个 IP 在两个批次里各出现一次，
// 各 +1 就成了 2。所以这里只存**可累加的计数器**，去重数留给读侧现算：
//
//	GROUP BY path_norm → 目标视角：SUM(req_cnt) / SUM(deny_cnt) / COUNT(DISTINCT actor_key)=去重 IP 数
//	GROUP BY actor_key → 行为视角：SUM(req_cnt) / SUM(deny_cnt) / COUNT(DISTINCT path_norm)=去重路径数
//
// 一张细粒度表同时喂两个视角，数字精确，机制与 stats_ip_days 完全同款
// （纯计数器：累加安全、重启安全、重复入队安全）。

// StatsPathNormLen 汇总表里路径模板的列宽，比窄行的 512 短。
// 这几列都要进唯一索引，PostgreSQL 的 btree 单行上限约 2704 字节，得留余量；
// NormalizePath 已把超 32 字符的段归一成 {s}，正常模板远短于此。
const StatsPathNormLen = 200

// StatsRuleLen 汇总表里规则名的列宽。日志里 RULE 是 text，做键要有界。
const StatsRuleLen = 128

// StatsActorPathDay 「谁 打了 哪个路径」的天级计数，两个分析视角共同的地基。
type StatsActorPathDay struct {
	baseorm.BaseOrm
	HostCode string `gorm:"size:64" json:"host_code"`  //网站唯一码（主要键）
	Day      int    `json:"day"`                       //年月日（主要键）如 20260919
	ActorKey string `gorm:"size:64" json:"actor_key"`  //访问者身份，目前是 ip:+来源IP（主要键）
	PathNorm string `gorm:"size:200" json:"path_norm"` //路径模板（主要键）
	ReqCnt   int64  `json:"req_cnt"`                   //请求数
	DenyCnt  int64  `json:"deny_cnt"`                  //被拦截数
	// Err4xxCnt 只数后端给的 4xx，不含 WAF 拦截页（也是 403）：
	// 混在一起就分不出「扫目录扫出一堆 404」和「被 WAF 挡了一堆」这两件事。
	Err4xxCnt int64 `gorm:"column:err4xx_cnt" json:"err4xx_cnt"`
}

func (StatsActorPathDay) TableName() string {
	return "stats_actor_path_days"
}

// StatsActorUaDay 「谁 用了哪个 UA 指纹」的天级计数，ua_cnt = 按 actor 数行数。
// 单独一张表而不并进上表：UA 与路径正交，合并会让行数变成两者的乘积。
type StatsActorUaDay struct {
	baseorm.BaseOrm
	HostCode string `gorm:"size:64" json:"host_code"` //网站唯一码（主要键）
	Day      int    `json:"day"`                      //年月日（主要键）
	ActorKey string `gorm:"size:64" json:"actor_key"` //访问者身份（主要键）
	UaHash   string `gorm:"size:64" json:"ua_hash"`   //UA 指纹（主要键）
	Cnt      int64  `json:"cnt"`                      //数量
}

func (StatsActorUaDay) TableName() string {
	return "stats_actor_ua_days"
}

// StatsPathRuleDay 「哪个路径 命中了哪条规则」的天级计数。
// 存整个分布而不是只存一个 top_rule：写入成本一样，读侧既能取 top 也能看构成。
type StatsPathRuleDay struct {
	baseorm.BaseOrm
	HostCode string `gorm:"size:64" json:"host_code"`  //网站唯一码（主要键）
	Day      int    `json:"day"`                       //年月日（主要键）
	PathNorm string `gorm:"size:200" json:"path_norm"` //路径模板（主要键）
	Rule     string `gorm:"size:128" json:"rule"`      //命中的规则（主要键）
	Cnt      int64  `json:"cnt"`                       //数量
}

func (StatsPathRuleDay) TableName() string {
	return "stats_path_rule_days"
}

// LogAnalysisRow 一条请求供分析层聚合用的最小投影。
// 三个键由写入侧（wafqueue）用与窄行同一套函数算好传进来，汇总口径因此不会和明细漂移；
// 也避开了 waftask 反向 import wafqueue 的环（日志队列正在调 waftask）。
type LogAnalysisRow struct {
	HostCode   string
	Day        int
	ActorKey   string
	PathNorm   string
	UaHash     string
	Rule       string
	Action     string
	StatusCode int
}
