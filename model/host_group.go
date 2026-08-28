package model

import (
	"SamWaf/model/baseorm"
)

// HostGroup 是网站的组织分组（文件夹语义）。
//
// 它只影响管理端的检索与批量选择：列表左栏按组导航、批量操作时一次选中一批。
// 分组不承载任何防护配置，也不参与请求期判定——网站离开分组照常运行。
// 因此 group_code 不下发引擎、变更也不触发主机变更通知；
// 将来若要让分组参与判定，必须先补上通知，否则引擎缓存里的主机快照是旧的。
//
// 表名/列名有意避开 waf_sql_query 的敏感规则（不含 config/account，
// 列名不用 value/params/key），参照 model/ui_preference.go 的说明。
type HostGroup struct {
	baseorm.BaseOrm
	GroupName string `gorm:"size:255" json:"group_name"` //分组名称
	GroupCode string `gorm:"size:64"  json:"group_code"` //分组短码，创建后不可修改（hosts.group_code 引用它）
	Color     string `gorm:"size:16"  json:"color"`      //标签色，仅取预设枚举（HostGroupColors）
	SortNo    int    `json:"sort_no"`                    //排序权重，越小越靠前
	Remarks   string `gorm:"size:500" json:"remarks"`    //备注
	HostCount int    `gorm:"-"        json:"host_count"` //组内网站数，列表接口聚合填充，不落库
}

func (HostGroup) TableName() string {
	return "host_group"
}

// HostGroupNone 是「未分组」的保留筛选值。
//
// 走一个保留值而不是空串，是因为空串在 JSON 里与「不筛选」无法区分；
// 服务层收到它会展开成 (group_code = '' or group_code is null) ——
// 存量行落的是 NULL 还是空串取决于数据库，只判一种会漏掉一半站点。
const HostGroupNone = "__none__"

// HostGroupColors 分组标签色白名单。
//
// 颜色是唯一会被渲染进管理端 DOM 属性的分组字段，因此只收预设值，
// 不接受任意字符串/十六进制。
var HostGroupColors = []string{
	"#0052D9", // 蓝
	"#2BA471", // 绿
	"#E37318", // 橙
	"#D54941", // 红
	"#834EC2", // 紫
	"#0594FA", // 青
	"#8B8B8B", // 灰
	"#D4A017", // 金
}

// IsValidHostGroupColor 判断颜色是否在预设白名单内
func IsValidHostGroupColor(color string) bool {
	for _, c := range HostGroupColors {
		if c == color {
			return true
		}
	}
	return false
}
