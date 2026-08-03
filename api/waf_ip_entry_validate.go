package api

import (
	"SamWaf/model"
	"SamWaf/utils"
	"errors"
	"strings"
)

// ipEntryInput 是黑/白名单「新增/编辑」入参中与条目类型相关的部分，
// 抽出来让两边共用同一套校验，避免规则漂移。
type ipEntryInput struct {
	IpType    string
	Ip        string
	GroupCode string
}

// normalizeIPEntry 归一并校验一条黑/白名单条目，返回可直接落库的 (ipType, ip, groupCode)。
//
// 这是黑/白名单第一次有 IP 格式校验——此前 AddApi/ModifyApi 完全不校验，
// 任意字符串都能写进去。校验只加在写入路径，加载路径依旧宽容，
// 免得存量脏数据在升级后把站点卡死。
func normalizeIPEntry(in ipEntryInput) (ipType string, ip string, groupCode string, err error) {
	ipType = strings.TrimSpace(in.IpType)
	ip = strings.TrimSpace(in.Ip)
	groupCode = strings.TrimSpace(in.GroupCode)

	if ipType == model.IPEntryTypeGroup {
		if groupCode == "" {
			return "", "", "", errors.New("请选择要引用的IP组")
		}
		if wafIPGroupService.GetDetailByCodeApi(groupCode).GroupCode == "" {
			return "", "", "", errors.New("IP组不存在: " + groupCode)
		}
		// 引用组时 Ip 无意义，清空避免脏数据误导后续判定与导出
		return model.IPEntryTypeGroup, "", groupCode, nil
	}

	// 单条：空串与 "ip" 都按单条处理（存量行的 ip_type 为空）
	if ip == "" {
		return "", "", "", errors.New("IP不能为空")
	}
	if utils.IsCatchAllIPPattern(ip) {
		return "", "", "", errors.New("该写法会匹配所有IP，风险过高；如确需全匹配请显式填写 0.0.0.0/0 或 ::/0")
	}
	if ok, msg := utils.IsValidIPPattern(ip); !ok {
		return "", "", "", errors.New("IP格式不正确: " + msg)
	}
	return model.IPEntryTypeIP, ip, "", nil
}

// checkSystemLayerSupported 判断一条黑名单条目能否下发到系统防火墙层。
//
// iptables / netsh 只认单 IP 与 CIDR：通配符、区间、IP 组引用都无法表达。
// 这里必须挡住——底层 firewall 包拿到这类字符串会报错或行为未定义。
func checkSystemLayerSupported(ipType, ip string) error {
	if ipType == model.IPEntryTypeGroup {
		return errors.New("引用IP组的条目只能作用于WAF应用层，系统防火墙不支持")
	}
	if ok, _ := utils.IsValidIPOrNetwork(ip); !ok {
		return errors.New("系统防火墙只支持单个IP或CIDR网段，不支持通配符与区间写法: " + ip)
	}
	return nil
}
