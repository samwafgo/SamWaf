package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/innerbean"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"time"

	"gorm.io/gorm"
)

// 从日志流批量聚合统计并写入统计库（不依赖日志入库）。
// 会按以下维度做增量统计：
// 1) 主机日聚合 (host_code, action, day)
// 2) IP日聚合 (host_code, ip, action, day)
// 3) 城市日聚合 (host_code, country, province, city, action, day)
// 4) IP标签计数 (ip, rule)
func CollectStatsFromLogs(logs []*innerbean.WebLog) {
	if len(logs) == 0 {
		return
	}

	// 添加输入日志数量的调试信息
	zlog.Debug("统计收集器开始处理", "日志数量", len(logs))

	// 安全检查：需要相关DB已初始化
	if global.GWAF_LOCAL_STATS_DB == nil || global.GWAF_LOCAL_DB == nil {
		zlog.Debug("统计收集器", "数据库未初始化，跳过处理")
		return
	}

	type hostKey struct {
		TenantId string
		UserCode string
		HostCode string
		Action   string
		Day      int
		Host     string
	}
	type ipKey struct {
		TenantId string
		UserCode string
		HostCode string
		Action   string
		Day      int
		Host     string
		IP       string
	}
	type cityKey struct {
		TenantId string
		UserCode string
		HostCode string
		Action   string
		Day      int
		Host     string
		Country  string
		Province string
		City     string
	}
	type ipTagKey struct {
		IP   string
		Rule string
	}

	hostAgg := make(map[hostKey]int)
	ipAgg := make(map[ipKey]int)
	cityAgg := make(map[cityKey]int)
	ipTagAgg := make(map[ipTagKey]int64)

	for _, lg := range logs {
		// 主机聚合
		hk := hostKey{
			TenantId: lg.TenantId,
			UserCode: lg.USER_CODE,
			HostCode: lg.HOST_CODE,
			Action:   lg.ACTION,
			Day:      lg.Day,
			Host:     lg.HOST,
		}
		hostAgg[hk]++

		// IP聚合
		ik := ipKey{
			TenantId: lg.TenantId,
			UserCode: lg.USER_CODE,
			HostCode: lg.HOST_CODE,
			Action:   lg.ACTION,
			Day:      lg.Day,
			Host:     lg.HOST,
			IP:       lg.SRC_IP,
		}
		ipAgg[ik]++

		// 城市聚合
		ck := cityKey{
			TenantId: lg.TenantId,
			UserCode: lg.USER_CODE,
			HostCode: lg.HOST_CODE,
			Action:   lg.ACTION,
			Day:      lg.Day,
			Host:     lg.HOST,
			Country:  lg.COUNTRY,
			Province: lg.PROVINCE,
			City:     lg.CITY,
		}
		cityAgg[ck]++

		// IPTag 聚合
		rule := lg.RULE
		if rule == "" {
			rule = "正常"
		}
		ipTagAgg[ipTagKey{IP: lg.SRC_IP, Rule: rule}]++
	}

	// 添加聚合结果的调试信息
	zlog.Debug("聚合计算完成",
		"主机聚合数量", len(hostAgg),
		"IP聚合数量", len(ipAgg),
		"城市聚合数量", len(cityAgg),
		"IP标签聚合数量", len(ipTagAgg))

	now := customtype.JsonTime(time.Now())

	// 1) 主机日聚合 增量
	hostUpdateCount := 0
	hostInsertCount := 0
	for k, delta := range hostAgg {
		tx := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsDay{}).
			Where("tenant_id = ? and user_code = ? and host_code = ? and type = ? and day = ?",
				k.TenantId, k.UserCode, k.HostCode, k.Action, k.Day).
			Updates(map[string]interface{}{
				"Count":       gorm.Expr("Count + ?", delta),
				"UPDATE_TIME": now,
			})
		if tx.Error != nil {
			zlog.Debug("主机聚合更新失败", "错误", tx.Error.Error(), "主机", k.HostCode, "动作", k.Action)
			continue
		}
		if tx.RowsAffected == 0 {
			// 创建新行
			err := global.GWAF_LOCAL_STATS_DB.Create(&model.StatsDay{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   k.UserCode,
					Tenant_ID:   k.TenantId,
					CREATE_TIME: now,
					UPDATE_TIME: now,
				},
				HostCode: k.HostCode,
				Day:      k.Day,
				Host:     k.Host,
				Type:     k.Action,
				Count:    delta,
			}).Error
			if err != nil {
				zlog.Debug("主机聚合插入失败", "错误", err.Error(), "主机", k.HostCode, "动作", k.Action)
			} else {
				hostInsertCount++
			}
		} else {
			hostUpdateCount++
		}
	}
	zlog.Debug("主机聚合处理完成", "更新记录数", hostUpdateCount, "插入记录数", hostInsertCount)

	// 2) IP日聚合 增量
	ipUpdateCount := 0
	ipInsertCount := 0
	for k, delta := range ipAgg {
		tx := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPDay{}).
			Where("tenant_id = ? and user_code = ? and host_code = ? and ip = ? and type = ? and day = ?",
				k.TenantId, k.UserCode, k.HostCode, k.IP, k.Action, k.Day).
			Updates(map[string]interface{}{
				"Count":       gorm.Expr("Count + ?", delta),
				"UPDATE_TIME": now,
			})
		if tx.Error != nil {
			zlog.Debug("IP聚合更新失败", "错误", tx.Error.Error(), "IP", k.IP, "动作", k.Action)
			continue
		}
		if tx.RowsAffected == 0 {
			err := global.GWAF_LOCAL_STATS_DB.Create(&model.StatsIPDay{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   k.UserCode,
					Tenant_ID:   k.TenantId,
					CREATE_TIME: now,
					UPDATE_TIME: now,
				},
				HostCode: k.HostCode,
				Day:      k.Day,
				Host:     k.Host,
				Type:     k.Action,
				Count:    delta,
				IP:       k.IP,
			}).Error
			if err != nil {
				zlog.Debug("IP聚合插入失败", "错误", err.Error(), "IP", k.IP, "动作", k.Action)
			} else {
				ipInsertCount++
			}
		} else {
			ipUpdateCount++
		}
	}
	zlog.Debug("IP聚合处理完成", "更新记录数", ipUpdateCount, "插入记录数", ipInsertCount)

	// 3) 城市日聚合 增量
	cityUpdateCount := 0
	cityInsertCount := 0
	for k, delta := range cityAgg {
		tx := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsIPCityDay{}).
			Where("tenant_id = ? and user_code = ? and host_code = ? and country = ? and province = ? and city = ? and type = ? and day = ?",
				k.TenantId, k.UserCode, k.HostCode, k.Country, k.Province, k.City, k.Action, k.Day).
			Updates(map[string]interface{}{
				"Count":       gorm.Expr("Count + ?", delta),
				"UPDATE_TIME": now,
			})
		if tx.Error != nil {
			zlog.Debug("城市聚合更新失败", "错误", tx.Error.Error(), "城市", k.City, "动作", k.Action)
			continue
		}
		if tx.RowsAffected == 0 {
			err := global.GWAF_LOCAL_STATS_DB.Create(&model.StatsIPCityDay{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   k.UserCode,
					Tenant_ID:   k.TenantId,
					CREATE_TIME: now,
					UPDATE_TIME: now,
				},
				HostCode: k.HostCode,
				Day:      k.Day,
				Host:     k.Host,
				Type:     k.Action,
				Count:    delta,
				Country:  k.Country,
				Province: k.Province,
				City:     k.City,
			}).Error
			if err != nil {
				zlog.Debug("城市聚合插入失败", "错误", err.Error(), "城市", k.City, "动作", k.Action)
			} else {
				cityInsertCount++
			}
		} else {
			cityUpdateCount++
		}
	}
	zlog.Debug("城市聚合处理完成", "更新记录数", cityUpdateCount, "插入记录数", cityInsertCount)

	// 4) IPTag 增量（根据配置选择数据库）
	ipTagUpdateCount := 0
	ipTagInsertCount := 0
	ipTagDB := global.GetIPTagDB() // 使用封装方法获取数据库连接
	for k, delta := range ipTagAgg {
		tx := ipTagDB.Model(&model.IPTag{}).
			Where("tenant_id = ? and user_code = ? and ip = ? and ip_tag = ?",
				global.GWAF_TENANT_ID, global.GWAF_USER_CODE, k.IP, k.Rule).
			Updates(map[string]interface{}{
				"Cnt":         gorm.Expr("Cnt + ?", delta),
				"UPDATE_TIME": now,
			})
		if tx.Error != nil {
			zlog.Debug("IP标签更新失败", "错误", tx.Error.Error(), "IP", k.IP, "规则", k.Rule)
			continue
		}
		if tx.RowsAffected == 0 {
			err := ipTagDB.Create(&model.IPTag{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   global.GWAF_USER_CODE,
					Tenant_ID:   global.GWAF_TENANT_ID,
					CREATE_TIME: now,
					UPDATE_TIME: now,
				},
				IP:      k.IP,
				IPTag:   k.Rule,
				Cnt:     delta,
				Remarks: "",
			}).Error
			if err != nil {
				zlog.Debug("IP标签插入失败", "错误", err.Error(), "IP", k.IP, "规则", k.Rule)
			} else {
				ipTagInsertCount++
			}
		} else {
			ipTagUpdateCount++
		}
	}
	zlog.Debug("IP标签处理完成", "更新记录数", ipTagUpdateCount, "插入记录数", ipTagInsertCount)

	// 总结统计信息
	zlog.Debug("统计收集器处理完成",
		"总处理日志数", len(logs),
		"主机聚合", map[string]interface{}{"更新": hostUpdateCount, "插入": hostInsertCount},
		"IP聚合", map[string]interface{}{"更新": ipUpdateCount, "插入": ipInsertCount},
		"城市聚合", map[string]interface{}{"更新": cityUpdateCount, "插入": cityInsertCount},
		"IP标签", map[string]interface{}{"更新": ipTagUpdateCount, "插入": ipTagInsertCount})
}
