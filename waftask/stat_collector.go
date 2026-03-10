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
	// 站点天级聚合 key
	type siteDayKey struct {
		TenantId string
		UserCode string
		HostCode string
		Day      int
		Host     string
	}
	// 站点小时级聚合 key
	type siteHourKey struct {
		TenantId string
		UserCode string
		HostCode string
		HourTime int64 // 整点unix时间戳
		Host     string
	}
	// 站点聚合值
	type siteAggVal struct {
		TotalCount     int64
		AttackCount    int64
		NormalCount    int64
		TrafficIn      int64
		TrafficOut     int64
		TotalTimeSpent int64
	}

	hostAgg := make(map[hostKey]int)
	ipAgg := make(map[ipKey]int)
	cityAgg := make(map[cityKey]int)
	ipTagAgg := make(map[ipTagKey]int64)
	siteDayAgg := make(map[siteDayKey]*siteAggVal)
	siteHourAgg := make(map[siteHourKey]*siteAggVal)

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

		// 站点天级聚合
		sdk := siteDayKey{
			TenantId: lg.TenantId,
			UserCode: lg.USER_CODE,
			HostCode: lg.HOST_CODE,
			Day:      lg.Day,
			Host:     lg.HOST,
		}
		if siteDayAgg[sdk] == nil {
			siteDayAgg[sdk] = &siteAggVal{}
		}
		sdv := siteDayAgg[sdk]
		sdv.TotalCount++
		if lg.ACTION == "阻止" {
			sdv.AttackCount++
		} else {
			sdv.NormalCount++
		}
		sdv.TrafficIn += lg.CONTENT_LENGTH
		sdv.TrafficOut += lg.RES_CONTENT_LENGTH
		sdv.TotalTimeSpent += lg.TimeSpent

		// 站点小时级聚合（将时间戳截断到整点，注意UNIX_ADD_TIME是毫秒）
		hourTs := (lg.UNIX_ADD_TIME / 1000 / 3600) * 3600
		shk := siteHourKey{
			TenantId: lg.TenantId,
			UserCode: lg.USER_CODE,
			HostCode: lg.HOST_CODE,
			HourTime: hourTs,
			Host:     lg.HOST,
		}
		if siteHourAgg[shk] == nil {
			siteHourAgg[shk] = &siteAggVal{}
		}
		shv := siteHourAgg[shk]
		shv.TotalCount++
		if lg.ACTION == "阻止" {
			shv.AttackCount++
		} else {
			shv.NormalCount++
		}
		shv.TrafficIn += lg.CONTENT_LENGTH
		shv.TrafficOut += lg.RES_CONTENT_LENGTH
		shv.TotalTimeSpent += lg.TimeSpent
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

	// 5) 站点天级聚合 增量
	siteDayUpdateCount := 0
	siteDayInsertCount := 0
	for k, v := range siteDayAgg {
		if k.HostCode == "" {
			continue
		}
		tx := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteDay{}).
			Where("tenant_id = ? and user_code = ? and host_code = ? and day = ?",
				k.TenantId, k.UserCode, k.HostCode, k.Day).
			Updates(map[string]interface{}{
				"total_count":      gorm.Expr("total_count + ?", v.TotalCount),
				"attack_count":     gorm.Expr("attack_count + ?", v.AttackCount),
				"normal_count":     gorm.Expr("normal_count + ?", v.NormalCount),
				"traffic_in":       gorm.Expr("traffic_in + ?", v.TrafficIn),
				"traffic_out":      gorm.Expr("traffic_out + ?", v.TrafficOut),
				"total_time_spent": gorm.Expr("total_time_spent + ?", v.TotalTimeSpent),
				"update_time":      now,
			})
		if tx.Error != nil {
			zlog.Debug("站点天聚合更新失败", "错误", tx.Error.Error(), "主机", k.HostCode)
			continue
		}
		if tx.RowsAffected == 0 {
			err := global.GWAF_LOCAL_STATS_DB.Create(&model.StatsSiteDay{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   k.UserCode,
					Tenant_ID:   k.TenantId,
					CREATE_TIME: now,
					UPDATE_TIME: now,
				},
				HostCode:       k.HostCode,
				Day:            k.Day,
				Host:           k.Host,
				TotalCount:     v.TotalCount,
				AttackCount:    v.AttackCount,
				NormalCount:    v.NormalCount,
				TrafficIn:      v.TrafficIn,
				TrafficOut:     v.TrafficOut,
				TotalTimeSpent: v.TotalTimeSpent,
			}).Error
			if err != nil {
				zlog.Debug("站点天聚合插入失败", "错误", err.Error(), "主机", k.HostCode)
			} else {
				siteDayInsertCount++
			}
		} else {
			siteDayUpdateCount++
		}
	}
	zlog.Debug("站点天聚合处理完成", "更新记录数", siteDayUpdateCount, "插入记录数", siteDayInsertCount)

	// 6) 站点小时级聚合 增量
	siteHourUpdateCount := 0
	siteHourInsertCount := 0
	for k, v := range siteHourAgg {
		if k.HostCode == "" {
			continue
		}
		tx := global.GWAF_LOCAL_STATS_DB.Model(&model.StatsSiteHour{}).
			Where("tenant_id = ? and user_code = ? and host_code = ? and hour_time = ?",
				k.TenantId, k.UserCode, k.HostCode, k.HourTime).
			Updates(map[string]interface{}{
				"total_count":      gorm.Expr("total_count + ?", v.TotalCount),
				"attack_count":     gorm.Expr("attack_count + ?", v.AttackCount),
				"normal_count":     gorm.Expr("normal_count + ?", v.NormalCount),
				"traffic_in":       gorm.Expr("traffic_in + ?", v.TrafficIn),
				"traffic_out":      gorm.Expr("traffic_out + ?", v.TrafficOut),
				"total_time_spent": gorm.Expr("total_time_spent + ?", v.TotalTimeSpent),
				"update_time":      now,
			})
		if tx.Error != nil {
			zlog.Debug("站点小时聚合更新失败", "错误", tx.Error.Error(), "主机", k.HostCode)
			continue
		}
		if tx.RowsAffected == 0 {
			err := global.GWAF_LOCAL_STATS_DB.Create(&model.StatsSiteHour{
				BaseOrm: baseorm.BaseOrm{
					Id:          uuid.GenUUID(),
					USER_CODE:   k.UserCode,
					Tenant_ID:   k.TenantId,
					CREATE_TIME: now,
					UPDATE_TIME: now,
				},
				HostCode:       k.HostCode,
				HourTime:       k.HourTime,
				Host:           k.Host,
				TotalCount:     v.TotalCount,
				AttackCount:    v.AttackCount,
				NormalCount:    v.NormalCount,
				TrafficIn:      v.TrafficIn,
				TrafficOut:     v.TrafficOut,
				TotalTimeSpent: v.TotalTimeSpent,
			}).Error
			if err != nil {
				zlog.Debug("站点小时聚合插入失败", "错误", err.Error(), "主机", k.HostCode)
			} else {
				siteHourInsertCount++
			}
		} else {
			siteHourUpdateCount++
		}
	}
	zlog.Debug("站点小时聚合处理完成", "更新记录数", siteHourUpdateCount, "插入记录数", siteHourInsertCount)

	// 自动清理超过3天的小时级数据
	expireTs := time.Now().Add(-72 * time.Hour).Unix()
	if err := global.GWAF_LOCAL_STATS_DB.
		Where("hour_time < ?", expireTs).
		Delete(&model.StatsSiteHour{}).Error; err != nil {
		zlog.Debug("清理过期小时统计失败", "错误", err.Error())
	}

	// 总结统计信息
	zlog.Debug("统计收集器处理完成",
		"总处理日志数", len(logs),
		"主机聚合", map[string]interface{}{"更新": hostUpdateCount, "插入": hostInsertCount},
		"IP聚合", map[string]interface{}{"更新": ipUpdateCount, "插入": ipInsertCount},
		"城市聚合", map[string]interface{}{"更新": cityUpdateCount, "插入": cityInsertCount},
		"IP标签", map[string]interface{}{"更新": ipTagUpdateCount, "插入": ipTagInsertCount},
		"站点天聚合", map[string]interface{}{"更新": siteDayUpdateCount, "插入": siteDayInsertCount},
		"站点小时聚合", map[string]interface{}{"更新": siteHourUpdateCount, "插入": siteHourInsertCount})
}
