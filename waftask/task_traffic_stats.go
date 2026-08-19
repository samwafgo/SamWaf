package waftask

import (
	"SamWaf/common/uuid"
	"SamWaf/common/zlog"
	"SamWaf/customtype"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/model/baseorm"
	"time"

	"gorm.io/gorm"
)

// 站点流量落库：把引擎侧累加的真实进出字节按天/小时增量写进统计库。
//
// 与 CollectStatsFromLogs 的分工（issue #930 后）：
//   - 本任务：只写 traffic_in / traffic_out，数据来自引擎字节计量，与日志无关；
//   - 日志聚合：只写 total/attack/normal_count 与 total_time_spent。
//
// 两边都用「先 Update 累加、影响 0 行再 Create」的写法，谁先建行都不冲突。

// trafficDayAgg 合并后的天级增量
type trafficDayAgg struct {
	HostCode string
	Host     string
	Day      int
	In       int64
	Out      int64
}

// trafficHourAgg 合并后的小时级增量
type trafficHourAgg struct {
	HostCode string
	Host     string
	HourTime int64
	In       int64
	Out      int64
}

// planTrafficUpserts 把 Drain 出来的桶合并成天级/小时级两组增量。
// 纯函数：同一天的多个整点桶会合并成一条天级增量，全零桶直接丢弃。
func planTrafficUpserts(list []global.TrafficSnapshot) ([]trafficDayAgg, []trafficHourAgg) {
	type dayKey struct {
		HostCode string
		Day      int
	}
	type hourKey struct {
		HostCode string
		HourTime int64
	}
	dayMap := make(map[dayKey]*trafficDayAgg)
	hourMap := make(map[hourKey]*trafficHourAgg)
	var days []*trafficDayAgg
	var hours []*trafficHourAgg

	for _, s := range list {
		if s.HostCode == "" || (s.In <= 0 && s.Out <= 0) {
			continue
		}
		dk := dayKey{HostCode: s.HostCode, Day: s.Day}
		d := dayMap[dk]
		if d == nil {
			d = &trafficDayAgg{HostCode: s.HostCode, Host: s.Host, Day: s.Day}
			dayMap[dk] = d
			days = append(days, d)
		}
		d.In += s.In
		d.Out += s.Out

		hk := hourKey{HostCode: s.HostCode, HourTime: s.HourTime}
		h := hourMap[hk]
		if h == nil {
			h = &trafficHourAgg{HostCode: s.HostCode, Host: s.Host, HourTime: s.HourTime}
			hourMap[hk] = h
			hours = append(hours, h)
		}
		h.In += s.In
		h.Out += s.Out
	}

	dayList := make([]trafficDayAgg, 0, len(days))
	for _, d := range days {
		dayList = append(dayList, *d)
	}
	hourList := make([]trafficHourAgg, 0, len(hours))
	for _, h := range hours {
		hourList = append(hourList, *h)
	}
	return dayList, hourList
}

// TaskTrafficFlush 定时任务入口（默认 30s 一次）
func TaskTrafficFlush() {
	FlushTrafficStats()
}

// FlushTrafficStats 把内存里累计的流量落库。
// 库没就绪或正在切库时**不取走**内存里的增量，等下个周期，避免把字节丢在切库窗口里。
func FlushTrafficStats() {
	if global.GWAF_LOCAL_STATS_DB == nil {
		return
	}
	if global.GDATA_CURRENT_CHANGE {
		zlog.Debug("流量统计落库", "正在切换数据库，本轮跳过")
		return
	}

	list := global.DrainTraffic()
	if len(list) == 0 {
		return
	}

	if err := writeTrafficStats(global.GWAF_LOCAL_STATS_DB, list); err != nil {
		// 整笔事务回滚了，把增量放回累加器下轮重试，绝不静默丢数
		global.RestoreTraffic(list)
		zlog.Error("流量统计落库失败，已退回内存等待重试", "错误", err.Error(), "桶数", len(list))
		return
	}
	zlog.Debug("流量统计落库完成", "桶数", len(list))
}

// writeTrafficStats 单事务写入：要么全成，要么全退（避免部分成功后重试造成重复计数）
func writeTrafficStats(db *gorm.DB, list []global.TrafficSnapshot) error {
	days, hours := planTrafficUpserts(list)
	if len(days) == 0 && len(hours) == 0 {
		return nil
	}
	now := customtype.JsonTime(time.Now())

	return db.Transaction(func(tx *gorm.DB) error {
		for _, d := range days {
			res := tx.Model(&model.StatsSiteDay{}).
				Where("tenant_id = ? and user_code = ? and host_code = ? and day = ?",
					global.GWAF_TENANT_ID, global.GWAF_USER_CODE, d.HostCode, d.Day).
				Updates(map[string]interface{}{
					"traffic_in":  gorm.Expr("traffic_in + ?", d.In),
					"traffic_out": gorm.Expr("traffic_out + ?", d.Out),
					"update_time": now,
				})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				if err := tx.Create(&model.StatsSiteDay{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: now,
						UPDATE_TIME: now,
					},
					HostCode:   d.HostCode,
					Day:        d.Day,
					Host:       d.Host,
					TrafficIn:  d.In,
					TrafficOut: d.Out,
				}).Error; err != nil {
					return err
				}
			}
		}

		for _, h := range hours {
			res := tx.Model(&model.StatsSiteHour{}).
				Where("tenant_id = ? and user_code = ? and host_code = ? and hour_time = ?",
					global.GWAF_TENANT_ID, global.GWAF_USER_CODE, h.HostCode, h.HourTime).
				Updates(map[string]interface{}{
					"traffic_in":  gorm.Expr("traffic_in + ?", h.In),
					"traffic_out": gorm.Expr("traffic_out + ?", h.Out),
					"update_time": now,
				})
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 0 {
				if err := tx.Create(&model.StatsSiteHour{
					BaseOrm: baseorm.BaseOrm{
						Id:          uuid.GenUUID(),
						USER_CODE:   global.GWAF_USER_CODE,
						Tenant_ID:   global.GWAF_TENANT_ID,
						CREATE_TIME: now,
						UPDATE_TIME: now,
					},
					HostCode:   h.HostCode,
					HourTime:   h.HourTime,
					Host:       h.Host,
					TrafficIn:  h.In,
					TrafficOut: h.Out,
				}).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}
