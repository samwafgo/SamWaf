package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/wafdb"
	"time"
)

// ExportLogRange 按时间段导出日志：与列表查询同一套按时间扇出选片，
// 实时库与命中的归档分区都作为数据源。只读实时库会在「时间段落在已归档分区」时导出空表。
// startTime/endTime 形如 2006-01-02 15:04:05，空 = 不限制。
func (receiver *WafLogService) ExportLogRange(outPath, startTime, endTime string, tiers map[string]bool) (map[string]int64, error) {
	fromMs := int64(0)
	toMs := time.Now().UnixMilli()
	if startTime != "" {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", startTime, time.Local); err == nil {
			fromMs = t.UnixMilli()
		}
	}
	if endTime != "" {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", endTime, time.Local); err == nil {
			toMs = t.UnixMilli()
		}
	}

	sources := make([]wafdb.ExportSource, 0, 4)
	for _, sh := range candidateShards(fromMs, toMs, false) {
		tables := wafdb.ResolveExportTables(sh.Name)
		switch {
		case tables.Err != nil:
			// 打不开的分区跳过而不是整单失败：剩下的分区照常导，
			// 缺的那个在日志里留名，界面按层计数也能看出少没少
			zlog.Warn("日志导出跳过分片", "shard", sh.Name, "error", tables.Err.Error())
			continue
		case tables.Empty:
			continue
		}
		sources = append(sources, wafdb.ExportSource{Shard: sh.Name, Tables: tables})
	}
	return wafdb.ExportLogRangeDb(outPath, startTime, endTime, tiers, sources)
}
