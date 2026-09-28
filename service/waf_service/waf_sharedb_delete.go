package waf_service

import (
	"SamWaf/common/zlog"
	"SamWaf/enums"
	"SamWaf/global"
	"SamWaf/model"
	"SamWaf/utils"
	"SamWaf/wafdb"
	"SamWaf/wafdb/dialect"
	"fmt"
	"os"
	"strings"
)

// 分区的「还剩哪些层」与「主动删除」（E6）。
//
// 两件事以前都没有：
//   - 按层过期之后，一个分区可能只剩安全事件与报文（窄行先到期被丢了），
//     但归档下拉里看不出这一点，选中它再切到访问日志视图就只会得到一句生硬的报错。
//   - 想立刻腾空间时只能去「文件管理」删 .db 文件——那条路**只对 SQLite 有效**，
//     而且删完 share_dbs 记录还在，下拉里仍然列着一个已经不存在的分区。
//     这里按「分区」来删：文件型删文件、服务型丢表，两种部署都把元数据记录一并清掉。

// ShardTierBases 一个归档分区里可能存在的四层基表
var ShardTierBases = []string{
	model.AccessLogTableName,
	model.SecurityEventTableName,
	model.EventPayloadTableName,
	wafdb.LogTableName,
}

// IsLiveShardName 实时库自己的标识，永远不能被当成归档删除
func IsLiveShardName(name string) bool {
	name = strings.TrimSpace(name)
	return name == "" || name == AutoShard || name == enums.DB_LOG || name == "local_log.db" ||
		name == wafdb.LogTableName || name == model.AccessLogTableName
}

// ArchiveSuffix 从归档标识里取出分片后缀（周期键或时间戳），认不出返回空。
// 只认 web_logs_ / access_log_ 两种前缀——与读侧 ResolveTierTables 的口径一致。
func ArchiveSuffix(name string) string {
	for _, base := range []string{wafdb.LogTableName, model.AccessLogTableName} {
		if strings.HasPrefix(name, base+"_") {
			return strings.TrimPrefix(name, base+"_")
		}
	}
	return ""
}

// ShardTierInfo 一个分片 + 它现在还剩哪些层
type ShardTierInfo struct {
	model.ShareDb
	Tiers   []string `json:"tiers"`
	Missing bool     `json:"missing"` // 登记还在，存储已不在
}

// GetAllShareDbWithTiers 列出分片，并（仅服务型数据库）标出每个分片还剩哪些层。
//
// SQLite 不给层信息：它的分区是独立文件，要判断层就得把每个归档文件都打开一遍，
// 列表接口不该付这个代价。前端拿不到 tiers 时就不显示，不去猜。
func (receiver *WafShareDbService) GetAllShareDbWithTiers() ([]ShardTierInfo, error) {
	shards, err := receiver.GetAllShareDbApi()
	if err != nil {
		return nil, err
	}
	out := make([]ShardTierInfo, 0, len(shards))

	var existing map[string]struct{}
	if !dialect.Get().IsFileBased() && global.GWAF_LOCAL_LOG_DB != nil {
		// 一次列表 + 内存里判在不在，比每张表各查一次 information_schema 便宜得多
		if tables, terr := dialect.Get().ListTables(global.GWAF_LOCAL_LOG_DB); terr == nil {
			existing = make(map[string]struct{}, len(tables))
			for _, t := range tables {
				existing[t] = struct{}{}
			}
		}
	}

	for _, s := range shards {
		info := ShardTierInfo{ShareDb: s}
		if !IsLiveShardName(s.FileName) {
			if dialect.Get().IsFileBased() {
				// 只看文件在不在，不打开：分片文件多时列表照样秒回
				info.Missing = wafdb.ShardFileMissing(s.FileName)
			} else if existing != nil {
				if suffix := ArchiveSuffix(s.FileName); suffix != "" {
					for _, base := range ShardTierBases {
						if _, ok := existing[base+"_"+suffix]; ok {
							info.Tiers = append(info.Tiers, base)
						}
					}
				}
				info.Missing = len(info.Tiers) == 0
			}
		}
		out = append(out, info)
	}
	return out, nil
}

// ForceDeleteShard 主动删除一个归档分区，**不看保留期**。
//
// 只删 share_dbs 里登记过的归档分片：名字得对得上记录，才不会被当成「随便丢一张表」的入口。
// 实时库一律拒绝。删完把分片记录与计数缓存一并清掉，否则下拉里会留下一个已经不存在的分区。
func (receiver *WafShareDbService) ForceDeleteShard(name string) (string, error) {
	name = strings.TrimSpace(name)
	if IsLiveShardName(name) {
		return "", fmt.Errorf("实时库不能删除")
	}

	shards, err := receiver.GetAllShareDbApi()
	if err != nil {
		return "", err
	}
	var target *model.ShareDb
	for i := range shards {
		if shards[i].FileName == name {
			target = &shards[i]
			break
		}
	}
	if target == nil {
		return "", fmt.Errorf("没有找到分区 %s，请刷新后重试", name)
	}

	detail := ""
	if dialect.Get().IsFileBased() {
		// 先关掉可能已按需打开的连接，避免删正在被查询的文件
		wafdb.CloseManualLogDb(name)
		base := utils.GetCurrentDir() + "/data/" + name
		removed := 0
		for _, p := range []string{base, base + "-wal", base + "-shm"} {
			if rerr := os.Remove(p); rerr != nil && !os.IsNotExist(rerr) {
				return "", fmt.Errorf("删除归档文件失败: %w", rerr)
			} else if rerr == nil {
				removed++
			}
		}
		detail = fmt.Sprintf("已删除归档文件 %s（含 %d 个关联文件）", name, removed)
	} else {
		suffix := ArchiveSuffix(name)
		if suffix == "" {
			return "", fmt.Errorf("认不出的归档标识：%s", name)
		}
		db := global.GWAF_LOCAL_LOG_DB
		if db == nil {
			return "", fmt.Errorf("日志库未就绪")
		}
		var dropped []string
		for _, base := range ShardTierBases {
			part := base + "_" + suffix
			if !dialect.Get().TableExists(db, part) {
				continue
			}
			// DropPartition 会校验「分区必须属于该基表」，实时表传不进来
			if derr := dialect.Get().DropPartition(db, base, part); derr != nil {
				return "", fmt.Errorf("丢分区表 %s 失败: %w", part, derr)
			}
			dropped = append(dropped, part)
		}
		detail = fmt.Sprintf("已丢分区表 %s", strings.Join(dropped, ", "))
		if len(dropped) == 0 {
			detail = "分区表已不存在，仅清理记录"
		}
	}

	if derr := receiver.DeleteById(target.Id); derr != nil {
		return detail, fmt.Errorf("存储已删除，但清理分片记录失败: %w", derr)
	}
	InvalidateShardCounts()
	zlog.Info("分区管理", "主动删除归档分区", name, "详情", detail)
	return detail, nil
}
