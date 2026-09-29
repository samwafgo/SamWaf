// Package partition 时间分区的口径：分区键怎么算、分区叫什么名、一段时间范围落在哪些分区上。
//
// 纯函数、不碰数据库；真正的建/列/丢在 `wafdb/dialect` 的三个动词里。
//
// 粒度 = 月（D3 定案）。一个分区就是「一段时间的独立存储单元」：
// SQLite 下是一个 `.db` 文件，MySQL/PG 下是一张以周期命名的表。两边都沿用已有的
// 换文件 / 换表 + 读侧扇出机制，所以这里只需要让「周期键 ↔ 时间范围 ↔ 存储单元名字」能互相换算。
//
// 与按体积切分的旧分片共存：旧分片名字带 14 位时间戳（`access_log_20260921153045`），
// 周期分区是 6 位（`access_log_202609`，同周期内被迫再切时是 `access_log_202609_02`）。
// `KeyFromName` 只认 6 位，旧分片认不出来是**故意的**——
// 它们的时间范围只能查 `share_dbs` 的起止时间，不能从名字算。
package partition

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// KeyLayout 周期键的格式：年月，如 202609
const KeyLayout = "200601"

// keyLen 周期键长度，用来和旧的 14 位时间戳分片区分开
const keyLen = 6

// KeyOf 返回某个时刻所属的周期键。按本地时区算——保留期、清理任务、
// 界面上的「时间段」都是本地时间口径，这里跟着走才不会在月初差一天。
func KeyOf(t time.Time) string {
	return t.Format(KeyLayout)
}

// Range 返回周期键覆盖的时间范围，左闭右开 [start, end)。
func Range(key string) (time.Time, time.Time, error) {
	if !IsKey(key) {
		return time.Time{}, time.Time{}, fmt.Errorf("非法周期键: %q（应形如 202609）", key)
	}
	start, err := time.ParseInLocation(KeyLayout, key, time.Local)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("解析周期键 %q 失败: %w", key, err)
	}
	return start, start.AddDate(0, 1, 0), nil
}

// IsKey 判断一个字符串是不是合法周期键（6 位数字且月份在 1~12）
func IsKey(key string) bool {
	if len(key) != keyLen {
		return false
	}
	n, err := strconv.Atoi(key)
	if err != nil || n <= 0 {
		return false
	}
	month := n % 100
	return month >= 1 && month <= 12
}

// TableName 返回周期分区表名，如 TableName("access_log", "202609") = access_log_202609
func TableName(base, key string) string {
	return base + "_" + key
}

// FileName 返回 SQLite 周期分区的文件名，如 FileName("202609") = local_log_202609.db
func FileName(key string) string {
	return "local_log_" + key + ".db"
}

// TableNameSeq 返回同一周期内第 seq 个分区表名（seq >= 2 才带序号）。
// 正常一个周期一个分区，只有体积/行数在周期内就超限、被迫提前切的时候才会用到——
// 那是异常兜底，不是常态。
func TableNameSeq(base, key string, seq int) string {
	if seq <= 1 {
		return TableName(base, key)
	}
	return fmt.Sprintf("%s_%s_%02d", base, key, seq)
}

// FileNameSeq 同 TableNameSeq，SQLite 文件版
func FileNameSeq(key string, seq int) string {
	if seq <= 1 {
		return FileName(key)
	}
	return fmt.Sprintf("local_log_%s_%02d.db", key, seq)
}

// KeyFromName 从存储单元名字里取出周期键：表名（access_log_202609）、
// 文件名（local_log_202609.db）、带兜底序号的（access_log_202609_02）都认。
// 按体积切出来的旧分片（14 位时间戳）返回 false。
//
// 只看最后两段：再往前找就会把业务表名里的数字段误当周期键。
func KeyFromName(name string) (string, bool) {
	name = strings.TrimSuffix(name, ".db")
	parts := strings.Split(name, "_")
	for i := len(parts) - 1; i >= 0 && i >= len(parts)-2; i-- {
		if IsKey(parts[i]) {
			return parts[i], true
		}
	}
	return "", false
}

// KeysBetween 返回覆盖 [from, to] 的全部周期键，升序、去重。
// from 晚于 to 时返回 nil。读侧的「候选分区裁剪」就靠它——
// 从「猜哪些分片可能有数据」变成纯算术。
func KeysBetween(from, to time.Time) []string {
	if from.After(to) {
		return nil
	}
	var keys []string
	cur := time.Date(from.Year(), from.Month(), 1, 0, 0, 0, 0, time.Local)
	last := time.Date(to.Year(), to.Month(), 1, 0, 0, 0, 0, time.Local)
	for !cur.After(last) {
		keys = append(keys, KeyOf(cur))
		cur = cur.AddDate(0, 1, 0)
	}
	return keys
}

// Expired 判断一个周期分区是否整段都超出了保留期。
//
// 判据是分区的**结束时刻**而不是开始时刻：9 月的分区装着 9/1~9/30 的数据，
// 保留 30 天时 10/5 还有 9/5 之后的数据在保留期内，这时候丢整个分区就是丢用户还该看到的数据。
// retentionDays <= 0 表示不按天清理，一律不过期。
func Expired(key string, retentionDays int, now time.Time) bool {
	if retentionDays <= 0 {
		return false
	}
	_, end, err := Range(key)
	if err != nil {
		return false
	}
	return !end.After(now.AddDate(0, 0, -retentionDays))
}
