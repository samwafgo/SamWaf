package dialect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gorm.io/gorm"
)

// 时间分区三动词的共用部分（M3/E1）。
//
// 分区在这里的形态是「一段时间一个存储单元」：MySQL/PG 是一张以周期命名的表
// （access_log_202609），SQLite 是一个 .db 文件。**没有走 PG/MySQL 的原生
// PARTITION BY RANGE**：两个引擎都要求分区列出现在每个唯一键里，而 access_log 与
// event_payload 都以 req_uuid 为主键，改成原生分区就得改主键并重建整表搬数据——
// 存量部署上这是一次大爆炸，计划 §5.4 明确要避免。周期表沿用已有的换表与读侧扇出，
// 一行读写代码都不用改，丢分区同样是一条 DROP TABLE。
//
// 文件型引擎（SQLite）的建与丢发生在文件层，dialect 拿不到数据目录，
// 所以这两个动词在 SQLite 上返回明确错误，调用方必须先看 IsFileBased()——
// 与 ShardSwapTable 一致的分工。

// partIdentPattern 分区表名允许的字符。名字是程序按周期拼出来的，
// 但它要拼进 DDL（DDL 不接受占位符），所以进 SQL 前必须先卡一遍。
var partIdentPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// maxIdentLen 三个引擎里最短的标识符上限（MySQL 64）
const maxIdentLen = 64

// checkPartIdent 校验要拼进 DDL 的表名
func checkPartIdent(name string) error {
	if name == "" {
		return fmt.Errorf("分区表名为空")
	}
	if len(name) > maxIdentLen {
		return fmt.Errorf("分区表名 %q 超过 %d 字符", name, maxIdentLen)
	}
	if !partIdentPattern.MatchString(name) {
		return fmt.Errorf("分区表名 %q 含非法字符（只允许字母、数字、下划线，且不以数字开头）", name)
	}
	return nil
}

// checkPartitionPair 校验「基表 + 分区表」这一对：分区表必须真的是该基表的分区，
// 免得把无关的表当分区丢掉。
func checkPartitionPair(baseTable, partTable string) error {
	if err := checkPartIdent(baseTable); err != nil {
		return err
	}
	if err := checkPartIdent(partTable); err != nil {
		return err
	}
	if !strings.HasPrefix(partTable, baseTable+"_") {
		return fmt.Errorf("分区表 %q 不是 %q 的分区（名字必须是 <基表>_<周期>）", partTable, baseTable)
	}
	return nil
}

// shardTmpSuffix ShardSwapTable 换表期间的临时表后缀，不是分区
const shardTmpSuffix = "_shardtmp"

// listPartitionsByPrefix 列分区的共用实现：拿全部表名，筛出 <基表>_<后缀> 形态的。
//
// 三个引擎共用一份：分区就是「名字带周期后缀的表」，各引擎只是 ListTables 的查法不同。
// SQLite 上正常返回空——它按文件分区，一个文件里不会有周期表，这不是错误。
func listPartitionsByPrefix(d DBDialect, db *gorm.DB, baseTable string) ([]string, error) {
	if err := checkPartIdent(baseTable); err != nil {
		return nil, err
	}
	tables, err := d.ListTables(db)
	if err != nil {
		return nil, err
	}
	prefix := baseTable + "_"
	var parts []string
	for _, t := range tables {
		if !strings.HasPrefix(t, prefix) || strings.HasSuffix(t, shardTmpSuffix) {
			continue
		}
		parts = append(parts, t)
	}
	sort.Strings(parts)
	return parts, nil
}
