package dialect

import (
	"strings"
	"testing"
)

// 分区表名要拼进 DDL（DDL 不接受占位符），所以校验是这里唯一的防线。
func TestCheckPartIdentRejectsUnsafeNames(t *testing.T) {
	bad := []string{
		"",
		"access log",
		"access_log; DROP TABLE hosts",
		"access_log\"",
		"access_log`",
		"access_log'",
		"access_log--",
		"202609_access", // 以数字开头
		strings.Repeat("a", 65),
	}
	for _, name := range bad {
		if err := checkPartIdent(name); err == nil {
			t.Errorf("%q 应被拒绝", name)
		}
	}
	for _, name := range []string{"access_log", "access_log_202609", "event_payload_202512"} {
		if err := checkPartIdent(name); err != nil {
			t.Errorf("%q 应通过: %v", name, err)
		}
	}
}

// 丢分区是不可逆动作，必须确认这张表真是该基表的分区
func TestCheckPartitionPairRequiresPrefix(t *testing.T) {
	if err := checkPartitionPair("access_log", "access_log_202609"); err != nil {
		t.Fatalf("同族分区应通过: %v", err)
	}
	for _, part := range []string{"hosts", "security_event_202609", "access_log", "xaccess_log_202609"} {
		if err := checkPartitionPair("access_log", part); err == nil {
			t.Errorf("%q 不是 access_log 的分区，应被拒绝", part)
		}
	}
}

// SQLite 按文件分区：建与丢必须明确报错，免得调用方以为已经建好/删掉了
func TestSQLitePartitionVerbsAreNotApplicable(t *testing.T) {
	d := &SQLiteDialect{}
	if err := d.CreatePartition(nil, "access_log", "access_log_202609"); err == nil {
		t.Error("SQLite 的 CreatePartition 应返回不适用错误")
	}
	if err := d.DropPartition(nil, "access_log", "access_log_202609"); err == nil {
		t.Error("SQLite 的 DropPartition 应返回不适用错误")
	}
}
