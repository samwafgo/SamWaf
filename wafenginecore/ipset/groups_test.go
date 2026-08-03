package ipset

import (
	"net"
	"strconv"
	"sync"
	"testing"
)

// 每个用例开头重置全局快照，避免用例间互相污染
func resetGroups() { SetGroupSnapshot(nil) }

func TestGroupSnapshotNilSafe(t *testing.T) {
	resetGroups()
	if GetGroupMatcher("nope") != nil {
		t.Error("未发布快照时 GetGroupMatcher 应返回 nil")
	}
	// nil *MatchSet 的 Contains 必须安全——判定侧正是靠这一点省掉判空
	if GetGroupMatcher("nope").Contains(net.ParseIP("1.2.3.4")) {
		t.Error("nil matcher 不应命中")
	}
	if LookupGroupMatcher("nope").Contains(net.ParseIP("1.2.3.4")) {
		t.Error("nil matcher(按名查) 不应命中")
	}
	if g, e := GroupStats(); g != 0 || e != 0 {
		t.Errorf("空快照 GroupStats() = (%d,%d), want (0,0)", g, e)
	}
}

func TestUpsertRemoveGroupMatcher(t *testing.T) {
	resetGroups()
	UpsertGroupMatcher("gA", "组A", BuildMatchSet([]string{"10.0.0.0/8"}))
	UpsertGroupMatcher("gB", "组B", BuildMatchSet([]string{"172.16.0.0/12"}))

	if !GetGroupMatcher("gA").Contains(net.ParseIP("10.1.2.3")) {
		t.Error("组A 应命中 10.1.2.3")
	}
	if GetGroupMatcher("gA").Contains(net.ParseIP("172.16.0.1")) {
		t.Error("组A 不应命中组B 的地址")
	}

	// COW 语义：更新组A 不能影响已经取到手的组B 指针
	before := GetGroupMatcher("gB")
	UpsertGroupMatcher("gA", "组A", BuildMatchSet([]string{"192.168.0.0/16"}))
	if GetGroupMatcher("gB") != before {
		t.Error("更新组A 后组B 的 matcher 指针不应变化")
	}
	if GetGroupMatcher("gA").Contains(net.ParseIP("10.1.2.3")) {
		t.Error("组A 已被替换，不应再命中旧内容")
	}
	if !GetGroupMatcher("gA").Contains(net.ParseIP("192.168.1.1")) {
		t.Error("组A 应命中新内容")
	}

	RemoveGroupMatcher("gA")
	if GetGroupMatcher("gA") != nil {
		t.Error("组A 已删除，应返回 nil")
	}
	if LookupGroupMatcher("组A") != nil {
		t.Error("组A 删除后按名字也不应查到")
	}
	if GetGroupMatcher("gB") == nil {
		t.Error("删除组A 不应影响组B")
	}
}

func TestLookupGroupMatcher_CodeBeforeName(t *testing.T) {
	resetGroups()
	byCode := BuildMatchSet([]string{"10.0.0.1"})
	byName := BuildMatchSet([]string{"10.0.0.2"})
	UpsertGroupMatcher("dup", "别的名字", byCode)
	UpsertGroupMatcher("другой", "dup", byName)

	// "dup" 同时是前者的 code 与后者的 name，短码优先
	if LookupGroupMatcher("dup") != byCode {
		t.Error("LookupGroupMatcher 应优先按短码命中")
	}
	if LookupGroupMatcher("别的名字") != byCode {
		t.Error("按名称应能查到")
	}
	if LookupGroupMatcher(" 别的名字 ") != byCode {
		t.Error("查名称应容忍两端空白")
	}
}

// 改名后旧名字必须失效，否则规则里写旧名会继续命中一个已经不存在的组
func TestUpsertGroupMatcher_RenameDropsOldName(t *testing.T) {
	resetGroups()
	m := BuildMatchSet([]string{"10.0.0.1"})
	UpsertGroupMatcher("g1", "旧名字", m)
	UpsertGroupMatcher("g1", "新名字", m)

	if LookupGroupMatcher("旧名字") != nil {
		t.Error("改名后旧名字应当查不到")
	}
	if LookupGroupMatcher("新名字") == nil {
		t.Error("改名后新名字应当可查")
	}
	if GetGroupMatcher("g1") == nil {
		t.Error("改名不应影响短码索引")
	}
}

func TestGroupStats(t *testing.T) {
	resetGroups()
	UpsertGroupMatcher("g1", "一", BuildMatchSet([]string{"1.1.1.1", "2.2.2.0/24"}))
	UpsertGroupMatcher("g2", "二", BuildMatchSet([]string{"3.3.3.3"}))
	g, e := GroupStats()
	if g != 2 || e != 3 {
		t.Errorf("GroupStats() = (%d,%d), want (2,3)", g, e)
	}
}

// 并发写 + 并发读。去掉 groupsMu 后并发的 read-modify-write 会互相覆盖，
// 最终快照里会缺组，本用例即失败（配合 -race 一并跑）。
func TestGroupSnapshotConcurrent(t *testing.T) {
	resetGroups()
	const n = 64
	var wg sync.WaitGroup

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code := "g" + strconv.Itoa(i)
			UpsertGroupMatcher(code, "名"+strconv.Itoa(i), BuildMatchSet([]string{"10.0.0." + strconv.Itoa(i%256)}))
		}(i)
	}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = GetGroupMatcher("g1").Contains(net.ParseIP("10.0.0.1"))
				_ = LookupGroupMatcher("名1").Contains(net.ParseIP("10.0.0.1"))
			}
		}()
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		code := "g" + strconv.Itoa(i)
		if GetGroupMatcher(code) == nil {
			t.Fatalf("并发写后 %s 丢失——groupsMu 未生效，read-modify-write 互相覆盖", code)
		}
		if LookupGroupMatcher("名"+strconv.Itoa(i)) == nil {
			t.Fatalf("并发写后 名%d 的名称索引丢失", i)
		}
	}
}
