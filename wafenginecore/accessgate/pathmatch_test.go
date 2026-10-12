package accessgate

import (
	"strings"
	"testing"
	"time"
)

// TestMatchPathPatterns 双语义匹配：普通条目按段边界前缀，含 * 条目按全路径通配。
func TestMatchPathPatterns(t *testing.T) {
	list := []string{"/admin", "/api/*/private", "*.php", "/manage*"}
	cases := []struct {
		p    string
		want bool
	}{
		// /admin：段边界前缀
		{"/admin", true},
		{"/admin/login", true},
		{"/admin/", true}, // 调用方传归一化后的路径，此行只防未归一化的漏网
		{"/adminconsole", false},
		{"/adminx", false},

		// /api/*/private：* 跨 /
		{"/api/v1/private", true},
		{"/api/v1/v2/private", true},
		{"/api/private", false},
		{"/api/v1/private/x", false}, // 通配条目是全路径匹配，不是前缀

		// *.php：后缀通配
		{"/index.php", true},
		{"/dir/a.php", true},
		{"/index.php.jpg", false},
		{"/index.html", false},

		// /manage*：显式通配放弃段边界
		{"/manage", true},
		{"/managex", true},
		{"/manage/panel", true},
		{"/manageconsole", true},
		{"/man", false},
	}
	for _, c := range cases {
		if got := MatchPathPatterns(c.p, list); got != c.want {
			t.Fatalf("MatchPathPatterns(%q) = %v, 期望 %v", c.p, got, c.want)
		}
	}
}

func TestMatchPathPatternsEdge(t *testing.T) {
	// nil / 空条目安全
	if MatchPathPatterns("/anything", nil) {
		t.Fatal("空列表不该匹配任何路径")
	}
	if MatchPathPatterns("/anything", []string{""}) {
		t.Fatal("空条目不能匹配所有路径")
	}
	// 单个 "/" 是显式的"全部路径"
	if !MatchPathPatterns("/whatever", []string{"/"}) {
		t.Fatal(`"/" 应匹配所有路径`)
	}
	// 尾斜杠条目等价于无尾斜杠
	if !MatchPathPatterns("/static/a.js", []string{"/static/"}) {
		t.Fatal("/static/ 应命中其子路径")
	}
	// 纯 * 条目匹配一切
	if !MatchPathPatterns("/a/b/c", []string{"*"}) {
		t.Fatal("* 应匹配所有路径")
	}
	// 两个 * 的长模式也不能退化
	if MatchPathPatterns("/aaaaab", []string{"/*a*a*a*a*a*a*a*a*a*a*a*a*b*c"}) {
		t.Fatal("不该命中")
	}
	if !MatchPathPatterns("/aaaaab", []string{"/*a*a*b"}) {
		t.Fatal("该命中而未命中")
	}
	// * 跨 / 的显式用例（对抗审查补充：文档承诺的语义必须有测试钉住）
	if !MatchPathPatterns("/a/x/b", []string{"/a*b"}) {
		t.Fatal("* 必须能跨越 /")
	}
	// 单字符路径与星号收尾
	if !MatchPathPatterns("/a", []string{"/*"}) || !MatchPathPatterns("/a", []string{"/a*"}) {
		t.Fatal("/* 与 /a* 都应命中 /a")
	}
}

// TestBuildPathPatterns 解析：换行/逗号混合、去空、小写、补前导 /、截断。
func TestBuildPathPatterns(t *testing.T) {
	got := BuildPathPatterns("/Admin,\r\n/api/*/private,  *.php \n\n,,no-slash")
	expect := []string{"/admin", "/api/*/private", "/*.php", "/no-slash"}
	if len(got) != len(expect) {
		t.Fatalf("解析出 %d 条, 期望 %d 条: %v", len(got), len(expect), got)
	}
	for i := range expect {
		if got[i] != expect[i] {
			t.Fatalf("第 %d 条 = %q, 期望 %q", i, got[i], expect[i])
		}
	}

	if BuildPathPatterns("  \r\n , ") != nil {
		t.Fatal("全空输入应返回 nil")
	}

	// 超 50 条截断
	var sb strings.Builder
	for i := 0; i < 80; i++ {
		sb.WriteString("/p")
		sb.WriteString(itoa(i))
		sb.WriteString("\n")
	}
	if got := BuildPathPatterns(sb.String()); len(got) != pathPatternMaxEntries {
		t.Fatalf("80 条输入应截断为 %d 条, 实际 %d", pathPatternMaxEntries, len(got))
	}

	// 单条超 256 字符截断
	long := "/" + strings.Repeat("a", 400)
	if got := BuildPathPatterns(long); len(got[0]) != pathPatternMaxLen {
		t.Fatalf("超长条目应截断为 %d 字符, 实际 %d", pathPatternMaxLen, len(got[0]))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestGlobMatchPathological 性能锚点：50 条多 * 长模式 × 2048 字符路径，
// 线性算法应瞬时完成；若有人换成 regexp 实现会在这里超时。
func TestGlobMatchPathological(t *testing.T) {
	pattern := "/" + strings.Repeat("a*/", 20) + strings.Repeat("*a", 20)
	list := make([]string, pathPatternMaxEntries)
	for i := range list {
		list[i] = pattern
	}
	s := "/" + strings.Repeat("a", 2048)
	start := time.Now()
	MatchPathPatterns(s, list)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("50 条多*模式匹配耗时 %v, 疑似退化为回溯实现", elapsed)
	}
}
