package wafenginecore

import (
	"strings"
	"testing"
)

// TestACMEDiagThrottle 钉住诊断日志的节流：
// 这条日志在热路径上，任何人都能构造 /.well-known/acme-challenge/<随机串> 打进来，
// 一旦节流失效，刷这个路径就等于刷日志文件。
func TestACMEDiagThrottle(t *testing.T) {
	const hostCode = "throttle-host-a"

	allowed := 0
	for i := 0; i < 1000; i++ {
		if acmeDiagAllowed(hostCode) {
			allowed++
		}
	}
	if allowed != 1 {
		t.Errorf("同一站点连打1000次，应该只放行1条日志，实际放行 %d 条", allowed)
	}

	// 另一个站点不受影响：节流是按站点独立的，否则 A 站点在签发时
	// 会把 B 站点的诊断日志顺带吞掉。
	if !acmeDiagAllowed("throttle-host-b") {
		t.Error("不同站点的节流应互相独立，B站点第一条日志被误吞")
	}
}

// TestAcmeTokenFromURL token 解析只服务于诊断日志，但仍然不能把畸形路径
// 解析成一个看起来合法的 token，否则诊断日志本身会误导排查方向。
func TestAcmeTokenFromURL(t *testing.T) {
	ok := map[string]string{
		"/.well-known/acme-challenge/2NKiiETgQdPmmjlM88mH5uo6jM98PrgWwsDslaN8":    "2NKiiETgQdPmmjlM88mH5uo6jM98PrgWwsDslaN8",
		"/.well-known/acme-challenge/ewiYrIoJRFMwEclGR57LLqYkoLeQ3neTNdNGciowtUw": "ewiYrIoJRFMwEclGR57LLqYkoLeQ3neTNdNGciowtUw",
		"/.well-known/acme-challenge/a_b-c":                                       "a_b-c",
	}
	for url, want := range ok {
		if got := acmeTokenFromURL(url); got != want {
			t.Errorf("acmeTokenFromURL(%s) = %q, 期望 %q", url, got, want)
		}
	}

	bad := []string{
		"/.well-known/acme-challenge/",             // 空 token
		"/.well-known/acme-challenge/../../admin",  // 穿越
		"/.well-known/acme-challenge/token/extra",  // 层级过深
		"/.well-known/acme-challenge/token?x=1",    // 带查询串
		"/.well-known/acme-challenge/to ken",       // 含空格
		"/foo/../.well-known/acme-challenge/token", // 归一化前不是标准路径
		"/admin", // 完全无关
	}
	for _, url := range bad {
		if got := acmeTokenFromURL(url); got != "" {
			t.Errorf("acmeTokenFromURL(%s) 应返回空串，实际 %q", url, got)
		}
	}
}

// TestAcmeChallengeFilePath 拼法必须和申请时传给 lego 的 savePath 一致
// （sslorder.go: GetCurrentDir()/data/vhost/<HostCode>），
// 一旦两边拼法漂移，就会出现"写在一处、读在另一处"的静默失败。
func TestAcmeChallengeFilePath(t *testing.T) {
	got := acmeChallengeFilePath("host-code-1", "tokenABC")
	want := "/data/vhost/host-code-1/.well-known/acme-challenge/tokenABC"
	if !strings.HasSuffix(got, want) {
		t.Errorf("挑战文件路径 = %q, 期望以 %q 结尾", got, want)
	}
}
