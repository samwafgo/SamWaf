package wafqueue

import "testing"

// 归一化规则守护用例：这些规则是 M5 汇总表的地基，规则一改历史与新数据就不可比。
// 要改规则就改这里，并在提交记录里写明——默默改 = 汇总悄悄失真。
func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/item/123456", "/item/{n}"},
		{"/item/123456?x=1&y=2", "/item/{n}"},   // query 去掉
		{"/p/page#frag", "/p/page"},             // fragment 去掉
		{"/u/550e8400-e29b-41d4-a716-446655440000", "/u/{id}"},
		{"/u/550e8400e29b41d4a716446655440000", "/u/{h}"}, // 32 位无横线 hex
		{"/img/12345.jpg", "/img/{n}.jpg"},      // 末段保留扩展名
		{"/static/app.9f8c7d6b.js", "/static/app.9f8c7d6b.js"}, // 段内含点的短串不归一，扩展名保留
		{"/a/b/c", "/a/b/c"},
		{"/", "/"},
		{"", ""},
		{"/t/abasdhfkjahsdkjfhajksdhfkjashdfkjahsldkfhj", "/t/{s}"}, // 超长段当 token 处理
		{"/api/v2/2026/report", "/api/v2/{n}/report"},
		{"/d/123/456/789", "/d/{n}/{n}/{n}"},
	}
	for _, c := range cases {
		if got := NormalizePath(c.in); got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestActorKey(t *testing.T) {
	if got := ActorKey("1.2.3.4"); got != "ip:1.2.3.4" {
		t.Fatalf("actor_key 取来源 IP，实际 %q", got)
	}
	if got := ActorKey(""); got != "" {
		t.Fatalf("没有 IP 应为空，实际 %q", got)
	}
	// 钉死：GUEST_IDENTIFICATION 是分类标签（正常访客/可疑用户/bot 名），
	// 不是身份，绝不能进 actor_key——否则全站正常访客聚成一个 actor。
	if ActorKey("1.2.3.4") == ActorKey("5.6.7.8") {
		t.Fatal("不同 IP 不该同键")
	}
}

func TestUaHashAndPayloadHash(t *testing.T) {
	if UaHash("") != "" {
		t.Fatal("空 UA 不留指纹")
	}
	if UaHash("Mozilla/5.0") != UaHash("Mozilla/5.0") || UaHash("Mozilla/5.0") == UaHash("curl/8.0") {
		t.Fatal("UA 指纹应稳定且区分")
	}
	if PayloadHash("", "") != "" {
		t.Fatal("无规则无内容不产手法指纹")
	}
	a := PayloadHash("SQLi:Union", "bodyhash1")
	if a != PayloadHash("SQLi:Union", "bodyhash1") || a == PayloadHash("SQLi:Union", "bodyhash2") || a == PayloadHash("XSS", "bodyhash1") {
		t.Fatal("手法指纹应稳定、随规则与内容变化")
	}
}
