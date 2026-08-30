package waf_service

import (
	"strings"
	"testing"
)

// 保存期校验：用户主动编辑时脏数据一律拒绝（与引擎运行期的宽容解析不同）
func TestValidatePortListensReq(t *testing.T) {
	svc := WafHostServiceApp

	// 空表 = 未携带，直接放行
	if listens, err := svc.ValidatePortListensReq("", 80, 0, 0); err != nil || listens != nil {
		t.Fatalf("空表应放行, got err=%v listens=%v", err, listens)
	}

	// 正常表
	listens, err := svc.ValidatePortListensReq(`[{"port":80,"proto":"http"},{"port":443,"proto":"https","ipv":"ipv4"}]`, 80, 1, 0)
	if err != nil {
		t.Fatalf("合法表被拒: %v", err)
	}
	if len(listens) != 2 || listens[0].Port != 80 || !listens[0].IsMain {
		t.Fatalf("归一结果不对: %+v", listens)
	}

	cases := []struct {
		name, raw string
		mainPort  int
		ssl       int
		wantMsg   string
	}{
		{"坏JSON", `{broken`, 80, 0, "格式不合法"},
		{"空数组", `[]`, 80, 0, "不能为空"},
		{"端口越界", `[{"port":99999,"proto":"http"}]`, 80, 0, "合法范围"},
		{"协议非法", `[{"port":80,"proto":"ftp"}]`, 80, 0, "http 或 https"},
		{"ipv非法", `[{"port":80,"proto":"http","ipv":"v6"}]`, 80, 0, "both/ipv4/ipv6"},
		{"addr预留拒收", `[{"port":80,"proto":"http","addr":"192.168.1.1"}]`, 80, 0, "不支持指定监听地址"},
		{"重复端口", `[{"port":80,"proto":"http"},{"port":80,"proto":"https"}]`, 80, 1, "重复"},
		{"缺主端口", `[{"port":8080,"proto":"http"}]`, 80, 0, "必须包含主端口"},
		{"HTTPS无SSL", `[{"port":443,"proto":"https"}]`, 443, 0, "启用SSL证书开关"},
	}
	for _, c := range cases {
		_, err := svc.ValidatePortListensReq(c.raw, c.mainPort, c.ssl, 0)
		if err == nil || !strings.Contains(err.Error(), c.wantMsg) {
			t.Errorf("%s: 期望含 %q 的错误, got=%v", c.name, c.wantMsg, err)
		}
	}

	// 80 端口显式 HTTPS（有证书）是合法配置——nginx 的 listen 80 ssl 语义
	if _, err := svc.ValidatePortListensReq(`[{"port":80,"proto":"https"}]`, 80, 1, 0); err != nil {
		t.Errorf("80:https 应合法(listen 80 ssl), got=%v", err)
	}
	// 有证书 + 全端口 HTTP 也是合法配置——CDN 明文回源场景(issue #955)
	if _, err := svc.ValidatePortListensReq(`[{"port":80,"proto":"http"}]`, 80, 1, 0); err != nil {
		t.Errorf("SSL=1+全HTTP 应合法(CDN明文回源), got=%v", err)
	}
}
