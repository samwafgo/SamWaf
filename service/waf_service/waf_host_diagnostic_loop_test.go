package waf_service

import (
	"SamWaf/model/wafenginmodel"
	"context"
	"errors"
	"net"
	"strconv"
	"testing"
)

func TestDiagnosticOriginLoopCheckGuards(t *testing.T) {
	guard := func(actual string) error {
		host, _, err := net.SplitHostPort(actual)
		if err != nil {
			return err
		}
		if host == "127.0.0.1" || host == "::1" {
			return errors.New("目标为本机受保护监听")
		}
		return nil
	}
	// 解析失败的地址只记录不阻断，避免单个后端 DNS 抖动挡住整个入口检测
	unverified, err := diagnosticOriginLoopCheck(context.Background(), []wafenginmodel.WebsiteDiagnosticOriginPlan{
		{FallbackAddress: "diagnostic-unresolvable.invalid:80"},
	}, guard)
	if err != nil || len(unverified) != 1 {
		t.Fatalf("dns failure should be recorded not blocked: unverified=%v err=%v", unverified, err)
	}
	// 确认解析到本机受保护监听时必须阻断
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	if _, err := strconv.Atoi(portText); err != nil {
		t.Fatal(err)
	}
	if _, err := diagnosticOriginLoopCheck(context.Background(), []wafenginmodel.WebsiteDiagnosticOriginPlan{
		{FallbackAddress: "localhost:" + portText},
	}, guard); err == nil {
		t.Fatal("loopback origin must be blocked")
	}
}
